// SPDX-License-Identifier: GPL-2.0-only

package main

// Assembling the manifest for a kernel from the declared configuration:
//
//	/etc/wisp/wisp.conf        the runtime configuration; the builder completes it
//	                           (luks.uuid and luks.name from /etc/crypttab) and places the
//	                           completed copy in the initramfs, where it is measured
//	/etc/wisp/modules          module names and +dir:/-dir: selectors; a built-in list otherwise
//	/etc/wisp/lvm.tab          a hand-maintained volume table; otherwise recorded from the running system
//	/usr/lib/wisp/key/<name>   a key provider named by key=, with /etc/wisp/key/<name>/ as its configuration
//
// Everything the builder writes goes to a stage directory first; the manifest
// references those files, so `wisp manifest --stage` hands a verifier exactly
// the inputs it needs to rebuild the same bytes.

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"wisp/internal/initrd"
	"wisp/internal/kmod"
)

const (
	confDir      = "/etc/wisp"
	initBinary   = "/usr/lib/wisp/wisp-init"
	providerRoot = "/usr/lib/wisp/key"
	modulesRoot  = "/lib/modules"
)

// defaultModules is the selection used when /etc/wisp/modules does not exist,
// in the spirit of initramfs-tools' "most": every module of the kernel except
// the subtrees that cannot matter before the root file system is mounted.
// The coldplug loads only what matches present hardware, so the breadth costs
// archive size and early-boot memory, not boot time. Exclusions shape the
// top-level set only; a dependency inside an excluded subtree is still pulled
// when a selected module needs it, and a bare name is resolved regardless of
// the directory selectors: that is how the firmware frame buffer driver
// survives the gpu exclusion on kernels that build it as a module (Ubuntu
// builds it in, then the name is a no-op).
var defaultModules = []string{
	"dm_mod",
	"dm_crypt",
	"simpledrm",
	"+dir:kernel",
	"-dir:kernel/net",
	"-dir:kernel/drivers/net",
	"-dir:kernel/sound",
	"-dir:kernel/drivers/gpu",
	"-dir:kernel/drivers/media",
	"-dir:kernel/drivers/staging",
	"-dir:kernel/drivers/infiniband",
	"-dir:kernel/drivers/bluetooth",
	"-dir:kernel/drivers/iio",
	"-dir:kernel/drivers/hwmon",
	"-dir:kernel/kernel",
	"-dir:kernel/zfs",
}

type buildOpts struct {
	kernel   string
	output   string
	compress string
	manifest string
	stage    string
	verbose  bool
}

func parseBuildFlags(name string, args []string, o *buildOpts) (*flag.FlagSet, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&o.kernel, "k", "", "kernel version (default: the running kernel)")
	fs.StringVar(&o.output, "o", "", "output file (default: /boot/initrd.img-<version>)")
	fs.StringVar(&o.compress, "compress", "zstd", "none or zstd")
	fs.StringVar(&o.manifest, "manifest", "", "build from this manifest instead of assembling one")
	fs.StringVar(&o.stage, "stage", "", "keep the assembled manifest and generated files in this directory")
	fs.BoolVar(&o.verbose, "v", false, "list the modules that went in")
	if err := fs.Parse(args); err != nil {
		return fs, nil, err
	}
	if o.kernel == "" {
		o.kernel = runningKernel()
	}
	return fs, fs.Args(), nil
}

func cmdBuild(args []string) int {
	var o buildOpts
	if _, _, err := parseBuildFlags("build", args, &o); err != nil {
		return 1
	}
	if o.compress != "none" && o.compress != "zstd" {
		return die("build: --compress must be none or zstd")
	}
	if o.output == "" {
		o.output = "/boot/initrd.img-" + o.kernel
	}
	m, cleanup, err := manifestFor(o)
	if err != nil {
		return die("build: %v", err)
	}
	defer cleanup()
	res, err := initrd.Build(m, modulesRoot)
	if err != nil {
		return die("%v", err)
	}
	blob := res.Cpio
	note := ""
	if o.compress == "zstd" {
		z, err := initrd.CompressZstd(blob)
		if err != nil {
			return die("build: zstd: %v", err)
		}
		note = fmt.Sprintf(", cpio %d bytes sha256=%s", len(blob), res.SHA256())
		blob = z
	}
	tmp := o.output + ".new"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return die("build: %v", err)
	}
	if err := os.Rename(tmp, o.output); err != nil {
		os.Remove(tmp)
		return die("build: %v", err)
	}
	if d, err := os.Open(filepath.Dir(o.output)); err == nil {
		d.Sync()
		d.Close()
	}
	sum := sha256.Sum256(blob)
	fmt.Fprintf(os.Stderr, "%s: %d bytes, kernel %s, %d module(s) + %d builtin, sha256=%s%s\n",
		o.output, len(blob), m.Kernel, len(res.Resolution.Order), len(res.Resolution.Builtin), hex.EncodeToString(sum[:]), note)
	if o.verbose {
		for _, rp := range res.Resolution.Order {
			fmt.Fprintln(os.Stderr, "  "+rp)
		}
	}
	return 0
}

func cmdManifest(args []string) int {
	var o buildOpts
	if _, _, err := parseBuildFlags("manifest", args, &o); err != nil {
		return 1
	}
	m, cleanup, err := manifestFor(o)
	if err != nil {
		return die("manifest: %v", err)
	}
	defer cleanup()
	fmt.Print(m.String())
	return 0
}

func cmdResolve(args []string) int {
	var o buildOpts
	_, rest, err := parseBuildFlags("resolve", args, &o)
	if err != nil {
		return 1
	}
	if len(rest) == 0 {
		return die("resolve: give module names and/or +dir:/-dir: selectors")
	}
	tree := kmod.Load(filepath.Join(modulesRoot, o.kernel))
	res, err := initrd.Resolve(rest, tree)
	if err != nil {
		return die("%v", err)
	}
	fmt.Printf("# resolved against %s: %d module(s), dependency-first\n", tree.Dir, len(res.Order))
	for _, rp := range res.Order {
		fmt.Println("  " + rp)
	}
	if len(res.Builtin) > 0 {
		fmt.Printf("# builtin (no file needed): %s\n", strings.Join(res.Builtin, ", "))
	}
	if len(res.Missing) > 0 {
		fmt.Printf("# MISSING: %s\n", strings.Join(res.Missing, ", "))
		return 1
	}
	return 0
}

// manifestFor returns the manifest to build from: the given one, or one
// assembled into a stage directory (a temporary one unless --stage).
func manifestFor(o buildOpts) (*initrd.Manifest, func(), error) {
	none := func() {}
	if o.manifest != "" {
		m, err := initrd.ParseManifest(o.manifest)
		return m, none, err
	}
	stage := o.stage
	cleanup := none
	if stage == "" {
		d, err := os.MkdirTemp("", "wisp-stage.")
		if err != nil {
			return nil, none, err
		}
		stage = d
		cleanup = func() { os.RemoveAll(d) }
	} else if err := os.MkdirAll(stage, 0o755); err != nil {
		return nil, none, err
	}
	m, err := assemble(o.kernel, stage)
	if err != nil {
		cleanup()
		return nil, none, err
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest"), []byte(m.String()), 0o644); err != nil {
		cleanup()
		return nil, none, err
	}
	return m, cleanup, nil
}

// assemble writes the generated files into stage and returns the manifest.
func assemble(kernel, stage string) (*initrd.Manifest, error) {
	if fi, err := os.Stat(filepath.Join(modulesRoot, kernel)); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("no module tree for kernel %s under %s", kernel, modulesRoot)
	}
	init := initBinary
	if v := os.Getenv("WISP_INIT"); v != "" {
		init = v
	}
	if _, err := os.Stat(init); err != nil {
		return nil, fmt.Errorf("init binary %s: %w", init, err)
	}

	// 1. the runtime configuration, completed
	conf := map[string]string{}
	order := []string{}
	if b, err := os.ReadFile(filepath.Join(confDir, "wisp.conf")); err == nil {
		conf, order = parseConf(string(b))
	}
	set := func(k, v string) {
		if _, ok := conf[k]; !ok {
			order = append(order, k)
		}
		conf[k] = v
	}
	entries, _ := readCrypttab("/etc/crypttab")
	var luksEntry *crypttabEntry
	for i := range entries {
		e := entries[i]
		if e.options == "" || strings.Contains(e.options, "luks") {
			luksEntry = &e
			break
		}
	}
	key := conf["key"]
	if key == "" {
		if luksEntry == nil {
			key = "none"
		} else {
			key = "passphrase"
		}
		set("key", key)
	}
	lay, err := inspectRoot()
	if err != nil {
		return nil, err
	}
	if key != "none" {
		if conf["luks.uuid"] == "" {
			if luksEntry == nil {
				return nil, fmt.Errorf("key=%s but no LUKS entry in /etc/crypttab and no luks.uuid in wisp.conf", key)
			}
			u, err := luksUUIDOf(luksEntry.source)
			if err != nil {
				return nil, fmt.Errorf("crypttab %s: %w", luksEntry.source, err)
			}
			set("luks.uuid", u)
		}
		if conf["luks.name"] == "" {
			switch {
			case lay.crypt != nil:
				set("luks.name", lay.crypt.name)
			case luksEntry != nil:
				set("luks.name", luksEntry.target)
			}
		}
	} else if lay.crypt != nil {
		return nil, fmt.Errorf("key=none but the root file system is on dm-crypt (%s)", lay.crypt.name)
	}
	if conf["root"] == "" && lay.device != "" {
		set("root", lay.device)
	}
	var sb strings.Builder
	sb.WriteString("# generated by wisp build; measured as part of the initramfs\n")
	for _, k := range order {
		fmt.Fprintf(&sb, "%s = %s\n", k, conf[k])
	}
	if err := os.WriteFile(filepath.Join(stage, "wisp.conf"), []byte(sb.String()), 0o644); err != nil {
		return nil, err
	}

	m := &initrd.Manifest{Kernel: kernel, Dir: stage}
	m.Files = append(m.Files,
		initrd.FileSpec{Archive: "/init", Source: init},
		initrd.FileSpec{Archive: "/etc/wisp/wisp.conf", Source: filepath.Join(stage, "wisp.conf")})

	// 2. modules
	if b, err := os.ReadFile(filepath.Join(confDir, "modules")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			if line = strings.TrimSpace(line); line != "" {
				m.Modules = append(m.Modules, line)
			}
		}
	} else {
		m.Modules = append(m.Modules, defaultModules...)
	}

	// 3. the volume table
	if b, err := os.ReadFile(filepath.Join(confDir, "lvm.tab")); err == nil {
		if err := os.WriteFile(filepath.Join(stage, "lvm.tab"), b, 0o644); err != nil {
			return nil, err
		}
		m.Files = append(m.Files, initrd.FileSpec{Archive: "/etc/wisp/lvm.tab", Source: filepath.Join(stage, "lvm.tab")})
	} else if lay.lvmTab != "" {
		if err := os.WriteFile(filepath.Join(stage, "lvm.tab"), []byte(lay.lvmTab), 0o644); err != nil {
			return nil, err
		}
		m.Files = append(m.Files, initrd.FileSpec{Archive: "/etc/wisp/lvm.tab", Source: filepath.Join(stage, "lvm.tab")})
	}

	// 4. a detached header copy, if configured
	if h := conf["luks.header"]; h != "" {
		if _, err := os.Stat(h); err != nil {
			return nil, fmt.Errorf("luks.header %s: %w", h, err)
		}
		m.Files = append(m.Files, initrd.FileSpec{Archive: h, Source: h})
	}

	// 5. a key provider and its configuration
	switch key {
	case "none", "passphrase", "credential":
	default:
		bin := filepath.Join(providerRoot, key)
		if _, err := os.Stat(bin); err != nil {
			return nil, fmt.Errorf("key=%s: provider %s is not installed", key, bin)
		}
		m.Files = append(m.Files, initrd.FileSpec{Archive: bin, Source: bin})
		cdir := filepath.Join(confDir, "key", key)
		if fi, err := os.Stat(cdir); err == nil && fi.IsDir() {
			var files []string
			filepath.WalkDir(cdir, func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					files = append(files, p)
				}
				return nil
			})
			sort.Strings(files)
			for _, p := range files {
				m.Files = append(m.Files, initrd.FileSpec{Archive: p, Source: p})
			}
		}
	}
	return m, nil
}

// parseConf reads key=value lines, keeping the first-seen order of the keys.
func parseConf(s string) (map[string]string, []string) {
	out := map[string]string{}
	var order []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, seen := out[k]; !seen {
			order = append(order, k)
		}
		out[k] = v
	}
	return out, order
}

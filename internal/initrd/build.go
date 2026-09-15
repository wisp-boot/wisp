// SPDX-License-Identifier: GPL-2.0-only

package initrd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"

	"wisp/internal/kmod"
)

// Result is a built initrd.
type Result struct {
	Cpio            []byte      // the uncompressed archive
	Early           []byte      // the uncompressed early cpio with the CPU microcode, or nil
	Resolution      *Resolution // which modules went in
	FirmwareFiles   int         // firmware entries placed (files and symlinks)
	FirmwareMissing []string    // firmware names the modules declare that the firmware root lacks
}

// FirmwareRoot is where firmware files are taken from when the manifest asks for them.
var FirmwareRoot = "/lib/firmware"

// SHA256 of the uncompressed archive, hex.
func (r *Result) SHA256() string {
	s := sha256.Sum256(r.Cpio)
	return hex.EncodeToString(s[:])
}

// Build assembles the initrd described by m. modulesRoot holds
// <kernel>/ (normally /lib/modules), or is that directory itself.
//
// The archive contains: the empty directories proc, sys, dev, etc, run; the
// resolved modules copied verbatim under lib/modules/<kernel>/ (never
// stripped or recompressed, that would break bit-reproducibility against the
// package); a pruned modules.order listing exactly the emitted set in load
// order; and the declared [files]. The [cmdline] is not placed in the
// archive: the kernel receives it from the boot entry and the initrd reads
// /proc/cmdline.
func Build(m *Manifest, modulesRoot string) (*Result, error) {
	moddir := modulesRoot
	if filepath.Base(filepath.Clean(moddir)) != m.Kernel {
		moddir = filepath.Join(moddir, m.Kernel)
	}
	if fi, err := os.Stat(moddir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("build: no module tree at %s", moddir)
	}
	tree := kmod.Load(moddir)
	res, err := Resolve(m.Modules, tree)
	if err != nil {
		return nil, err
	}
	if len(res.Missing) > 0 {
		return nil, fmt.Errorf("build: modules neither present nor builtin: %s", strings.Join(res.Missing, ", "))
	}

	t := NewTree()
	modBase := "lib/modules/" + m.Kernel
	for _, d := range []string{"proc", "sys", "dev", "etc", "run", modBase} {
		t.AddDir(d)
	}
	for _, rp := range res.Order {
		data, err := os.ReadFile(filepath.Join(moddir, filepath.FromSlash(rp)))
		if err != nil {
			return nil, err
		}
		if err := t.AddFile(modBase+"/"+rp, data, false); err != nil {
			return nil, err
		}
	}
	var order bytes.Buffer
	for _, rp := range res.Order {
		order.WriteString(rp + "\n")
	}
	if err := t.AddFile(modBase+"/modules.order", order.Bytes(), false); err != nil {
		return nil, err
	}
	result := &Result{Resolution: res}
	if m.Firmware == "modules" {
		n, missing, err := addFirmware(t, res.Firmware, FirmwareRoot)
		if err != nil {
			return nil, err
		}
		result.FirmwareFiles, result.FirmwareMissing = n, missing
	}
	if err := addFiles(t, m); err != nil {
		return nil, err
	}
	result.Cpio = WriteCpio(t.Entries(), m.SourceEpoch)
	if m.Microcode == "all" {
		early, err := MicrocodeCpio(FirmwareRoot, m.SourceEpoch)
		if err != nil {
			return nil, err
		}
		result.Early = early
	}
	return result, nil
}

// MicrocodeCpio builds the early cpio the kernel's microcode loader reads:
// kernel/x86/microcode/AuthenticAMD.bin and GenuineIntel.bin, each the
// concatenation, in sorted file order, of the vendor's microcode files under
// the firmware root (amd-ucode/*.bin, intel-ucode/*). The loader scans the
// blob for the running CPU's entry, so no selection tool is needed and the
// result is a pure function of the two microcode packages. The archive must
// stay uncompressed and precede the main archive. Nil if neither directory
// exists.
func MicrocodeCpio(root string, sourceEpoch int64) ([]byte, error) {
	concat := func(dir string, ext string) ([]byte, error) {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			return nil, nil
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() && (ext == "" || strings.HasSuffix(e.Name(), ext)) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		var out []byte
		for _, n := range names {
			b, err := os.ReadFile(filepath.Join(root, dir, n))
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	}
	amd, err := concat("amd-ucode", ".bin")
	if err != nil {
		return nil, err
	}
	intel, err := concat("intel-ucode", "")
	if err != nil {
		return nil, err
	}
	if len(amd) == 0 && len(intel) == 0 {
		return nil, nil
	}
	t := NewTree()
	if len(amd) > 0 {
		if err := t.AddFile("kernel/x86/microcode/AuthenticAMD.bin", amd, false); err != nil {
			return nil, err
		}
	}
	if len(intel) > 0 {
		if err := t.AddFile("kernel/x86/microcode/GenuineIntel.bin", intel, false); err != nil {
			return nil, err
		}
	}
	return WriteCpio(t.Entries(), sourceEpoch), nil
}

// addFiles places the declared [files] entries.
func addFiles(t *Tree, m *Manifest) error {
	for _, f := range m.Files {
		if f.Link != "" {
			if err := t.AddSymlink(f.Archive, f.Link); err != nil {
				return fmt.Errorf("build: [files] %s: %w", f.Archive, err)
			}
			continue
		}
		src := f.Source
		if !filepath.IsAbs(src) {
			src = filepath.Join(m.Dir, src)
		}
		fi, err := os.Stat(src)
		if err != nil {
			return fmt.Errorf("build: [files] %s: %w", f.Archive, err)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("build: [files] %s: %w", f.Archive, err)
		}
		if err := t.AddFile(f.Archive, data, fi.Mode()&0o111 != 0); err != nil {
			return fmt.Errorf("build: [files] %s: %w", f.Archive, err)
		}
	}
	return nil
}

// addFirmware places the firmware files the modules name, as the kernel's
// firmware loader will look for them: /lib/firmware/<name>, or the
// compressed variant <name>.zst or <name>.xz that the distribution ships.
// Symbolic links are kept as links and their targets added too, so that the
// many generation-specific names that point at one file cost the archive one
// copy. Names the firmware root does not have are skipped and reported; the
// result is a pure function of (module set, firmware tree).
func addFirmware(t *Tree, names []string, root string) (int, []string, error) {
	placed := 0
	var missing []string
	done := map[string]bool{}
	// link records a symlink entry once and returns the path it resolves to,
	// relative to the firmware root.
	link := func(rel, target string) (string, error) {
		if !done["link:"+rel] {
			if err := t.AddSymlink("lib/firmware/"+rel, target); err != nil {
				return "", err
			}
			done["link:"+rel] = true
			placed++
		}
		if strings.HasPrefix(target, "/") {
			return strings.Trim(strings.TrimPrefix(target, root), "/"), nil
		}
		return filepath.ToSlash(filepath.Join(filepath.Dir(rel), target)), nil
	}
	var place func(rel string) error
	place = func(rel string) error {
		rel = strings.Trim(filepath.ToSlash(rel), "/")
		// Directory symlinks on the way (nvidia/ga106 -> ga102 and the like): keep
		// the link, continue under the real directory, so one file serves every name.
		parts := strings.Split(rel, "/")
		for i := 1; i < len(parts); i++ {
			prefix := strings.Join(parts[:i], "/")
			fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(prefix)))
			if err != nil {
				return err
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(filepath.Join(root, filepath.FromSlash(prefix)))
				if err != nil {
					return err
				}
				resolved, err := link(prefix, target)
				if err != nil {
					return err
				}
				return place(resolved + "/" + strings.Join(parts[i:], "/"))
			}
		}
		if done[rel] {
			return nil
		}
		done[rel] = true
		full := filepath.Join(root, filepath.FromSlash(rel))
		fi, err := os.Lstat(full)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(full)
			if err != nil {
				return err
			}
			resolved, err := link(rel, target)
			if err != nil {
				return err
			}
			return place(resolved)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", full)
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		if err := t.AddFile("lib/firmware/"+rel, data, false); err != nil {
			return err
		}
		placed++
		return nil
	}
	for _, name := range names {
		found := ""
		for _, cand := range []string{name, name + ".zst", name + ".xz"} {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(cand))); err == nil {
				found = cand
				break
			}
		}
		if found == "" {
			missing = append(missing, name)
			continue
		}
		if err := place(found); err != nil {
			return 0, nil, fmt.Errorf("build: firmware %s: %w", name, err)
		}
	}
	return placed, missing, nil
}

// CompressZstd compresses an archive deterministically: best level, one
// thread, no content checksum. The output depends only on the input bytes and
// the vendored zstd implementation, never on the machine.
func CompressZstd(b []byte) ([]byte, error) {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(false),
		zstd.WithZeroFrames(true),
	)
	if err != nil {
		return nil, err
	}
	out := enc.EncodeAll(b, make([]byte, 0, len(b)/3))
	enc.Close()
	return out, nil
}

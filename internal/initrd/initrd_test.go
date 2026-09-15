// SPDX-License-Identifier: GPL-2.0-only

package initrd

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"wisp/internal/kmod"
)

// readCpio is a minimal newc reader for checking our own output.
type member struct {
	name string
	mode uint32
	data []byte
}

func readCpio(t *testing.T, b []byte) []member {
	t.Helper()
	var out []member
	p := 0
	for {
		if string(b[p:p+6]) != cpioMagic {
			t.Fatalf("bad magic at %d", p)
		}
		f := func(i int) uint64 {
			v, err := strconv.ParseUint(string(b[p+6+8*i:p+6+8*i+8]), 16, 32)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		mode, size, namesize := uint32(f(1)), int(f(6)), int(f(11))
		p += 110
		name := string(b[p : p+namesize-1])
		p += namesize
		for p%4 != 0 {
			p++
		}
		data := b[p : p+size]
		p += size
		for p%4 != 0 {
			p++
		}
		if name == trailer {
			return out
		}
		out = append(out, member{name, mode, data})
	}
}

func sampleEntries() []Entry {
	return []Entry{
		{"usr/bin/tool", modeFile | 0o755, []byte("binary-ish\x00\x01")},
		{"init", modeFile | 0o755, []byte("hello init\n")},
		{"etc/cmdline", modeFile | 0o644, []byte("root=/dev/mapper/x\n")},
		{"usr/modules", modeLink | 0o777, []byte("../lib/modules")},
		{"usr", modeDir | 0o755, nil},
		{"usr/bin", modeDir | 0o755, nil},
		{"etc", modeDir | 0o755, nil},
	}
}

func TestCpioDeterministic(t *testing.T) {
	a := WriteCpio(sampleEntries(), 0)
	b := WriteCpio(sampleEntries(), 0)
	if !bytes.Equal(a, b) {
		t.Fatal("two runs differ")
	}
	if bytes.Equal(a, WriteCpio(sampleEntries(), 1700000000)) {
		t.Fatal("source epoch has no effect: mtime not pinned?")
	}
	changed := sampleEntries()
	changed[1].Data = []byte("changed\n")
	if bytes.Equal(a, WriteCpio(changed, 0)) {
		t.Fatal("a content change is invisible in the archive")
	}
}

func TestCpioStructure(t *testing.T) {
	ms := readCpio(t, WriteCpio(sampleEntries(), 0))
	var names []string
	for _, m := range ms {
		names = append(names, m.name)
	}
	want := []string{"etc", "etc/cmdline", "init", "usr", "usr/bin", "usr/bin/tool", "usr/modules"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("order %v, want %v", names, want)
	}
	for _, m := range ms {
		switch m.name {
		case "usr/modules":
			if m.mode&0o170000 != modeLink || string(m.data) != "../lib/modules" {
				t.Fatalf("symlink lost: %+v", m)
			}
		case "usr/bin/tool":
			if m.mode != modeFile|0o755 {
				t.Fatalf("exec bit lost: %o", m.mode)
			}
		}
	}
	if _, err := exec.LookPath("cpio"); err == nil {
		cmd := exec.Command("cpio", "-itv")
		cmd.Stdin = bytes.NewReader(WriteCpio(sampleEntries(), 0))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cpio -itv: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "usr/bin/tool") {
			t.Fatalf("cpio did not list usr/bin/tool:\n%s", out)
		}
	}
}

func TestTreeParents(t *testing.T) {
	tr := NewTree()
	if err := tr.AddFile("/lib/modules/1.0/kernel/x.ko", []byte("m"), false); err != nil {
		t.Fatal(err)
	}
	if err := tr.AddSymlink("lib64", "usr/lib64"); err != nil {
		t.Fatal(err)
	}
	if err := tr.AddSymlink("lib64", "usr/lib64"); err != nil { // identical link accepted
		t.Fatal(err)
	}
	if err := tr.AddSymlink("lib64", "elsewhere"); err == nil {
		t.Fatal("conflicting symlink accepted")
	}
	ms := readCpio(t, WriteCpio(tr.Entries(), 0))
	var names []string
	for _, m := range ms {
		names = append(names, m.name)
	}
	want := []string{"lib", "lib/modules", "lib/modules/1.0", "lib/modules/1.0/kernel", "lib/modules/1.0/kernel/x.ko", "lib64"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("%v", names)
	}
}

func TestWalkTreeMatchesInMemory(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755)
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "init"), []byte("hello init\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "usr/bin/tool"), []byte("binary-ish\x00\x01"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc/cmdline"), []byte("root=/dev/mapper/x\n"), 0o644)
	os.Symlink("../lib/modules", filepath.Join(dir, "usr/modules"))
	walked, err := WalkTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(WriteCpio(walked, 0), WriteCpio(sampleEntries(), 0)) {
		t.Fatal("walked tree and in-memory tree produce different archives")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	text := "# comment\nkernel = 6.1.0-test\nsource_epoch = 7\n\n[modules]\nnvme\n+dir:kernel/fs\n-dir:kernel/fs/nfs\n\n[cmdline]\nroot=/dev/mapper/root quiet # not a comment\n\n[files]\n/init = init\n/lib64 = link:usr/lib64\n"
	m, err := ParseManifestString(text, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if m.Kernel != "6.1.0-test" || m.SourceEpoch != 7 || len(m.Modules) != 3 || m.CmdlineString() != "root=/dev/mapper/root quiet # not a comment" {
		t.Fatalf("%+v", m)
	}
	if len(m.Files) != 2 || m.Files[0].Source != "init" || m.Files[1].Link != "usr/lib64" {
		t.Fatalf("%+v", m.Files)
	}
	again, err := ParseManifestString(m.String(), "/x")
	if err != nil {
		t.Fatal(err)
	}
	if again.String() != m.String() {
		t.Fatalf("round trip differs:\n%s\n%s", m.String(), again.String())
	}
	if _, err := ParseManifestString("[modules]\nx\n", "/x"); err == nil {
		t.Fatal("missing kernel accepted")
	}
}

// makeKo builds a tiny ELF64 module whose .modinfo carries depends= and name=.
func makeKo(t *testing.T, path, deps string) {
	t.Helper()
	if _, err := exec.LookPath("objcopy"); err != nil {
		t.Skip("objcopy not installed")
	}
	name := strings.TrimSuffix(filepath.Base(path), ".ko")
	bin := path + ".modinfo"
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(bin, []byte("depends="+deps+"\x00name="+name+"\x00license=GPL\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("objcopy", "-I", "binary", "-O", "elf64-x86-64",
		"--rename-section", ".data=.modinfo", bin, path).CombinedOutput(); err != nil {
		t.Fatalf("objcopy: %v: %s", err, out)
	}
	os.Remove(bin)
}

// The selector semantics: a broad set with cutouts, a dependency inside a
// cutout is still pulled, whole-component matching, canonical order, and
// the build is byte-identical across runs.
func TestResolveSelectorsAndBuild(t *testing.T) {
	root := t.TempDir()
	const ver = "9.9.9-test"
	mod := filepath.Join(root, ver)
	mk := func(rp, deps string) { makeKo(t, filepath.Join(mod, rp), deps) }
	mk("kernel/crypto/aes.ko", "")
	mk("kernel/drivers/base.ko", "")
	mk("kernel/drivers/char/tpm.ko", "")
	mk("kernel/drivers/mid.ko", "base")
	mk("kernel/fs/ext4.ko", "mid")
	mk("kernel/fs/netfs.ko", "helper")
	mk("kernel/drivers/net/helper.ko", "")
	mk("kernel/drivers/net/e1000.ko", "")
	mk("kernel/drivers/gpu/drm.ko", "")
	mk("sound/core/snd.ko", "")
	mk("kernel/drivers-foo/foo.ko", "")
	os.WriteFile(filepath.Join(mod, "modules.builtin"), []byte("kernel/drivers/builtin-thing.ko\n"), 0o644)

	tree := kmod.Load(mod)
	res, err := Resolve([]string{"builtin_thing", "+dir:kernel/drivers", "+dir:kernel/fs", "+dir:kernel/crypto",
		"-dir:kernel/drivers/net", "-dir:kernel/drivers/gpu", "-dir:sound"}, tree)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"kernel/crypto/aes.ko",
		"kernel/drivers/base.ko",
		"kernel/drivers/char/tpm.ko",
		"kernel/drivers/mid.ko",
		"kernel/fs/ext4.ko",
		"kernel/drivers/net/helper.ko", // dependency inside a cutout: still pulled
		"kernel/fs/netfs.ko",
	}
	if !reflect.DeepEqual(res.Order, want) {
		t.Fatalf("order\n got %v\nwant %v", res.Order, want)
	}
	if !reflect.DeepEqual(res.Builtin, []string{"builtin_thing"}) || len(res.Missing) != 0 {
		t.Fatalf("builtin %v missing %v", res.Builtin, res.Missing)
	}
	if r, _ := Resolve([]string{"nosuch"}, tree); !reflect.DeepEqual(r.Missing, []string{"nosuch"}) {
		t.Fatalf("missing: %v", r.Missing)
	}

	initPath := filepath.Join(root, "init")
	os.WriteFile(initPath, []byte("#!/bin/sh\n"), 0o755)
	m, err := ParseManifestString("kernel = "+ver+"\n[modules]\next4\n[files]\n/init = init\n/lib64 = link:usr/lib64\n", root)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Build(m, root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(m, root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Cpio, b.Cpio) {
		t.Fatal("two builds differ")
	}
	var names []string
	for _, x := range readCpio(t, a.Cpio) {
		names = append(names, x.name)
		if x.name == "lib/modules/"+ver+"/modules.order" && string(x.data) != "kernel/drivers/base.ko\nkernel/drivers/mid.ko\nkernel/fs/ext4.ko\n" {
			t.Fatalf("modules.order: %q", x.data)
		}
	}
	wantNames := []string{"dev", "etc", "init", "lib", "lib/modules", "lib/modules/" + ver, "lib/modules/" + ver + "/kernel",
		"lib/modules/" + ver + "/kernel/drivers", "lib/modules/" + ver + "/kernel/drivers/base.ko", "lib/modules/" + ver + "/kernel/drivers/mid.ko",
		"lib/modules/" + ver + "/kernel/fs", "lib/modules/" + ver + "/kernel/fs/ext4.ko", "lib/modules/" + ver + "/modules.order",
		"lib64", "proc", "run", "sys"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("archive members\n got %v\nwant %v", names, wantNames)
	}
	z1, _ := CompressZstd(a.Cpio)
	z2, _ := CompressZstd(a.Cpio)
	if !bytes.Equal(z1, z2) {
		t.Fatal("zstd output not deterministic")
	}
	t.Logf("cpio %d bytes sha256 %s, zstd %d bytes", len(a.Cpio), a.SHA256(), len(z1))
	if len(hex.EncodeToString([]byte{1})) != 2 {
		t.Fatal("unreachable")
	}
}

// Firmware placement: names come from the modules' firmware= fields, files
// are taken from the firmware root with their compressed suffix, symlink
// chains are kept as links plus one copy of the target, absent names are
// reported, and the archive is deterministic.
func TestFirmwarePlacement(t *testing.T) {
	root := t.TempDir()
	const ver = "9.9.9-fw"
	mod := filepath.Join(root, ver)
	if _, err := exec.LookPath("objcopy"); err != nil {
		t.Skip("objcopy not installed")
	}
	name := "gpu"
	bin := filepath.Join(root, "modinfo")
	os.MkdirAll(filepath.Join(mod, "kernel/drivers/gpu"), 0o755)
	os.WriteFile(bin, []byte("depends=\x00name="+name+"\x00firmware=vendor/a.bin\x00firmware=vendor/b.bin\x00firmware=alias/real.bin\x00firmware=vendor/missing.bin\x00"), 0o644)
	if out, err := exec.Command("objcopy", "-I", "binary", "-O", "elf64-x86-64", "--rename-section", ".data=.modinfo", bin, filepath.Join(mod, "kernel/drivers/gpu/gpu.ko")).CombinedOutput(); err != nil {
		t.Fatalf("objcopy: %v: %s", err, out)
	}
	fw := filepath.Join(root, "firmware")
	os.MkdirAll(filepath.Join(fw, "vendor"), 0o755)
	os.WriteFile(filepath.Join(fw, "vendor/a.bin.zst"), []byte("A-COMPRESSED"), 0o644) // shipped compressed
	os.WriteFile(filepath.Join(fw, "vendor/real.bin"), []byte("B-REAL"), 0o644)        // the real file
	os.Symlink("real.bin", filepath.Join(fw, "vendor/b.bin"))                          // b.bin -> real.bin
	os.Symlink("vendor", filepath.Join(fw, "alias"))                                   // alias/ -> vendor/ (directory symlink)
	old := FirmwareRoot
	FirmwareRoot = fw
	defer func() { FirmwareRoot = old }()

	os.WriteFile(filepath.Join(root, "init"), []byte("#!/bin/sh\n"), 0o755)
	m, err := ParseManifestString("kernel = "+ver+"\nfirmware = modules\n[modules]\ngpu\n[files]\n/init = init\n", root)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := Build(m, root)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Build(m, root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r1.Cpio, r2.Cpio) {
		t.Fatal("firmware build not deterministic")
	}
	if !reflect.DeepEqual(r1.FirmwareMissing, []string{"vendor/missing.bin"}) || r1.FirmwareFiles != 4 {
		t.Fatalf("placed %d, missing %v", r1.FirmwareFiles, r1.FirmwareMissing)
	}
	got := map[string]member{}
	for _, x := range readCpio(t, r1.Cpio) {
		got[x.name] = x
	}
	if x, ok := got["lib/firmware/vendor/a.bin.zst"]; !ok || string(x.data) != "A-COMPRESSED" {
		t.Fatalf("compressed firmware missing: %+v", x)
	}
	if x, ok := got["lib/firmware/vendor/b.bin"]; !ok || x.mode&0o170000 != modeLink || string(x.data) != "real.bin" {
		t.Fatalf("symlink not kept: %+v", x)
	}
	if x, ok := got["lib/firmware/vendor/real.bin"]; !ok || string(x.data) != "B-REAL" {
		t.Fatalf("symlink target missing: %+v", x)
	}
	if _, ok := got["lib/firmware/vendor/missing.bin"]; ok {
		t.Fatal("absent firmware appeared")
	}
	if x, ok := got["lib/firmware/alias"]; !ok || x.mode&0o170000 != modeLink || string(x.data) != "vendor" {
		t.Fatalf("directory symlink not kept: %+v", x)
	}
	if _, ok := got["lib/firmware/alias/real.bin"]; ok {
		t.Fatal("file duplicated under the directory symlink instead of shared")
	}
	// without the firmware key nothing is placed
	m2, _ := ParseManifestString("kernel = "+ver+"\n[modules]\ngpu\n[files]\n/init = init\n", root)
	r3, err := Build(m2, root)
	if err != nil {
		t.Fatal(err)
	}
	if r3.FirmwareFiles != 0 || len(r3.Cpio) >= len(r1.Cpio) {
		t.Fatal("firmware placed without the key")
	}
	if _, err := ParseManifestString("kernel = x\nfirmware = maybe\n", root); err == nil {
		t.Fatal("bad firmware value accepted")
	}
}

func TestMicrocodeCpio(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "amd-ucode"), 0o755)
	os.MkdirAll(filepath.Join(root, "intel-ucode"), 0o755)
	os.WriteFile(filepath.Join(root, "amd-ucode/microcode_amd.bin"), []byte("AMD1"), 0o644)
	os.WriteFile(filepath.Join(root, "amd-ucode/microcode_amd_fam17h.bin"), []byte("AMD2"), 0o644)
	os.WriteFile(filepath.Join(root, "amd-ucode/README"), []byte("no"), 0o644)
	os.WriteFile(filepath.Join(root, "intel-ucode/06-8e-09"), []byte("I1"), 0o644)
	os.WriteFile(filepath.Join(root, "intel-ucode/06-55-04"), []byte("I0"), 0o644)
	a, err := MicrocodeCpio(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := MicrocodeCpio(root, 0)
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	got := map[string]string{}
	for _, m := range readCpio(t, a) {
		got[m.name] = string(m.data)
	}
	if got["kernel/x86/microcode/AuthenticAMD.bin"] != "AMD1AMD2" || got["kernel/x86/microcode/GenuineIntel.bin"] != "I0I1" {
		t.Fatalf("%#v", got)
	}
	if n, _ := MicrocodeCpio(t.TempDir(), 0); n != nil {
		t.Fatal("expected nil without microcode directories")
	}
	if _, err := ParseManifestString("kernel = x\nmicrocode = some\n", root); err == nil {
		t.Fatal("bad microcode value accepted")
	}
}

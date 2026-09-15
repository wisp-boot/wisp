// SPDX-License-Identifier: GPL-2.0-only

package kmod

// Hermetic tests of the .modinfo reader. The ELF fixtures are built at test
// time by objcopy from a raw NUL-separated blob, so the parser runs against
// real section headers from the system toolchain. Skipped without objcopy.

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestKey(t *testing.T) {
	cases := map[string]string{
		"kernel/drivers/nvme/host/nvme.ko.zst": "nvme",
		"dm-crypt.ko":                          "dm_crypt",
		"foo-bar.ko.xz":                        "foo_bar",
		"snd-hda-intel.ko.gz":                  "snd_hda_intel",
		"plain":                                "plain",
	}
	for in, want := range cases {
		if got := Key(in); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
}

// MakeKo writes blob as the .modinfo section of an ELF64 module (objcopy -I binary).
func MakeKo(t *testing.T, blob string) []byte {
	t.Helper()
	if _, err := exec.LookPath("objcopy"); err != nil {
		t.Skip("objcopy not installed; fixture cannot be built")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	ko := filepath.Join(dir, "x.ko")
	if err := os.WriteFile(bin, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("objcopy", "-I", "binary", "-O", "elf64-x86-64",
		"--rename-section", ".data=.modinfo", bin, ko)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("objcopy: %v: %s", err, out)
	}
	b, err := os.ReadFile(ko)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestDepends(t *testing.T) {
	elf := MakeKo(t, "alias=pci:v*d*\x00depends=base,other\x00name=top\x00")
	eq(t, Depends(elf), []string{"base", "other"})
}

func TestDependsEmpty(t *testing.T) {
	if got := Depends(MakeKo(t, "depends=\x00name=lonely\x00")); len(got) != 0 {
		t.Fatalf("got %#v, want empty", got)
	}
	if got := Depends(MakeKo(t, "alias=usb:v1234p*\x00name=nodep\x00")); len(got) != 0 {
		t.Fatalf("got %#v, want empty", got)
	}
}

func TestAliases(t *testing.T) {
	elf := MakeKo(t, "alias=pci:v*d*\x00alias=usb:v1234p*\x00depends=base\x00name=top\x00")
	eq(t, Aliases(elf), []string{"pci:v*d*", "usb:v1234p*"})
	eq(t, Depends(elf), []string{"base"})
}

func TestNotELF(t *testing.T) {
	if got := Aliases([]byte("not an elf file at all")); got != nil {
		t.Fatalf("non-ELF should yield nil, got %#v", got)
	}
	if got := Depends(nil); got != nil {
		t.Fatalf("nil should yield nil, got %#v", got)
	}
	if got := Depends([]byte{0x7f, 'E', 'L', 'F', 2, 0, 0, 0}); got != nil {
		t.Fatalf("truncated ELF should yield nil, got %#v", got)
	}
}

func TestSoftdep(t *testing.T) {
	elf := MakeKo(t, "alias=pci:v*\x00softdep=pre: usbio gpio-usbio\x00softdep=post: foo\x00name=x\x00")
	pre, post := Softdep(elf)
	eq(t, pre, []string{"usbio", "gpio-usbio"})
	eq(t, post, []string{"foo"})
	pre, post = Softdep(MakeKo(t, "depends=base\x00name=y\x00"))
	if pre != nil || post != nil {
		t.Fatalf("without softdep: pre=%#v post=%#v", pre, post)
	}
}

func TestDecompressRawAndGzip(t *testing.T) {
	elf := MakeKo(t, "alias=pci:v*d*\x00depends=base\x00name=top\x00")
	dir := t.TempDir()
	raw := filepath.Join(dir, "m.ko")
	if err := os.WriteFile(raw, elf, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := Decompress(raw); err != nil || !bytes.Equal(got, elf) {
		t.Fatalf("raw: err=%v equal=%v", err, bytes.Equal(got, elf))
	}
	gz := filepath.Join(dir, "m.ko.gz")
	f, err := os.Create(gz)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	zw.Write(elf)
	zw.Close()
	f.Close()
	got, err := Decompress(gz)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	eq(t, Aliases(got), []string{"pci:v*d*"})
}

// Decompress(.ko.zst) must equal `zstd -dcq` byte for byte, on a real module.
func TestDecompressZstMatchesTool(t *testing.T) {
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("zstd tool not installed")
	}
	var ko string
	filepath.WalkDir("/lib/modules", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && ko == "" && strings.HasSuffix(p, ".ko.zst") {
			ko = p
		}
		return nil
	})
	if ko == "" {
		t.Skip("no .ko.zst under /lib/modules")
	}
	ref, err := exec.Command("zstd", "-dcq", ko).Output()
	if err != nil {
		t.Fatalf("zstd -dcq %s: %v", ko, err)
	}
	got, err := Decompress(ko)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, ref) {
		t.Fatalf("zst: pure-Go output differs (%d vs %d bytes)", len(got), len(ref))
	}
}

func TestDecompressXzMatchesTool(t *testing.T) {
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz tool not installed")
	}
	orig := bytes.Repeat([]byte("wisp xz round trip\x00\x01\x02\x03"), 5000)
	dir := t.TempDir()
	raw := filepath.Join(dir, "x")
	if err := os.WriteFile(raw, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("xz", "-z", "-c", raw).Output()
	if err != nil {
		t.Fatalf("xz -z -c: %v", err)
	}
	koxz := filepath.Join(dir, "x.ko.xz")
	if err := os.WriteFile(koxz, out, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Decompress(koxz)
	if err != nil {
		t.Fatalf("Decompress(.ko.xz): %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("xz: output differs (%d vs %d bytes)", len(got), len(orig))
	}
}

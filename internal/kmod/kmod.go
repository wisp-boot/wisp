// SPDX-License-Identifier: GPL-2.0-only

// Package kmod reads kernel module metadata straight from the .ko files of a
// /lib/modules/<version> tree: the alias=, depends= and softdep= fields of the
// .modinfo ELF section, plus the modules.builtin list. It deliberately does not
// use modules.dep, modules.alias or depmod: those files are generated on the
// machine, so anything derived from them is not reproducible elsewhere. The
// .modinfo section is written by modpost at kernel build time and shipped
// inside the package, which makes it a pure function of the signed module
// bytes.
//
// Compressed modules (.ko.zst, .ko.xz, .ko.gz) are decompressed in pure Go so
// that no external tool is needed, neither in the initrd nor on the build host.
package kmod

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"wisp/internal/modtab"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Exts lists the module file suffixes, longest first.
var Exts = []string{".ko.zst", ".ko.xz", ".ko.gz", ".ko"}

// IsKo reports whether name looks like a kernel module file.
func IsKo(name string) bool {
	for _, e := range Exts {
		if strings.HasSuffix(name, e) {
			return true
		}
	}
	return false
}

// Key returns the canonical module key of a path: see modtab.Key.
func Key(relpath string) string { return modtab.Key(relpath) }

// Decompress returns the raw ELF bytes of a possibly compressed module.
func Decompress(path string) ([]byte, error) {
	if strings.HasSuffix(path, ".ko") {
		return os.ReadFile(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader
	switch {
	case strings.HasSuffix(path, ".ko.zst"):
		zr, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case strings.HasSuffix(path, ".ko.xz"):
		xr, err := xz.NewReader(f)
		if err != nil {
			return nil, err
		}
		r = xr
	case strings.HasSuffix(path, ".ko.gz"):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		r = f
	}
	return io.ReadAll(r)
}

// ModinfoSection returns the bytes of the .modinfo section of an ELF64 image.
// Every access is bounds-checked: a truncated or foreign file yields (nil, false).
//
//	e_shoff    = u64 @0x28   e_shentsize = u16 @0x3A   e_shnum = u16 @0x3C   e_shstrndx = u16 @0x3E
//	sh_name    = u32 @sh+0   sh_offset   = u64 @sh+0x18  sh_size = u64 @sh+0x20
func ModinfoSection(elf []byte) ([]byte, bool) {
	if len(elf) < 0x40 || elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F' || elf[4] != 2 {
		return nil, false
	}
	shoff := binary.LittleEndian.Uint64(elf[0x28:])
	shentsize := uint64(binary.LittleEndian.Uint16(elf[0x3A:]))
	shnum := uint64(binary.LittleEndian.Uint16(elf[0x3C:]))
	shstrndx := uint64(binary.LittleEndian.Uint16(elf[0x3E:]))
	if shentsize < 0x28 {
		return nil, false
	}
	field := func(i, rel uint64, width int) (uint64, bool) {
		base := shoff + i*shentsize + rel
		if base+uint64(width) > uint64(len(elf)) || base+uint64(width) < base {
			return 0, false
		}
		if width == 4 {
			return uint64(binary.LittleEndian.Uint32(elf[base:])), true
		}
		return binary.LittleEndian.Uint64(elf[base:]), true
	}
	strOff, ok := field(shstrndx, 0x18, 8)
	if !ok {
		return nil, false
	}
	secName := func(nameoff uint64) string {
		p := strOff + nameoff
		if p >= uint64(len(elf)) || p < strOff {
			return ""
		}
		e := p
		for e < uint64(len(elf)) && elf[e] != 0 {
			e++
		}
		return string(elf[p:e])
	}
	for i := uint64(0); i < shnum; i++ {
		nameoff, ok := field(i, 0, 4)
		if !ok {
			return nil, false
		}
		if secName(nameoff) != ".modinfo" {
			continue
		}
		off, ok1 := field(i, 0x18, 8)
		size, ok2 := field(i, 0x20, 8)
		if !ok1 || !ok2 || off > uint64(len(elf)) || off+size > uint64(len(elf)) || off+size < off {
			return nil, false
		}
		return elf[off : off+size], true
	}
	return nil, false
}

// Values collects every value of key in the .modinfo section. The section is a
// sequence of NUL-separated "key=value" fields. depends= is a single
// comma-separated field and is split; alias= appears once per pattern.
func Values(elf []byte, key string) []string {
	sec, ok := ModinfoSection(elf)
	if !ok {
		return nil
	}
	prefix := key + "="
	var out []string
	for _, field := range strings.Split(string(sec), "\x00") {
		v, ok := strings.CutPrefix(field, prefix)
		if !ok {
			continue
		}
		if key == "depends" {
			for _, d := range strings.Split(v, ",") {
				if d != "" {
					out = append(out, d)
				}
			}
		} else if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Aliases returns the alias= patterns (fnmatch patterns against a modalias).
func Aliases(elf []byte) []string { return Values(elf, "alias") }

// Depends returns the depends= names, raw (hyphens as in the field).
func Depends(elf []byte) []string { return Values(elf, "depends") }

// Softdep returns the soft dependencies: pre (load before) and post (load
// after), raw names. Several softdep= fields are merged.
func Softdep(elf []byte) (pre, post []string) {
	for _, v := range Values(elf, "softdep") {
		bucket := &pre
		for _, tok := range strings.Fields(v) {
			switch tok {
			case "pre:":
				bucket = &pre
			case "post:":
				bucket = &post
			default:
				*bucket = append(*bucket, tok)
			}
		}
	}
	return
}

// Tree is an indexed /lib/modules/<version> directory.
type Tree struct {
	Dir     string            // the /lib/modules/<version> directory
	Index   map[string]string // module key -> path relative to Dir
	Builtin map[string]bool   // keys compiled into the kernel (no file)
}

// Load indexes dir: a cheap file name scan (no decompression) plus modules.builtin.
func Load(dir string) *Tree {
	t := &Tree{Dir: dir, Index: map[string]string{}, Builtin: map[string]bool{}}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if IsKo(d.Name()) {
			if rel, err := filepath.Rel(dir, p); err == nil {
				t.Index[Key(d.Name())] = filepath.ToSlash(rel)
			}
		}
		return nil
	})
	if f, err := os.Open(filepath.Join(dir, "modules.builtin")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" {
				t.Builtin[Key(l)] = true
			}
		}
		f.Close()
	}
	return t
}

// Path returns the absolute path of a module key, or "" if it is not a file.
func (t *Tree) Path(key string) string {
	rel, ok := t.Index[key]
	if !ok {
		return ""
	}
	return filepath.Join(t.Dir, filepath.FromSlash(rel))
}

// SPDX-License-Identifier: GPL-2.0-only

// Package initrd builds an initramfs whose bytes are a pure function of a
// manifest and named public inputs (the kernel package's module tree, the
// declared files). Same inputs, same bytes, bit for bit; therefore a
// predictable hash for anyone who holds the same inputs.
//
// The determinism primitive is a reproducible newc ("070701") cpio writer:
//   - entries sorted by path, so parents precede children deterministically
//   - mtime pinned to SOURCE_DATE_EPOCH (default 0), never the file system time
//   - uid = gid = 0
//   - permissions normalised: directories 0755, files 0644 or 0755, symlinks 0777
//   - inode numbers are a running counter, not the file system inode
//
// The layout per entry matches the kernel's gen_init_cpio: a 110-byte ASCII
// header, the NUL-terminated name padded to a 4-byte boundary, the data padded
// to a 4-byte boundary. Padding is relative to the archive start.
package initrd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	cpioMagic = "070701"
	trailer   = "TRAILER!!!"

	modeDir  = 0o040000
	modeFile = 0o100000
	modeLink = 0o120000
)

// Entry is one archive member: a normalised name (no leading slash), the
// full st_mode (type bits | permission) and the content (file data, symlink
// target, or empty for a directory).
type Entry struct {
	Name string
	Mode uint32
	Data []byte
}

// maxField is the largest value a newc header field holds: eight hex digits.
// A variable only so that a test can lower it.
var maxField uint64 = 1<<32 - 1

// checkEntry refuses what a newc header cannot express instead of writing a
// truncated size: the archive would unpack to something else than was declared.
func checkEntry(name string, size int) error {
	if uint64(size) > maxField {
		return fmt.Errorf("initrd: %s: %d bytes do not fit a newc size field", name, size)
	}
	if uint64(len(name))+1 > maxField {
		return fmt.Errorf("initrd: a name of %d bytes does not fit a newc name field", len(name))
	}
	return nil
}

// WriteCpio serialises the entries as a reproducible newc cpio. Entries come
// from Tree or WalkTree, which have checked them; one that does not fit the
// format here is a programming error.
func WriteCpio(entries []Entry, sourceEpoch int64) []byte {
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var buf []byte
	pad := func() {
		for len(buf)%4 != 0 {
			buf = append(buf, 0)
		}
	}
	field := func(v uint64) {
		buf = append(buf, fmt.Sprintf("%08x", uint32(v))...)
	}
	ino := uint64(1)
	for _, e := range sorted {
		nlink := uint64(1)
		if e.Mode&0o170000 == modeDir {
			nlink = 2
		}
		if err := checkEntry(e.Name, len(e.Data)); err != nil {
			panic(err)
		}
		name := []byte(e.Name)
		name = append(name, 0)
		buf = append(buf, cpioMagic...)
		for _, v := range []uint64{
			ino, uint64(e.Mode), 0, 0, nlink, uint64(sourceEpoch), uint64(len(e.Data)),
			0, 0, 0, 0, uint64(len(name)), 0,
		} {
			field(v)
		}
		buf = append(buf, name...)
		pad()
		buf = append(buf, e.Data...)
		pad()
		ino++
	}
	tname := []byte(trailer)
	tname = append(tname, 0)
	buf = append(buf, cpioMagic...)
	for _, v := range []uint64{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, uint64(len(tname)), 0} {
		field(v)
	}
	buf = append(buf, tname...)
	pad()
	return buf
}

// WalkTree turns a directory tree into normalised entries. Symbolic links are
// kept as links (also those pointing at directories, which a plain walk would
// otherwise drop); of a file's mode only the execute bit survives.
func WalkTree(root string) ([]Entry, error) {
	root = filepath.Clean(root)
	var entries []Entry
	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		names, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
		for _, d := range names {
			full := filepath.Join(dir, d.Name())
			arc := d.Name()
			if rel != "" {
				arc = rel + "/" + d.Name()
			}
			info, err := os.Lstat(full)
			if err != nil {
				return err
			}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				target, err := os.Readlink(full)
				if err != nil {
					return err
				}
				entries = append(entries, Entry{Name: arc, Mode: modeLink | 0o777, Data: []byte(target)})
			case info.IsDir():
				entries = append(entries, Entry{Name: arc, Mode: modeDir | 0o755})
				if err := walk(full, arc); err != nil {
					return err
				}
			case info.Mode().IsRegular():
				data, err := os.ReadFile(full)
				if err != nil {
					return err
				}
				if err := checkEntry(arc, len(data)); err != nil {
					return err
				}
				entries = append(entries, Entry{Name: arc, Mode: modeFile | filePerm(info.Mode()), Data: data})
			default:
				// devices, sockets, fifos: devtmpfs provides them, skip
			}
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return nil, err
	}
	return entries, nil
}

func filePerm(m os.FileMode) uint32 {
	if m&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

// Tree is an in-memory archive being assembled: every directory, including
// intermediate ones, is an explicit entry, exactly as a walk of an unpacked
// tree would produce.
type Tree struct {
	entries map[string]Entry
}

// NewTree returns an empty tree.
func NewTree() *Tree { return &Tree{entries: map[string]Entry{}} }

func clean(p string) string {
	p = strings.TrimPrefix(filepath.ToSlash(p), "/")
	return strings.Trim(p, "/")
}

// AddDir adds a directory and all its parents. A path component that already
// exists as a file or a symlink is an error: the entry below it would have no
// directory to live in, and what an unpacker makes of that is not defined.
func (t *Tree) AddDir(p string) error {
	p = clean(p)
	if p == "" {
		return nil
	}
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			d := p[:i]
			e, ok := t.entries[d]
			if !ok {
				if err := checkEntry(d, 0); err != nil {
					return err
				}
				t.entries[d] = Entry{Name: d, Mode: modeDir | 0o755}
			} else if e.Mode&0o170000 != modeDir {
				return fmt.Errorf("initrd: %s exists and is not a directory", d)
			}
		}
	}
	return nil
}

// AddFile adds a regular file; exec decides between 0755 and 0644.
func (t *Tree) AddFile(p string, data []byte, exec bool) error {
	p = clean(p)
	if p == "" {
		return fmt.Errorf("initrd: empty file name")
	}
	if e, ok := t.entries[p]; ok && e.Mode&0o170000 != modeFile {
		return fmt.Errorf("initrd: %s exists and is not a file", p)
	}
	if err := checkEntry(p, len(data)); err != nil {
		return err
	}
	if err := t.AddDir(parentOf(p)); err != nil {
		return err
	}
	perm := uint32(0o644)
	if exec {
		perm = 0o755
	}
	t.entries[p] = Entry{Name: p, Mode: modeFile | perm, Data: data}
	return nil
}

// AddSymlink adds a symbolic link. An identical existing link is accepted.
func (t *Tree) AddSymlink(p, target string) error {
	p = clean(p)
	if e, ok := t.entries[p]; ok {
		if e.Mode&0o170000 == modeLink && string(e.Data) == target {
			return nil
		}
		return fmt.Errorf("initrd: %s exists and is not a symlink to %s", p, target)
	}
	if err := checkEntry(p, len(target)); err != nil {
		return err
	}
	if err := t.AddDir(parentOf(p)); err != nil {
		return err
	}
	t.entries[p] = Entry{Name: p, Mode: modeLink | 0o777, Data: []byte(target)}
	return nil
}

// Entries returns the members, unsorted (WriteCpio sorts).
func (t *Tree) Entries() []Entry {
	out := make([]Entry, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, e)
	}
	return out
}

func parentOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

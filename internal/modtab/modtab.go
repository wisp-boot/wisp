// SPDX-License-Identifier: GPL-2.0-only

// Package modtab is the module table an initrd carries at
// lib/modules/<version>/modules.wisp: for every module in the archive its
// key, path, depends=, softdep= and alias= patterns, plus the keys compiled
// into the kernel. The builder derives it from the modules' own .modinfo
// (internal/kmod) and places it in the archive, measured with everything
// else; the init reads this one text file and never opens a module before
// finit_module, so it needs no ELF reader and no decompressor.
//
// Format, one record per line, tab-separated, keys sorted:
//
//	wisp-modules 1
//	builtin	<key>
//	module	<key>	<relpath>	<depends,…>	<softdep pre,…>	<softdep post,…>	<alias> <alias> …
//
// Keys and paths contain neither tabs nor commas; alias patterns contain no
// whitespace. A reader refuses any other format number.
package modtab

import (
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Format is the table format this package writes and reads.
const Format = 1

// Name is the table's file name inside lib/modules/<version>/.
const Name = "modules.wisp"

// Module is one record.
type Module struct {
	Key      string   // canonical module name (see Key)
	Path     string   // relative to lib/modules/<version>, slash-separated
	Depends  []string // canonical keys, sorted
	SoftPre  []string // softdep pre:, canonical keys, in the module's order
	SoftPost []string // softdep post:, canonical keys, in the module's order
	Aliases  []string // alias= patterns, in the module's order
}

// Table is the whole file.
type Table struct {
	Modules []Module // sorted by Key
	Builtin []string // sorted keys compiled into the kernel
}

// Key returns the canonical module key of a path or name: the basename
// without the .ko* suffix, with '-' replaced by '_'. Kernel module names use
// underscores, while file names and depends= fields use hyphens.
func Key(relpath string) string {
	base := path.Base(strings.TrimSpace(relpath))
	if i := strings.Index(base, ".ko"); i > 0 {
		base = base[:i]
	}
	return strings.ReplaceAll(base, "-", "_")
}

// Marshal writes the table in canonical form: header, builtin records, module
// records, each list sorted where the format says so.
func (t *Table) Marshal() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "wisp-modules %d\n", Format)
	builtin := append([]string(nil), t.Builtin...)
	sort.Strings(builtin)
	for _, k := range builtin {
		fmt.Fprintf(&b, "builtin\t%s\n", k)
	}
	mods := append([]Module(nil), t.Modules...)
	sort.Slice(mods, func(i, j int) bool { return mods[i].Key < mods[j].Key })
	for _, m := range mods {
		deps := append([]string(nil), m.Depends...)
		sort.Strings(deps)
		fmt.Fprintf(&b, "module\t%s\t%s\t%s\t%s\t%s\t%s\n", m.Key, m.Path,
			strings.Join(deps, ","), strings.Join(m.SoftPre, ","), strings.Join(m.SoftPost, ","),
			strings.Join(m.Aliases, " "))
	}
	return b.Bytes()
}

// Parse reads a table. The first line must name this format; every record
// must be complete; anything else is an error with its line number.
func Parse(data []byte) (*Table, error) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("modules table: empty")
	}
	var v int
	if n, _ := fmt.Sscanf(lines[0], "wisp-modules %d", &v); n != 1 {
		return nil, fmt.Errorf("modules table: line 1: not a wisp modules table")
	}
	if v != Format {
		return nil, fmt.Errorf("modules table: format %d, this wisp reads format %d", v, Format)
	}
	t := &Table{}
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	for i, line := range lines[1:] {
		f := strings.Split(line, "\t")
		switch {
		case f[0] == "builtin" && len(f) == 2 && f[1] != "":
			t.Builtin = append(t.Builtin, f[1])
		case f[0] == "module" && len(f) == 7 && f[1] != "" && f[2] != "":
			t.Modules = append(t.Modules, Module{
				Key: f[1], Path: f[2],
				Depends: split(f[3]), SoftPre: split(f[4]), SoftPost: split(f[5]),
				Aliases: strings.Fields(f[6]),
			})
		default:
			return nil, fmt.Errorf("modules table: line %d: malformed record", i+2)
		}
	}
	return t, nil
}

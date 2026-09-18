// SPDX-License-Identifier: GPL-2.0-only

package initrd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"wisp/internal/kmod"
	"wisp/internal/modtab"
)

// Resolution is the outcome of Resolve.
type Resolution struct {
	Order    []string        // module paths relative to the tree, dependency-first, deduplicated
	Builtin  []string        // requested names compiled into the kernel (no file)
	Missing  []string        // requested names that are neither a module nor builtin
	Firmware []string        // firmware file names the emitted modules declare (firmware= in .modinfo), sorted
	Table    []modtab.Module // the emitted modules' key, path, depends=, softdep= and alias=, sorted by key
}

// Resolve computes the exact set of module files to place in the initrd, in a
// deterministic load order, from [modules] entries (names and +dir:/-dir:
// selectors) against a /lib/modules/<version> tree.
//
// The dependency graph is read from each module's own .modinfo depends= field,
// never from modules.dep: that file is produced by depmod on the machine and
// its ordering depends on the depmod version, so two machines could emit
// different but equally valid orders and therefore different initrd bytes.
//
// The order is a post-order depth-first walk: first the bare names in manifest
// order, then the directory-selected modules in canonical relpath order, each
// module's dependency edges visited in sorted order. A pure function of
// (entries, module graph), so a verifier on another machine reproduces it
// from the same module files.
//
// Directory selectors declare a broad set with cutouts: +dir:<subtree>
// includes every module under it, -dir:<subtree> removes a subtree again and
// wins over +dir regardless of line order. Subtrees match whole path
// components (kernel/drivers matches kernel/drivers/net/x.ko but not
// kernel/drivers-foo). Cutouts shape only the top-level set: a dependency that
// lives in an excluded subtree is still pulled in when a selected module
// needs it.
func Resolve(entries []string, tree *kmod.Tree) (*Resolution, error) {
	var names, inc, exc []string
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e, "+dir:"):
			inc = append(inc, strings.Trim(strings.TrimSpace(e[5:]), "/"))
		case strings.HasPrefix(e, "-dir:"):
			exc = append(exc, strings.Trim(strings.TrimSpace(e[5:]), "/"))
		default:
			names = append(names, e)
		}
	}

	var dirKeys []string
	if len(inc) > 0 {
		keys := make([]string, 0, len(tree.Index))
		for k := range tree.Index {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return tree.Index[keys[i]] < tree.Index[keys[j]] })
		for _, k := range keys {
			rp := tree.Index[k]
			if underAny(rp, inc) && !underAny(rp, exc) {
				dirKeys = append(dirKeys, k)
			}
		}
	}

	info := map[string]*modtab.Module{}
	firmware := map[string]bool{}
	// deps reads a module's .modinfo once: depends= drives the resolution,
	// softdep=, alias= and firmware= are recorded for the table and the firmware set.
	deps := func(key string) ([]string, error) {
		if m, ok := info[key]; ok {
			return m.Depends, nil
		}
		elf, err := kmod.Decompress(tree.Path(key))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tree.Index[key], err)
		}
		m := &modtab.Module{Key: key, Path: tree.Index[key], Aliases: kmod.Aliases(elf)}
		for _, d := range kmod.Depends(elf) {
			m.Depends = append(m.Depends, kmod.Key(d))
		}
		sort.Strings(m.Depends)
		pre, post := kmod.Softdep(elf)
		for _, d := range pre {
			m.SoftPre = append(m.SoftPre, kmod.Key(d))
		}
		for _, d := range post {
			m.SoftPost = append(m.SoftPost, kmod.Key(d))
		}
		info[key] = m
		for _, f := range kmod.Values(elf, "firmware") {
			firmware[f] = true
		}
		return m.Depends, nil
	}

	res := &Resolution{}
	seen := map[string]bool{}
	var visit func(key string) error
	visit = func(key string) error {
		if seen[key] {
			return nil
		}
		seen[key] = true
		if _, ok := tree.Index[key]; !ok {
			if tree.Builtin[key] {
				res.Builtin = append(res.Builtin, key)
			} else {
				res.Missing = append(res.Missing, key)
			}
			return nil
		}
		d, err := deps(key)
		if err != nil {
			return err
		}
		for _, x := range d {
			if err := visit(x); err != nil {
				return err
			}
		}
		res.Order = append(res.Order, tree.Index[key])
		return nil
	}
	for _, n := range names {
		if err := visit(kmod.Key(n)); err != nil {
			return nil, err
		}
	}
	for _, k := range dirKeys {
		if err := visit(k); err != nil {
			return nil, err
		}
	}
	for f := range firmware {
		res.Firmware = append(res.Firmware, f)
	}
	sort.Strings(res.Firmware)
	for _, m := range info {
		res.Table = append(res.Table, *m)
	}
	sort.Slice(res.Table, func(i, j int) bool { return res.Table[i].Key < res.Table[j].Key })
	return res, nil
}

func underAny(relpath string, prefixes []string) bool {
	rp := filepath.ToSlash(relpath)
	for _, p := range prefixes {
		if rp == p || strings.HasPrefix(rp, p+"/") {
			return true
		}
	}
	return false
}

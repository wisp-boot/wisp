// SPDX-License-Identifier: GPL-2.0-only

package initrd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"wisp/internal/kmod"
)

// Resolution is the outcome of Resolve.
type Resolution struct {
	Order    []string // module paths relative to the tree, dependency-first, deduplicated
	Builtin  []string // requested names compiled into the kernel (no file)
	Missing  []string // requested names that are neither a module nor builtin
	Firmware []string // firmware file names the emitted modules declare (firmware= in .modinfo), sorted
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

	depsCache := map[string][]string{}
	firmware := map[string]bool{}
	deps := func(key string) ([]string, error) {
		if d, ok := depsCache[key]; ok {
			return d, nil
		}
		elf, err := kmod.Decompress(tree.Path(key))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tree.Index[key], err)
		}
		var out []string
		for _, d := range kmod.Depends(elf) {
			out = append(out, kmod.Key(d))
		}
		sort.Strings(out)
		depsCache[key] = out
		for _, f := range kmod.Values(elf, "firmware") {
			firmware[f] = true
		}
		return out, nil
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

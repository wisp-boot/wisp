// SPDX-License-Identifier: GPL-2.0-only

package main

// Step 2: coldplug without udev, kmod or depmod. A tiny device manager:
//
//  1. index the module tree     /lib/modules/<version>: key -> relpath, a cheap file scan
//  2. alias table               decompress each module once, read its alias= patterns
//  3. always load               dm_mod and dm_crypt (LUKS) with their depends=, dependency-first
//  4. coldplug rounds           read every modalias under /sys/devices, match it against all
//                               alias patterns with fnmatch semantics, load the hits (+ depends=).
//                               Then scan /sys again: loading a bus driver (xhci) makes its
//                               children (USB keyboard, USB stick) appear. Repeat with a short
//                               settle pause until a round loads nothing new.
//  5. fallbacks                 if the LUKS container has not appeared, load every module of the
//                               storage subtrees; if no input device exists, load the HID and input
//                               subtrees. Then one more matching round for the children.
//
// The matcher is a faithful port of the kernel's own glob_match (lib/glob.c,
// GPL-2.0-only), because the kernel uses exactly those semantics when it
// matches a modalias against a driver's alias patterns.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"wisp/internal/kmod"
	"wisp/internal/luks"

	"golang.org/x/sys/unix"
)

var storageSubtrees = []string{
	"kernel/drivers/nvme",
	"kernel/drivers/ata",
	"kernel/drivers/scsi",
	"kernel/drivers/block",
	"kernel/drivers/mmc",
	"kernel/drivers/md",
	"kernel/drivers/usb",
	"kernel/drivers/virtio",
}

var inputSubtrees = []string{
	"kernel/drivers/hid",
	"kernel/drivers/input",
	"kernel/drivers/i2c",
	"kernel/drivers/usb",
}

type modInfo struct {
	aliases  []string
	depends  []string // canonical keys
	softPre  []string
	softPost []string
}

type aliasEntry struct {
	pattern string
	key     string
}

// modTree is the indexed module tree plus a lazy cache of each module's .modinfo.
type modTree struct {
	*kmod.Tree
	info   map[string]modInfo
	params map[string]string // module key -> parameters from the kernel command line
}

func newModTree() *modTree {
	var uts unix.Utsname
	unix.Uname(&uts)
	dir := filepath.Join("/lib/modules", unix.ByteSliceToString(uts.Release[:]))
	cl, _ := os.ReadFile("/proc/cmdline")
	return &modTree{Tree: kmod.Load(dir), info: map[string]modInfo{}, params: moduleParams(string(cl))}
}

func (t *modTree) infoFor(key string) modInfo {
	if mi, ok := t.info[key]; ok {
		return mi
	}
	var mi modInfo
	if p := t.Path(key); p != "" {
		if elf, err := kmod.Decompress(p); err == nil {
			mi.aliases = kmod.Aliases(elf)
			for _, d := range kmod.Depends(elf) {
				mi.depends = append(mi.depends, kmod.Key(d))
			}
			pre, post := kmod.Softdep(elf)
			for _, d := range pre {
				mi.softPre = append(mi.softPre, kmod.Key(d))
			}
			for _, d := range post {
				mi.softPost = append(mi.softPost, kmod.Key(d))
			}
		}
	}
	t.info[key] = mi
	return mi
}

// aliasTable reads the alias= patterns of every module (each decompressed once).
// Sorted by key so that, with several hits, the same module always loads first.
func (t *modTree) aliasTable() []aliasEntry {
	keys := make([]string, 0, len(t.Index))
	for k := range t.Index {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []aliasEntry
	for _, k := range keys {
		for _, pat := range t.infoFor(k).aliases {
			out = append(out, aliasEntry{pattern: pat, key: k})
		}
	}
	return out
}

// load loads a module dependency-first. Returns how many modules this call
// attempted (failed attempts count too, so no round retries them forever).
func (t *modTree) load(con *Console, key string, loaded map[string]bool) int {
	return t.loadRec(con, key, loaded, map[string]bool{})
}

func (t *modTree) loadRec(con *Console, key string, loaded, inProgress map[string]bool) int {
	if loaded[key] || t.Builtin[key] || inProgress[key] {
		return 0
	}
	path := t.Path(key)
	if path == "" {
		return 0 // neither a file nor builtin: not in this initrd
	}
	inProgress[key] = true
	n := 0
	info := t.infoFor(key)
	deps := append([]string(nil), info.depends...)
	sort.Strings(deps)
	for _, d := range deps {
		n += t.loadRec(con, d, loaded, inProgress)
	}
	for _, d := range info.softPre { // best effort, before the module
		n += t.loadRec(con, d, loaded, inProgress)
	}
	delete(inProgress, key)
	if loaded[key] {
		return n
	}
	if err := insmod(path, t.params[key]); err != nil && err != unix.EEXIST {
		con.Say("wisp-init: module %s: %v", t.Index[key], err)
	}
	loaded[key] = true
	for _, d := range info.softPost { // best effort, after the module
		n += t.loadRec(con, d, loaded, inProgress)
	}
	return n + 1
}

// loadSubtrees loads every module whose relpath lies under one of the prefixes.
func (t *modTree) loadSubtrees(con *Console, loaded map[string]bool, prefixes []string) int {
	keys := make([]string, 0, len(t.Index))
	for k := range t.Index {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	n := 0
	for _, k := range keys {
		rel := t.Index[k]
		for _, pre := range prefixes {
			if strings.HasPrefix(rel, pre) {
				n += t.load(con, k, loaded)
				break
			}
		}
	}
	return n
}

// scanModaliases collects every distinct modalias string under /sys/devices.
func scanModaliases() []string {
	seen := map[string]bool{}
	var out []string
	filepath.WalkDir("/sys/devices", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "modalias" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if s := strings.TrimSpace(string(b)); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		return nil
	})
	return out
}

// matchRound rescans /sys and loads every module whose alias matches a modalias.
func (t *modTree) matchRound(con *Console, aliases []aliasEntry, loaded map[string]bool) int {
	n := 0
	for _, ma := range scanModaliases() {
		for _, ae := range aliases {
			if !loaded[ae.key] && globMatch(ae.pattern, ma) {
				n += t.load(con, ae.key, loaded)
			}
		}
	}
	return n
}

func haveInputDevice() bool {
	names, _ := filepath.Glob("/sys/class/input/input*")
	return len(names) > 0
}

func coldplug(con *Console, c config) {
	t := newModTree()
	if len(t.Index) == 0 {
		con.Say("wisp-init: no module tree under %s, coldplug skipped", t.Dir)
		return
	}
	loaded := map[string]bool{}
	for _, k := range []string{"dm_mod", "dm_crypt"} {
		t.load(con, k, loaded)
	}
	aliases := t.aliasTable()
	for round := 0; round < 16; round++ {
		if t.matchRound(con, aliases, loaded) == 0 {
			break
		}
		time.Sleep(300 * time.Millisecond) // settle: a bus driver must enumerate its children
	}
	con.Say("wisp-init: coldplug loaded %d modules", len(loaded))

	fallback := false
	if c.key != keyNone && c.luksUUID != "" {
		found := false
		for i := 0; i < 10; i++ { // ~2 s for late enumeration
			if _, err := luks.FindByUUID(c.luksUUID); err == nil {
				found = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !found {
			con.Say("wisp-init: LUKS device %s not present after coldplug, loading all storage modules", c.luksUUID)
			t.loadSubtrees(con, loaded, storageSubtrees)
			fallback = true
		}
	}
	if c.key != keyNone && !haveInputDevice() {
		con.Say("wisp-init: no input device after coldplug, loading all input modules")
		t.loadSubtrees(con, loaded, inputSubtrees)
		fallback = true
	}
	if fallback {
		time.Sleep(500 * time.Millisecond)
		t.matchRound(con, aliases, loaded)
	}
}

// globMatch matches str against an fnmatch-style pattern: '*' (any run),
// '?' (one character), '[...]' with ranges and '!'/'^' negation, '\' escapes.
// A '[' without a closing ']' is a literal. Port of the Linux kernel's
// lib/glob.c glob_match; reads beyond the end yield 0, which stands in for the
// NUL terminator of the C strings.
func globMatch(pat, str string) bool {
	at := func(s string, i int) byte {
		if i >= 0 && i < len(s) {
			return s[i]
		}
		return 0
	}
	si, pi := 0, 0
	backPat, backStr := -1, -1
	for {
		c := at(str, si)
		si++
		d := at(pat, pi)
		pi++

		literal := false
		backtrack := false

		switch d {
		case '?':
			if c == 0 {
				return false
			}
		case '*':
			if at(pat, pi) == 0 {
				return true
			}
			backPat = pi
			si--
			backStr = si
		case '[':
			if c == 0 {
				return false
			}
			inverted := at(pat, pi) == '!' || at(pat, pi) == '^'
			cls := pi
			if inverted {
				cls++
			}
			a := at(pat, cls)
			cls++
			match := false
			malformed := false
			for {
				if a == 0 {
					malformed = true
					break
				}
				b := a
				if at(pat, cls) == '-' && at(pat, cls+1) != ']' {
					b = at(pat, cls+1)
					if b == 0 {
						malformed = true
						break
					}
					cls += 2
				}
				if a <= c && c <= b {
					match = true
				}
				a = at(pat, cls)
				cls++
				if a == ']' {
					break
				}
			}
			switch {
			case malformed:
				literal = true
			case match == inverted:
				backtrack = true
			default:
				pi = cls
			}
		case '\\':
			d = at(pat, pi)
			pi++
			literal = true
		default:
			literal = true
		}

		if literal {
			if c == d {
				if d == 0 {
					return true
				}
			} else {
				backtrack = true
			}
		}
		if backtrack {
			if c == 0 || backPat < 0 {
				return false
			}
			pi = backPat
			backStr++
			si = backStr
		}
	}
}

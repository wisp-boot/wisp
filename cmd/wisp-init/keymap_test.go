// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// synthetic bkeymap: tables 0 and 2 present, keycode 21 = 'z' (KT_LETTER) in
// table 0 and U+2190 (ucs ^ 0xf000) in table 2.
func syntheticBkeymap() []byte {
	b := []byte(bkeymapMagic)
	flags := make([]byte, maxNrKeymaps)
	flags[0], flags[2] = 1, 1
	b = append(b, flags...)
	for _, v := range []uint16{0x0b7a, 0xd190} {
		tbl := make([]byte, nrKeys*2)
		binary.LittleEndian.PutUint16(tbl[21*2:], v)
		b = append(b, tbl...)
	}
	return b
}

func TestParseBkeymap(t *testing.T) {
	entries, tables, err := parseBkeymap(syntheticBkeymap())
	if err != nil {
		t.Fatal(err)
	}
	if tables != 2 || len(entries) != 2*nrKeys {
		t.Fatalf("tables=%d entries=%d", tables, len(entries))
	}
	if e := entries[21]; e.table != 0 || e.index != 21 || e.value != 0x0b7a {
		t.Fatalf("table 0 keycode 21: %+v", e)
	}
	if e := entries[nrKeys+21]; e.table != 2 || e.index != 21 || e.value != 0xd190 {
		t.Fatalf("table 2 keycode 21: %+v", e)
	}
	if _, _, err := parseBkeymap([]byte("not a keymap")); err == nil {
		t.Fatal("bad magic accepted")
	}
	if _, _, err := parseBkeymap(syntheticBkeymap()[:400]); err == nil {
		t.Fatal("truncated file accepted")
	}
	if _, _, err := parseBkeymap(append(syntheticBkeymap(), 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}

// TestParseBkeymapFromTools parses what the builder's tool chain produces for
// the German layout: keycode 21 must be 'z' (KT_LETTER 0x7a) in the base table.
func TestParseBkeymapFromTools(t *testing.T) {
	for _, bin := range []string{"ckbcomp", "loadkeys"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir := t.TempDir()
	kmap := filepath.Join(dir, "de.kmap")
	txt, err := exec.Command("ckbcomp", "-layout", "de").Output()
	if err != nil {
		t.Skipf("ckbcomp: %v", err)
	}
	if err := os.WriteFile(kmap, txt, 0o644); err != nil {
		t.Fatal(err)
	}
	bin, err := exec.Command("loadkeys", "-b", "-u", kmap).Output()
	if err != nil {
		t.Skipf("loadkeys -b -u: %v", err)
	}
	entries, tables, err := parseBkeymap(bin)
	if err != nil {
		t.Fatal(err)
	}
	if tables == 0 {
		t.Fatal("no tables")
	}
	if e := entries[21]; e.table != 0 || e.index != 21 || e.value != 0x0b7a {
		t.Fatalf("de: base table keycode 21 = %#x, want 'z' (0x0b7a)", e.value)
	}
	t.Logf("de: %d tables, %d entries", tables, len(entries))
}

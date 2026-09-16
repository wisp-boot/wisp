// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDefaultKeyboard(t *testing.T) {
	kc := parseDefaultKeyboard("# KEYBOARD CONFIGURATION FILE\n\nXKBMODEL=\"pc105\"\nXKBLAYOUT=\"de,us\"\nXKBVARIANT=\"nodeadkeys,\"\nXKBOPTIONS=''\n\nBACKSPACE=\"guess\"\n")
	if kc.model != "pc105" || kc.layout != "de,us" || kc.variant != "nodeadkeys," || kc.options != "" {
		t.Fatalf("%+v", kc)
	}
	if first(kc.layout) != "de" || first(kc.variant) != "nodeadkeys" || first("") != "" {
		t.Fatal("first")
	}
}

func TestResolveKeymap(t *testing.T) {
	dir := t.TempDir()
	old := keymapsDir
	keymapsDir = dir
	defer func() { keymapsDir = old }()
	for _, n := range []string{"de.bkmap", "de+nodeadkeys.bkmap"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("bkeymap"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rec, file, err := resolveKeymap("none")
	if err != nil || rec != "" || file != "" {
		t.Fatalf("none: %q %q %v", rec, file, err)
	}
	rec, file, err = resolveKeymap("de")
	if err != nil || rec != "de" || file != filepath.Join(dir, "de.bkmap") {
		t.Fatalf("de: %q %q %v", rec, file, err)
	}
	rec, file, err = resolveKeymap("de:nodeadkeys")
	if err != nil || rec != "de:nodeadkeys" || file != filepath.Join(dir, "de+nodeadkeys.bkmap") {
		t.Fatalf("de:nodeadkeys: %q %q %v", rec, file, err)
	}
	if _, _, err := resolveKeymap("xx"); err == nil {
		t.Fatal("unknown layout accepted")
	}
	if _, _, err := resolveKeymap("../etc"); err == nil {
		t.Fatal("bad name accepted")
	}
}

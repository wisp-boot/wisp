// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseDefaultKeyboard(t *testing.T) {
	kc := parseDefaultKeyboard("# KEYBOARD CONFIGURATION FILE\n\nXKBMODEL=\"pc105\"\nXKBLAYOUT=\"de\"\nXKBVARIANT=\"nodeadkeys\"\nXKBOPTIONS=''\n\nBACKSPACE=\"guess\"\n")
	if kc.model != "pc105" || kc.layout != "de" || kc.variant != "nodeadkeys" || kc.options != "" {
		t.Fatalf("%+v", kc)
	}
}

func TestStageKeymapNone(t *testing.T) {
	rec, file, err := stageKeymap("none", t.TempDir())
	if err != nil || rec != "" || file != "" {
		t.Fatalf("none: %q %q %v", rec, file, err)
	}
}

func TestStageKeymapDe(t *testing.T) {
	for _, bin := range []string{"ckbcomp", "loadkeys"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir := t.TempDir()
	rec, file, err := stageKeymap("de", dir)
	if err != nil {
		t.Fatal(err)
	}
	if rec != "de" || file != filepath.Join(dir, "keymap.bin") {
		t.Fatalf("rec=%q file=%q", rec, file)
	}
	a, _ := os.ReadFile(file)
	rec2, file2, err := stageKeymap("de", t.TempDir())
	if err != nil || rec2 != "de" {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file2)
	if !bytes.HasPrefix(a, []byte("bkeymap")) || len(a) <= 263 || !bytes.Equal(a, b) {
		t.Fatalf("keymap.bin: %d bytes, deterministic=%v", len(a), bytes.Equal(a, b))
	}
	t.Logf("de: %d bytes", len(a))
}

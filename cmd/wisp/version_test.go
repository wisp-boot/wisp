// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"6.8.0-45-generic", "6.8.0-100-generic", true},
		{"6.8.0-100-generic", "6.8.0-45-generic", false},
		{"6.14.0-1020-oem", "6.17.0-1032-oem", true},
		{"6.17.0-1032-oem", "6.17.0-1032-oem", false},
		{"7.0.0-30-generic", "7.0.0-31-generic", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseConfOrder(t *testing.T) {
	m, order := parseConf("key = tpm\n# c\nluks.uuid = x\nkey = credential\n")
	if m["key"] != "credential" || m["luks.uuid"] != "x" || len(order) != 2 || order[0] != "key" {
		t.Fatalf("%v %v", m, order)
	}
}

func TestUpdateInitramfsDeleteRemovesTheKeptCopy(t *testing.T) {
	boot := t.TempDir()
	for _, n := range []string{"initrd.img-1.2.3-test", "initrd.img-1.2.3-test.pre-wisp", "initrd.img-9.9.9-other.pre-wisp"} {
		if err := os.WriteFile(filepath.Join(boot, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if rc := updateInitramfs([]string{"-d", "-k", "1.2.3-test", "-b", boot}); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	left, _ := os.ReadDir(boot)
	if len(left) != 1 || left[0].Name() != "initrd.img-9.9.9-other.pre-wisp" {
		t.Fatalf("left in /boot: %v", left)
	}
}

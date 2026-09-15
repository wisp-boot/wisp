// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCrypttab(t *testing.T) {
	p := filepath.Join(t.TempDir(), "crypttab")
	os.WriteFile(p, []byte("# comment\ndm_crypt-0 UUID=4d7e2b1c-8394-4943-8b24-0c7c1e7c9d07 none luks\nswap /dev/sda3 /dev/urandom swap,cipher=aes-xts-plain64\n"), 0o644)
	es, err := readCrypttab(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[0].target != "dm_crypt-0" || es[0].options != "luks" || es[1].options != "swap,cipher=aes-xts-plain64" {
		t.Fatalf("%+v", es)
	}
	u, err := luksUUIDOf(es[0].source)
	if err != nil || u != "4d7e2b1c-8394-4943-8b24-0c7c1e7c9d07" {
		t.Fatalf("%q %v", u, err)
	}
	if u, _ := luksUUIDOf("/dev/disk/by-uuid/ABCD-1"); u != "abcd-1" {
		t.Fatalf("%q", u)
	}
}

// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestReadBlacklist(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.conf"), []byte("# comment\nblacklist nouveau\nblacklist snd-pcsp\noptions i915 foo=1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.conf"), []byte("blacklist nouveau\nblacklist  \n"), 0o644)
	os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("blacklist nvme\n"), 0o644)
	got := readBlacklist(dir)
	if len(got) != 2 || got[0] != "nouveau" || got[1] != "snd_pcsp" {
		t.Fatalf("%v", got)
	}
}

func TestRootMount(t *testing.T) {
	const ext4 = `26 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
31 26 0:24 / /proc rw - proc proc rw
`
	m, err := rootMountFrom(strings.NewReader(ext4))
	if err != nil || m.source != "/dev/mapper/ubuntu--vg-ubuntu--lv" || m.fstype != "ext4" || m.fsroot != "/" {
		t.Fatalf("%+v %v", m, err)
	}
	if err := checkRootMount(m); err != nil {
		t.Fatalf("ext4 rejected: %v", err)
	}

	// Ubuntu's btrfs installation: the root is the subvolume @.
	const subvol = `29 1 0:26 /@ / rw,relatime shared:1 - btrfs /dev/mapper/dm_crypt-0 rw,ssd,subvolid=256,subvol=/@
`
	m, err = rootMountFrom(strings.NewReader(subvol))
	if err != nil || m.fstype != "btrfs" || m.fsroot != "/@" {
		t.Fatalf("%+v %v", m, err)
	}
	if err := checkRootMount(m); err == nil || !strings.Contains(err.Error(), "subvolume /@") {
		t.Fatalf("a btrfs subvolume root was accepted: %v", err)
	}

	// btrfs mounted at the top of the file system is what wisp-init gets too.
	const top = `29 1 0:26 / / rw - btrfs /dev/sda2 rw,subvolid=5,subvol=/
`
	m, _ = rootMountFrom(strings.NewReader(top))
	if err := checkRootMount(m); err != nil {
		t.Fatalf("top-level btrfs rejected: %v", err)
	}

	// optional fields before the separator; a later mount on / covers the earlier one
	const stacked = `20 1 8:1 / / rw - ext4 /dev/sda1 rw
40 20 8:2 / / rw master:1 shared:2 - xfs /dev/sda2 rw
`
	m, _ = rootMountFrom(strings.NewReader(stacked))
	if m.source != "/dev/sda2" || m.fstype != "xfs" {
		t.Fatalf("%+v", m)
	}
	if _, err := rootMountFrom(strings.NewReader("31 26 0:24 / /proc rw - proc proc rw\n")); err == nil {
		t.Fatal("no root mount, no error")
	}
}

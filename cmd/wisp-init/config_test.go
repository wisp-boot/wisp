// SPDX-License-Identifier: GPL-2.0-only

package main

import "testing"

func TestConfigDefaults(t *testing.T) {
	c := configFrom(parseConfig(""), "")
	if c.key != keyPassphrase || c.luksName != "root" {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestConfigFileWinsOverCmdline(t *testing.T) {
	file := parseConfig("# measured\nkey = tpm\nluks.uuid = AAAA-1\nluks.name = cr\nroot = UUID=Root-1\nrootfstype = ext4\n")
	c := configFrom(file, "root=/dev/sda1 rd.luks.uuid=bbbb rd.luks.name=other rootfstype=xfs")
	if c.key != "tpm" || c.luksUUID != "aaaa-1" || c.luksName != "cr" || c.rootUUID != "root-1" || c.rootPath != "" || c.rootfstype != "ext4" {
		t.Fatalf("merge: %+v", c)
	}
}

func TestConfigCmdlineFallback(t *testing.T) {
	c := configFrom(parseConfig("key = credential\n"), "root=/dev/mapper/vg-root rd.luks.uuid=BBBB rd.luks.name=dm_crypt-0 quiet")
	if c.key != keyCredential || c.luksUUID != "bbbb" || c.luksName != "dm_crypt-0" || c.rootPath != "/dev/mapper/vg-root" || c.rootUUID != "" {
		t.Fatalf("fallback: %+v", c)
	}
}

func TestParseConfigIgnoresJunk(t *testing.T) {
	m := parseConfig("no equals here\nfoo = bar # trailing comment\n  spaced  =  value  \n")
	if m["foo"] != "bar" || m["spaced"] != "value" || len(m) != 2 {
		t.Fatalf("parse: %#v", m)
	}
}

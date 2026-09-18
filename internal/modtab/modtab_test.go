// SPDX-License-Identifier: GPL-2.0-only

package modtab

import (
	"bytes"
	"strings"
	"testing"
)

func TestKey(t *testing.T) {
	for in, want := range map[string]string{
		"kernel/drivers/nvme/host/nvme-core.ko.zst": "nvme_core",
		"dm-crypt.ko":       "dm_crypt",
		"dm_mod":            "dm_mod",
		" ext4.ko.xz ":      "ext4",
		"kernel/fs/ext4.ko": "ext4",
	} {
		if got := Key(in); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRoundTripAndCanonicalOrder(t *testing.T) {
	tab := &Table{
		Builtin: []string{"unix", "dm_mod"},
		Modules: []Module{
			{Key: "nvme", Path: "kernel/drivers/nvme/host/nvme.ko.zst", Depends: []string{"nvme_core"},
				Aliases: []string{"pci:v*d*sv*sd*bc01sc08i02*", "of:N*T*Cfsl,imx6q-pcie"}},
			{Key: "ext4", Path: "kernel/fs/ext4/ext4.ko.zst", Depends: []string{"mbcache", "jbd2", "crc16"},
				SoftPre: []string{"crc32c"}, Aliases: []string{"fs-ext4", "fs-ext3", "fs-ext2"}},
			{Key: "dm_crypt", Path: "kernel/drivers/md/dm-crypt.ko.zst", SoftPost: []string{"aesni_intel"}},
		},
	}
	b := tab.Marshal()
	want := strings.Join([]string{
		"wisp-modules 1",
		"builtin\tdm_mod",
		"builtin\tunix",
		"module\tdm_crypt\tkernel/drivers/md/dm-crypt.ko.zst\t\t\taesni_intel\t",
		"module\text4\tkernel/fs/ext4/ext4.ko.zst\tcrc16,jbd2,mbcache\tcrc32c\t\tfs-ext4 fs-ext3 fs-ext2",
		"module\tnvme\tkernel/drivers/nvme/host/nvme.ko.zst\tnvme_core\t\t\tpci:v*d*sv*sd*bc01sc08i02* of:N*T*Cfsl,imx6q-pcie",
		"",
	}, "\n")
	if string(b) != want {
		t.Fatalf("marshal:\n%s\nwant:\n%s", b, want)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), b) {
		t.Fatalf("round trip differs:\n%s", got.Marshal())
	}
	if len(got.Modules) != 3 || got.Modules[1].Key != "ext4" || len(got.Modules[1].Depends) != 3 ||
		got.Modules[1].SoftPre[0] != "crc32c" || len(got.Modules[2].Aliases) != 2 || got.Modules[0].SoftPost[0] != "aesni_intel" {
		t.Fatalf("parsed: %+v", got.Modules)
	}
	if len(got.Builtin) != 2 || got.Builtin[0] != "dm_mod" {
		t.Fatalf("builtin: %v", got.Builtin)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"empty":          "",
		"not a table":    "modules.alias\n",
		"other format":   "wisp-modules 2\n",
		"short record":   "wisp-modules 1\nmodule\tx\tkernel/x.ko\n",
		"unknown record": "wisp-modules 1\nalias\tx\ty\n",
		"empty key":      "wisp-modules 1\nbuiltin\t\n",
		"empty path":     "wisp-modules 1\nmodule\tx\t\t\t\t\t\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the empty table (a kernel with everything built in) is valid
	if tab, err := Parse([]byte("wisp-modules 1\n")); err != nil || len(tab.Modules) != 0 {
		t.Fatalf("empty table: %v %+v", err, tab)
	}
}

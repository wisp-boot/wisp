// SPDX-License-Identifier: GPL-2.0-only

package main

import "testing"

func TestParseLvmTab(t *testing.T) {
	const crypt = "253:1"
	name, uuid, targets, err := parseLvmTab("# comment\nname ubuntu--vg-ubuntu--lv\nuuid LVM-abc\n0 77328384 linear @crypt@ 2048\n", crypt)
	if err != nil {
		t.Fatalf("parseLvmTab: %v", err)
	}
	if name != "ubuntu--vg-ubuntu--lv" || uuid != "LVM-abc" || len(targets) != 1 {
		t.Fatalf("name=%q uuid=%q targets=%d", name, uuid, len(targets))
	}
	tg := targets[0]
	if tg.Start != 0 || tg.Length != 77328384 || tg.Type != "linear" || tg.Params != "253:1 2048" {
		t.Fatalf("target: %+v", tg)
	}
}

func TestParseLvmTabMultiSegment(t *testing.T) {
	name, _, targets, err := parseLvmTab("name lv\n0 2048 linear @crypt@ 2048\n2048 4096 linear @crypt@ 8192\n", "9:3")
	if err != nil {
		t.Fatalf("parseLvmTab: %v", err)
	}
	if name != "lv" || len(targets) != 2 {
		t.Fatalf("name=%q targets=%d", name, len(targets))
	}
	if targets[1].Start != 2048 || targets[1].Length != 4096 || targets[1].Params != "9:3 8192" {
		t.Fatalf("second segment: %+v", targets[1])
	}
}

func TestParseLvmTabErrors(t *testing.T) {
	cases := map[string]string{
		"no name line":      "0 2048 linear @crypt@ 2048\n",
		"no segments":       "name lv\n",
		"segment too short": "name lv\n0 2048 linear\n",
		"start unparsable":  "name lv\nX 2048 linear @crypt@ 0\n",
		"length unparsable": "name lv\n0 Y linear @crypt@ 0\n",
	}
	for desc, in := range cases {
		if _, _, _, err := parseLvmTab(in, "1:0"); err == nil {
			t.Errorf("%s: expected an error", desc)
		}
	}
}

// SPDX-License-Identifier: GPL-2.0-only

package lukstab

import (
	"bytes"
	"strings"
	"testing"
)

func sample() *Table {
	return &Table{
		HeaderSHA256: bytes.Repeat([]byte{0xab}, 32), UUID: "0b2f1b8e-1111-2222-3333-444455556666",
		Segments: []Segment{{ID: "0", Encryption: "aes-xts-plain64", SectorSize: 512, Offset: 16777216, Size: "dynamic"}},
		Digests:  []Digest{{ID: "0", Hash: "sha256", Iterations: 1000, Salt: []byte{1, 2}, Digest: []byte{3, 4}, Keyslots: []string{"1", "0"}, Segments: []string{"0"}}},
		Keyslots: []Keyslot{
			{ID: "1", KeySize: 64, AreaEncryption: "aes-xts-plain64", AreaKeySize: 64, AreaOffset: 290816, AreaSize: 258048, AfHash: "sha256", AfStripes: 4000, KdfType: "pbkdf2", KdfHash: "sha512", KdfIterations: 2000, Salt: []byte{9}},
			{ID: "0", KeySize: 64, AreaEncryption: "aes-xts-plain64", AreaKeySize: 64, AreaOffset: 32768, AreaSize: 258048, AfHash: "sha256", AfStripes: 4000, KdfType: "argon2id", KdfTime: 4, KdfMemory: 32, KdfCpus: 1, Salt: []byte{5, 6}},
		},
	}
}

func TestRoundTripAndCanonicalOrder(t *testing.T) {
	b := sample().Marshal()
	want := strings.Join([]string{
		"wisp-luks 1",
		"header\tabababababababababababababababababababababababababababababababab\t0b2f1b8e-1111-2222-3333-444455556666",
		"segment\t0\taes-xts-plain64\t512\t16777216\tdynamic\t0",
		"digest\t0\tsha256\t1000\t0102\t0304\t1,0\t0",
		"keyslot\t0\t64\taes-xts-plain64\t64\t32768\t258048\tsha256\t4000\targon2id\t\t0\t4\t32\t1\t0506",
		"keyslot\t1\t64\taes-xts-plain64\t64\t290816\t258048\tsha256\t4000\tpbkdf2\tsha512\t2000\t0\t0\t0\t09",
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
	if got.Keyslots[0].KdfType != "argon2id" || got.Keyslots[1].KdfIterations != 2000 || got.Digests[0].Keyslots[1] != "0" || got.Segments[0].Size != "dynamic" {
		t.Fatalf("parsed: %+v", got)
	}
}

func TestParseRefuses(t *testing.T) {
	ok := string(sample().Marshal())
	for name, in := range map[string]string{
		"empty":         "",
		"not a table":   "luks.tab\n",
		"other format":  "wisp-luks 2\n",
		"no header":     "wisp-luks 1\nsegment\t0\taes-xts-plain64\t512\t0\tdynamic\t0\n",
		"short hash":    "wisp-luks 1\nheader\tabab\tuuid\n",
		"unknown":       "wisp-luks 1\nheader\t" + strings.Repeat("ab", 32) + "\tu\ntoken\t0\n",
		"short keyslot": strings.Replace(ok, "\t0506\n", "\n", 1),
		"bad number":    strings.Replace(ok, "\t4000\t", "\tvier\t", 1),
		"bad size":      strings.Replace(ok, "\tdynamic\t", "\tbig\t", 1),
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

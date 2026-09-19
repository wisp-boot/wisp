// SPDX-License-Identifier: GPL-2.0-only

package luks_test

// The tests drive Recover the way the init does: the table comes from the
// builder's reader (luksmeta), the header on the device is only hashed.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"wisp/internal/luks"
	"wisp/internal/luksmeta"
	"wisp/internal/lukstab"
)

func recover(t *testing.T, headerSrc, dataDev string, secret []byte) (*luks.Volume, error) {
	t.Helper()
	tab, err := luksmeta.Read(headerSrc)
	if err != nil {
		return nil, err
	}
	if err := luks.CheckHeader(headerSrc, tab); err != nil {
		return nil, err
	}
	return luks.Recover(tab, headerSrc, dataDev, secret)
}

// A header that changed after the table was built is refused before any
// keyslot is touched, with the message the init prints.
func TestChangedHeaderIsRefused(t *testing.T) {
	img, err := os.ReadFile("../../vectors/luks/luks2.img")
	if err != nil {
		t.Skip(err)
	}
	pw, _ := os.ReadFile("../../vectors/luks/passphrase.txt")
	pw = bytes.TrimSpace(pw)
	p := filepath.Join(t.TempDir(), "img")
	os.WriteFile(p, img, 0o600)
	tab, err := luksmeta.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	// the same table, re-read through the wire format
	tab2, err := lukstab.Parse(tab.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tab2.Marshal(), tab.Marshal()) {
		t.Fatal("table does not round-trip")
	}
	if err := luks.CheckHeader(p, tab2); err != nil {
		t.Fatal(err)
	}
	if _, err := luks.Recover(tab2, p, p, pw); err != nil {
		t.Fatal(err)
	}
	// touch one byte of the JSON area: a new keyslot, a killed one, anything
	mod := bytes.Replace(img, []byte(`"stripes":4000`), []byte(`"stripes":4001`), 1)
	if bytes.Equal(mod, img) {
		t.Fatal("stripes field not in the vector")
	}
	os.WriteFile(p, mod, 0o600)
	if err := luks.CheckHeader(p, tab2); !errors.Is(err, luks.ErrHeaderChanged) {
		t.Fatalf("changed header: err = %v", err)
	}
}

// The init checks the table's numbers again even though the builder did:
// a table is the only input it trusts, and trust has to be cheap to verify.
func TestRecoverRefusesOutOfRangeTable(t *testing.T) {
	img, err := os.ReadFile("../../vectors/luks/luks2.img")
	if err != nil {
		t.Skip(err)
	}
	pw, _ := os.ReadFile("../../vectors/luks/passphrase.txt")
	p := filepath.Join(t.TempDir(), "img")
	os.WriteFile(p, img, 0o600)
	tab, err := luksmeta.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		mut  func(k *lukstab.Keyslot)
	}{
		{"time 0", func(k *lukstab.Keyslot) { k.KdfTime = 0 }},
		{"cpus 0", func(k *lukstab.Keyslot) { k.KdfCpus = 0 }},
		{"memory huge", func(k *lukstab.Keyslot) { k.KdfMemory = 1 << 40 }},
		{"key_size 0", func(k *lukstab.Keyslot) { k.KeySize = 0 }},
		{"stripes", func(k *lukstab.Keyslot) { k.AfStripes = 1 }},
	} {
		t2 := *tab
		t2.Keyslots = append([]lukstab.Keyslot(nil), tab.Keyslots...)
		c.mut(&t2.Keyslots[0])
		if _, err := luks.Recover(&t2, p, p, bytes.TrimSpace(pw)); err == nil || errors.Is(err, luks.ErrNoKeyslot) {
			t.Fatalf("%s: err = %v", c.name, err)
		}
	}
}

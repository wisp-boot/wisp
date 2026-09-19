// SPDX-License-Identifier: GPL-2.0-only

package luks_test

// The LUKS2 vector under ../../vectors/luks: a container formatted by
// cryptsetup with a known passphrase and a dumped volume key. Regenerated
// with -update (cryptsetup needed); verified without cryptsetup.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wisp/internal/luks"
	"wisp/internal/luksmeta"
)

var update = flag.Bool("update", false, "regenerate the vectors under ../../vectors")

const luksVector = "../../vectors/luks"

func TestVectorLuks2(t *testing.T) {
	img := filepath.Join(luksVector, "luks2.img")
	if *update {
		needCryptsetup(t)
		os.MkdirAll(luksVector, 0o755)
		os.Remove(img)
		os.WriteFile(img, nil, 0o600)
		if err := os.Truncate(img, 2<<20); err != nil {
			t.Fatal(err)
		}
		const pw = "wisp vector passphrase"
		pwf := filepath.Join(t.TempDir(), "pw")
		os.WriteFile(pwf, []byte(pw), 0o600)
		args := append([]string{"luksFormat", "--type", "luks2", "-q", "--key-file", pwf,
			"--luks2-metadata-size", "16k", "--luks2-keyslots-size", "256k"}, fastPbkdf...)
		if out, err := exec.Command("cryptsetup", append(args, img)...).CombinedOutput(); err != nil {
			t.Fatalf("luksFormat: %v\n%s", err, out)
		}
		vk := filepath.Join(t.TempDir(), "vk")
		if out, err := exec.Command("cryptsetup", "luksDump", "--dump-volume-key", "--volume-key-file", vk, "-q", "--key-file", pwf, img).CombinedOutput(); err != nil {
			t.Fatalf("luksDump: %v\n%s", err, out)
		}
		mk, _ := os.ReadFile(vk)
		v, err := recover(t, img, img, []byte(pw))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(luksVector, "passphrase.txt"), []byte(pw+"\n"), 0o644)
		os.WriteFile(filepath.Join(luksVector, "wrong-passphrase.txt"), []byte("not the passphrase\n"), 0o644)
		os.WriteFile(filepath.Join(luksVector, "master-key.hex"), []byte(hex.EncodeToString(mk)+"\n"), 0o644)
		os.WriteFile(filepath.Join(luksVector, "segment.txt"), []byte(fmt.Sprintf("uuid=%s\nencryption=%s\nsector_size=%d\noffset=%d\nsize=%s\niv_tweak=%d\n",
			v.UUID, v.Encryption, v.SectorSize, v.Offset, v.Size, v.IvTweak)), 0o644)
	}
	pw, err := os.ReadFile(filepath.Join(luksVector, "passphrase.txt"))
	if err != nil {
		t.Skipf("vector missing (%v); run with -update", err)
	}
	// the table the builder derives from this header: what the init acts on
	tab, err := luksmeta.Read(img)
	if err != nil {
		t.Fatal(err)
	}
	tabPath := filepath.Join(luksVector, "expected.luks.tab")
	if *update {
		os.WriteFile(tabPath, tab.Marshal(), 0o644)
	}
	wantTab, err := os.ReadFile(tabPath)
	if err != nil {
		t.Fatalf("%s: %v (run with -update)", tabPath, err)
	}
	if !bytes.Equal(wantTab, tab.Marshal()) {
		t.Fatalf("luks table differs from the vector\n got:\n%s\nwant:\n%s", tab.Marshal(), wantTab)
	}
	wantHex, _ := os.ReadFile(filepath.Join(luksVector, "master-key.hex"))
	want, err := hex.DecodeString(strings.TrimSpace(string(wantHex)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := recover(t, img, img, []byte(strings.TrimSpace(string(pw))))
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !bytes.Equal(v.MasterKey, want) {
		t.Fatalf("volume key differs from the vector\n got %x\nwant %x", v.MasterKey, want)
	}
	seg, _ := os.ReadFile(filepath.Join(luksVector, "segment.txt"))
	if !strings.Contains(string(seg), "encryption="+v.Encryption) || !strings.Contains(string(seg), fmt.Sprintf("offset=%d", v.Offset)) {
		t.Fatalf("segment differs: %+v vs\n%s", v, seg)
	}
	wrong, _ := os.ReadFile(filepath.Join(luksVector, "wrong-passphrase.txt"))
	if _, err := recover(t, img, img, []byte(strings.TrimSpace(string(wrong)))); !errors.Is(err, luks.ErrNoKeyslot) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

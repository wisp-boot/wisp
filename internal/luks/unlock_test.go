// SPDX-License-Identifier: GPL-2.0-only

package luks

// Correctness gate: our pure-Go Recover against the real cryptsetup.
// luksFormat creates a LUKS2 container (argon2id, aes-xts-plain64, sha256) on
// a regular file with a known passphrase; cryptsetup dumps the volume key; we
// recover it from the same bytes. Equal keys prove the crypto. Skipped when
// cryptsetup is not installed.

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func needCryptsetup(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup not installed; differential test skipped")
	}
}

// small, fast KDF parameters so that argon2 does not eat a gigabyte in tests
var fastPbkdf = []string{"--pbkdf", "argon2id", "--pbkdf-force-iterations", "4", "--pbkdf-memory", "32", "--pbkdf-parallel", "1"}

func formatLuks2(t *testing.T, img, pw string, extra ...string) {
	t.Helper()
	if err := os.Truncate(img, 32<<20); err != nil {
		t.Fatal(err)
	}
	pwf := filepath.Join(filepath.Dir(img), "pw")
	if err := os.WriteFile(pwf, []byte(pw), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"luksFormat", "--type", "luks2", "-q", "--key-file", pwf}, fastPbkdf...)
	args = append(args, extra...)
	args = append(args, img)
	if out, err := exec.Command("cryptsetup", args...).CombinedOutput(); err != nil {
		t.Fatalf("luksFormat: %v\n%s", err, out)
	}
}

func refVolumeKey(t *testing.T, img, pw string) []byte {
	t.Helper()
	pwf := filepath.Join(filepath.Dir(img), "pw")
	vk := filepath.Join(filepath.Dir(img), "vk")
	out, err := exec.Command("cryptsetup", "luksDump", "--dump-volume-key",
		"--volume-key-file", vk, "-q", "--key-file", pwf, img).CombinedOutput()
	if err != nil {
		t.Fatalf("luksDump --dump-volume-key: %v\n%s", err, out)
	}
	b, err := os.ReadFile(vk)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecoverMatchesCryptsetup(t *testing.T) {
	needCryptsetup(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const pw = "correct horse battery staple"
	formatLuks2(t, img, pw)

	ref := refVolumeKey(t, img, pw)
	if len(ref) == 0 {
		t.Fatal("cryptsetup returned an empty volume key")
	}
	v, err := Recover(img, img, []byte(pw))
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !bytes.Equal(v.MasterKey, ref) {
		t.Fatalf("volume key differs\n cryptsetup: %x\n ours:       %x", ref, v.MasterKey)
	}
	if v.Encryption != "aes-xts-plain64" {
		t.Errorf("Encryption = %q, want aes-xts-plain64", v.Encryption)
	}
	if v.SectorSize == 0 {
		t.Errorf("SectorSize 0")
	}
}

func TestRecoverWrongPassphrase(t *testing.T) {
	needCryptsetup(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	formatLuks2(t, img, "right")
	if _, err := Recover(img, img, []byte("wrong")); !errors.Is(err, ErrNoKeyslot) {
		t.Fatalf("wrong passphrase: err=%v, want ErrNoKeyslot", err)
	}
}

func TestRecoverSha512Hash(t *testing.T) {
	needCryptsetup(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const pw = "second test"
	formatLuks2(t, img, pw, "--hash", "sha512", "--cipher", "aes-xts-plain64", "--key-size", "512")
	ref := refVolumeKey(t, img, pw)
	v, err := Recover(img, img, []byte(pw))
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !bytes.Equal(v.MasterKey, ref) {
		t.Fatalf("sha512: volume key differs\n cryptsetup: %x\n ours:       %x", ref, v.MasterKey)
	}
}

// Live dm-crypt mapping: needs root and a real /dev/mapper. Opt-in with
// WISP_DM_TEST=1. The same container is mapped by our MapCrypt and by
// cryptsetup; both decrypted devices must read byte-identically, which proves
// the table (cipher, key, offset, IV), not merely that a node appears.
func TestMapCryptRoot(t *testing.T) {
	needCryptsetup(t)
	if os.Geteuid() != 0 || os.Getenv("WISP_DM_TEST") != "1" {
		t.Skip("dm-crypt mapping test: only as root with WISP_DM_TEST=1")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const pw = "dm test"
	formatLuks2(t, img, pw)

	out, err := exec.Command("losetup", "-f", "--show", img).CombinedOutput()
	if err != nil {
		t.Fatalf("losetup: %v\n%s", err, out)
	}
	loop := strings.TrimSpace(string(out))
	defer exec.Command("losetup", "-d", loop).Run()

	v, err := Recover(loop, loop, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(v.MasterKey)

	const our = "wisp-luks-test-ours"
	if err := MapCrypt(our, loop, v); err != nil {
		t.Fatalf("MapCrypt: %v", err)
	}
	defer exec.Command("dmsetup", "remove", our).Run()

	const ref = "wisp-luks-test-ref"
	pwf := filepath.Join(dir, "pw")
	if o, err := exec.Command("cryptsetup", "open", "--type", "luks2", "--key-file", pwf, loop, ref).CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup open: %v\n%s", err, o)
	}
	defer exec.Command("cryptsetup", "close", ref).Run()

	ourB := readN(t, "/dev/mapper/"+our, 1<<20)
	refB := readN(t, "/dev/mapper/"+ref, 1<<20)
	if !bytes.Equal(ourB, refB) {
		t.Fatalf("dm-crypt mapping differs from cryptsetup (plaintext not equal)")
	}
}

func readN(t *testing.T, path string, n int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := io.ReadFull(f, b); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

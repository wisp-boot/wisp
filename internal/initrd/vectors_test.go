// SPDX-License-Identifier: GPL-2.0-only

package initrd

// The language-neutral vectors under ../../vectors: reproduced here, and
// regenerated with -update (objcopy needed for the module tree).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wisp/internal/kmod"
)

var update = flag.Bool("update", false, "regenerate the vectors under ../../vectors")

const vectorsDir = "../../vectors"

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func writeOrCompare(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run with -update to create the vectors)", path, err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Fatalf("%s differs from the vector\n got: %.80s\nwant: %.80s", path, got, want)
	}
}

func TestVectorCpio(t *testing.T) {
	dir := filepath.Join(vectorsDir, "cpio")
	tree := filepath.Join(dir, "tree")
	if *update {
		os.RemoveAll(tree)
		os.MkdirAll(filepath.Join(tree, "usr/bin"), 0o755)
		os.MkdirAll(filepath.Join(tree, "etc"), 0o755)
		os.WriteFile(filepath.Join(tree, "init"), []byte("#!/bin/sh\necho hello init\n"), 0o755)
		os.WriteFile(filepath.Join(tree, "usr/bin/tool"), []byte("binary-ish\x00\x01\x02"), 0o755)
		os.WriteFile(filepath.Join(tree, "etc/cmdline"), []byte("root=/dev/mapper/x\n"), 0o644)
		os.Symlink("../lib/modules", filepath.Join(tree, "usr/modules"))
	}
	entries, err := WalkTree(tree)
	if err != nil {
		t.Fatal(err)
	}
	blob := WriteCpio(entries, 0)
	writeOrCompare(t, filepath.Join(dir, "expected.cpio"), blob)
	writeOrCompare(t, filepath.Join(dir, "expected.sha256"), []byte(hexSum(blob)+"\n"))
	writeOrCompare(t, filepath.Join(dir, "expected-epoch-1700000000.sha256"), []byte(hexSum(WriteCpio(entries, 1700000000))+"\n"))
}

func TestVectorModules(t *testing.T) {
	dir := filepath.Join(vectorsDir, "modules")
	const ver = "9.9.9-test"
	mod := filepath.Join(dir, ver)
	if *update {
		os.RemoveAll(mod)
		mk := func(rp, deps string) { makeKo(t, filepath.Join(mod, rp), deps) }
		mk("kernel/crypto/aes.ko", "")
		mk("kernel/drivers/base.ko", "")
		mk("kernel/drivers/char/tpm.ko", "")
		mk("kernel/drivers/mid.ko", "base")
		mk("kernel/fs/ext4.ko", "mid")
		mk("kernel/fs/netfs.ko", "helper")
		mk("kernel/drivers/net/helper.ko", "")
		mk("kernel/drivers/net/e1000.ko", "")
		mk("kernel/drivers/gpu/drm.ko", "")
		mk("sound/core/snd.ko", "")
		mk("kernel/drivers-foo/foo.ko", "")
		os.WriteFile(filepath.Join(mod, "modules.builtin"), []byte("kernel/drivers/builtin-thing.ko\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "manifest"), []byte("kernel = "+ver+"\nsource_epoch = 0\n\n[modules]\nbuiltin_thing\n+dir:kernel/drivers\n+dir:kernel/fs\n+dir:kernel/crypto\n-dir:kernel/drivers/net\n-dir:kernel/drivers/gpu\n-dir:sound\n\n[files]\n/init = init\n/lib64 = link:usr/lib64\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "init"), []byte("#!/bin/sh\n"), 0o755)
	}
	m, err := ParseManifest(filepath.Join(dir, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Resolve(m.Modules, kmod.Load(mod))
	if err != nil {
		t.Fatal(err)
	}
	writeOrCompare(t, filepath.Join(dir, "expected.order"), []byte(strings.Join(res.Order, "\n")+"\n"))
	built, err := Build(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	writeOrCompare(t, filepath.Join(dir, "expected.cpio"), built.Cpio)
	writeOrCompare(t, filepath.Join(dir, "expected.sha256"), []byte(built.SHA256()+"\n"))
	if !*update {
		if _, err := exec.LookPath("objcopy"); err == nil {
			t.Log("module vector verified against committed ELF fixtures")
		}
	}
}

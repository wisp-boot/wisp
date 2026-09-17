// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderFiles(t *testing.T) {
	root := t.TempDir()
	bins, confs := filepath.Join(root, "key"), filepath.Join(root, "etc-key")
	write := func(p string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bins, "tpm"), 0o755)
	write(filepath.Join(confs, "tpm", "tpm.conf"), 0o644)
	write(filepath.Join(confs, "tpm", "srk.pub"), 0o644)
	write(filepath.Join(confs, "tpm", "sub", "b"), 0o644)
	write(filepath.Join(confs, "tpm", "sub", "a"), 0o644)
	write(filepath.Join(confs, "other", "not-ours"), 0o644)

	// the built-in key sources bring no files
	for _, k := range []string{"none", "passphrase", "credential"} {
		if fs, err := providerFiles(k, bins, confs); err != nil || fs != nil {
			t.Fatalf("%s: %v %v", k, fs, err)
		}
	}

	fs, err := providerFiles("tpm", bins, confs)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.Archive+" <- "+strings.TrimPrefix(f.Source, root))
	}
	want := []string{
		"/usr/lib/wisp/key/tpm <- /key/tpm",
		"/etc/wisp/key/tpm/srk.pub <- /etc-key/tpm/srk.pub",
		"/etc/wisp/key/tpm/sub/a <- /etc-key/tpm/sub/a",
		"/etc/wisp/key/tpm/sub/b <- /etc-key/tpm/sub/b",
		"/etc/wisp/key/tpm/tpm.conf <- /etc-key/tpm/tpm.conf",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// a provider without a configuration directory is complete
	write(filepath.Join(bins, "bare"), 0o755)
	if fs, err := providerFiles("bare", bins, confs); err != nil || len(fs) != 1 {
		t.Fatalf("bare: %v %v", fs, err)
	}

	// what would halt the boot fails the build
	write(filepath.Join(bins, "noexec"), 0o644)
	if err := os.MkdirAll(filepath.Join(bins, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, errHas := range map[string]string{
		"missing":      "is not installed",
		"noexec":       "is not an executable file",
		"adir":         "is not an executable file",
		"Tpm":          "not a valid provider name",
		"../etc":       "not a valid provider name",
		"tpm/../other": "not a valid provider name",
		"":             "not a valid provider name",
	} {
		if _, err := providerFiles(name, bins, confs); err == nil || !strings.Contains(err.Error(), errHas) {
			t.Errorf("key=%q: error %v, want %q", name, err, errHas)
		}
	}
}

// SPDX-License-Identifier: GPL-2.0-only

package luks

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A manipulated header must produce an error, never a panic: x/crypto/argon2
// panics on time 0 and cpus 0, and memory sizes an allocation.
func TestDegenerateKdfIsAnError(t *testing.T) {
	img, err := os.ReadFile("../../vectors/luks/luks2.img")
	if err != nil {
		t.Skip(err)
	}
	pw, _ := os.ReadFile("../../vectors/luks/passphrase.txt")
	pw = bytes.TrimSpace(pw)
	for _, c := range []struct{ name, from, to string }{
		{"time 0", `"time":`, `"time":0,"x":`},
		{"cpus 0", `"cpus":`, `"cpus":0,"x":`},
		{"memory huge", `"memory":`, `"memory":4194304000,"x":`},
	} {
		mod := bytes.Replace(img, []byte(c.from), []byte(c.to), 1)
		if bytes.Equal(mod, img) {
			t.Fatalf("%s: field not in the vector", c.name)
		}
		p := filepath.Join(t.TempDir(), "img")
		if err := os.WriteFile(p, mod, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Recover(p, p, pw)
		if err == nil || !strings.Contains(err.Error(), "argon2 parameters out of range") {
			t.Fatalf("%s: err = %v", c.name, err)
		}
	}
}

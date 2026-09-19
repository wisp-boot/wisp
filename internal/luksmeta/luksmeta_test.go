// SPDX-License-Identifier: GPL-2.0-only

package luksmeta

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A manipulated header is refused at build time with a reason: the values
// x/crypto/argon2 would panic on, sizes that do not fit, unknown algorithms.
func TestRefusesBadHeaders(t *testing.T) {
	img, err := os.ReadFile("../../vectors/luks/luks2.img")
	if err != nil {
		t.Skip(err)
	}
	for _, c := range []struct{ name, from, to, want string }{
		{"time 0", `"time":`, `"time":0,"x":`, "argon2 parameters"},
		{"cpus 0", `"cpus":`, `"cpus":0,"x":`, "argon2 parameters"},
		{"memory huge", `"memory":`, `"memory":4194304000,"x":`, "argon2 parameters"},
		{"stripes", `"stripes":4000`, `"stripes":4001`, "af"},
		{"digest type", `"type":"pbkdf2"`, `"type":"pbkdf3"`, "digest"},
		{"sector size", `"sector_size":4096`, `"sector_size":4097`, "sector_size"},
		{"not json", `"keyslots"`, `"keyslots`, "unreadable JSON"},
	} {
		mod := bytes.Replace(img, []byte(c.from), []byte(c.to), 1)
		if bytes.Equal(mod, img) {
			t.Fatalf("%s: field not in the vector", c.name)
		}
		p := filepath.Join(t.TempDir(), "img")
		os.WriteFile(p, mod, 0o600)
		_, err := Read(p)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	p := filepath.Join(t.TempDir(), "img")
	os.WriteFile(p, img, 0o600)
	tab, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.Keyslots) != 1 || len(tab.Digests) != 1 || len(tab.Segments) != 1 || tab.UUID == "" || len(tab.HeaderSHA256) != 32 {
		t.Fatalf("table: %+v", tab)
	}
}

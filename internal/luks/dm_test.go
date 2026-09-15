// SPDX-License-Identifier: GPL-2.0-only

package luks

// Correctness gate for the linear volume tables: our MapTable against the
// real LVM. An LV is created with lvm2 on a loop PV and filled with a
// pattern; we read its table (dmsetup table) and create a second, parallel
// device over the same loop with our ioctls. Byte-identical reads prove the
// linear table. Needs root and lvm2; opt-in with WISP_LVM_TEST=1.

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestMapTableLinearAgainstLVM(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("WISP_LVM_TEST") != "1" {
		t.Skip("linear table test: only as root with WISP_LVM_TEST=1")
	}
	for _, bin := range []string{"lvm", "dmsetup", "losetup"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "pv.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 64<<20); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("losetup", "-f", "--show", img).CombinedOutput()
	if err != nil {
		t.Fatalf("losetup: %v\n%s", err, out)
	}
	loop := strings.TrimSpace(string(out))
	defer exec.Command("losetup", "-d", loop).Run()

	vg := "wisptestvg" + strconv.Itoa(os.Getpid())
	const lv = "testlv"
	mustRun(t, "pvcreate", "-y", "-ff", loop)
	mustRun(t, "vgcreate", vg, loop)
	defer exec.Command("vgremove", "-f", vg).Run()
	mustRun(t, "lvcreate", "-y", "-L", "16M", "-n", lv, vg)
	lvpath := "/dev/" + vg + "/" + lv
	defer exec.Command("lvchange", "-an", vg+"/"+lv).Run()

	pattern := make([]byte, 4<<20)
	if _, err := rand.Read(pattern); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lvpath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", lvpath, err)
	}
	if _, err := f.Write(pattern); err != nil {
		f.Close()
		t.Fatalf("write %s: %v", lvpath, err)
	}
	f.Close()
	exec.Command("sync").Run()

	tblOut, err := exec.Command("dmsetup", "table", vg+"-"+lv).CombinedOutput()
	if err != nil {
		t.Fatalf("dmsetup table: %v\n%s", err, tblOut)
	}
	var targets []Target
	for _, line := range strings.Split(strings.TrimSpace(string(tblOut)), "\n") {
		fs := strings.Fields(line)
		if len(fs) < 4 || fs[2] != "linear" {
			t.Fatalf("unexpected table line (only linear supported): %q", line)
		}
		start, _ := strconv.ParseUint(fs[0], 10, 64)
		length, _ := strconv.ParseUint(fs[1], 10, 64)
		targets = append(targets, Target{Start: start, Length: length, Type: "linear", Params: strings.Join(fs[3:], " ")})
	}

	const our = "wisp-lvm-test-ours"
	if err := MapTable(our, "", targets); err != nil {
		t.Fatalf("MapTable: %v", err)
	}
	defer exec.Command("dmsetup", "remove", our).Run()
	mustRun(t, "dmsetup", "mknodes", our)

	ourB := readN(t, "/dev/mapper/"+our, len(pattern))
	if !bytes.Equal(ourB, pattern) {
		t.Fatalf("MapTable device does not read the bytes LVM wrote (linear table differs)")
	}
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

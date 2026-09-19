// SPDX-License-Identifier: GPL-2.0-only

// wisp-init is the /init of a wisp initramfs: one static binary that bridges
// the gap between "kernel is up, nothing mounted, root encrypted" and "the real
// operating system runs on the decrypted root". Seven steps, each a function:
//
//  1. mount the pseudo file systems      proc, sysfs, devtmpfs, a tmpfs on /run
//     1b. console keymap                   the system's layout from the measured keymap.bin, if any
//  2. load modules                        coldplug: only modules whose alias= matches present hardware
//  3. find the LUKS container             wait for the device with the configured UUID
//  4. obtain the key                      none | passphrase | credential | a key provider process
//  5. open LUKS                           volume key in pure Go, dm-crypt through the device-mapper ioctl
//     5b. activate volumes                   the recorded linear LV table over the dm-crypt device, if any
//  6. mount the root file system          by UUID or path, read-only
//  7. switch_root                         move mounts, chroot, exec /sbin/init
//
// Everything that may differ between machines or profiles is data in the
// measured /etc/wisp/wisp.conf, never a code path selected at build time. On
// any failure the init prints why and halts. There is no rescue shell.
package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	if os.Getpid() != 1 {
		if len(os.Args) == 3 && os.Args[1] == "fsuuid" { // for comparing against blkid
			t, u, err := fsProbe(os.Args[2])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("%s %s\n", t, u)
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "wisp-init: runs as /init of an initramfs; `wisp-init fsuuid <dev>` probes a file system")
		os.Exit(1)
	}

	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin") // the kernel starts /init without an environment
	mountPseudoFS()                                    // 1
	con := openConsole()
	// A panic in PID 1 ends as a kernel panic with a Go stack trace scrolling
	// by. Turn it into the same halt as every other failure, with the reason.
	defer func() {
		if r := recover(); r != nil {
			halt(con, "internal error: %v", r)
		}
	}()
	cfg := loadConfig(con) // measured wisp.conf first, kernel command line as fallback
	applyKeymap(con)       // 1b: before any prompt
	con.Say("=== wisp-init %s, kernel %s, key=%s ===", version, kernelRelease(), cfg.key)

	coldplug(con, cfg) // 2

	var luksDev string
	if cfg.key != keyNone {
		luksDev = waitLUKS(con, cfg.luksUUID) // 3
		con.Say("wisp-init: LUKS device %s (UUID %s)", luksDev, cfg.luksUUID)
		key := obtainKey(con, cfg, luksDev) // 4
		openLUKS(con, cfg, luksDev, key)    // 5
		clear(key)
		activateVolumes(con, cfg.luksName) // 5b
	}

	root := waitRoot(con, cfg) // 6
	con.Say("wisp-init: root %s, switching", root)
	mountRoot(con, root, cfg.rootfstype)
	switchRoot(con) // 7
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "?"
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// halt prints the reason and stops. No rescue shell: an initramfs with a shell
// is an initramfs with a root shell for whoever holds the keyboard.
func halt(con *Console, format string, a ...any) {
	con.Say("wisp-init: "+format, a...)
	if os.Getpid() != 1 {
		os.Exit(1)
	}
	con.Say("wisp-init: halted. Power off and boot the previous kernel or a rescue medium.")
	for {
		time.Sleep(time.Hour)
	}
}

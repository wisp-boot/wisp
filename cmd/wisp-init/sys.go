// SPDX-License-Identifier: GPL-2.0-only

package main

// The system steps as syscalls: mount, finit_module, wait for devices, chroot, exec.

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"wisp/internal/luks"
)

const deviceWait = 30 * time.Second // real hardware (USB, storage enumeration) takes longer than a VM

// 1. pseudo file systems
func mountPseudoFS() {
	for _, d := range []string{"/proc", "/sys", "/dev", "/run", "/sysroot"} {
		os.MkdirAll(d, 0o755)
	}
	unix.Mount("proc", "/proc", "proc", 0, "")
	unix.Mount("sysfs", "/sys", "sysfs", 0, "")
	if err := unix.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		unix.Mount("tmpfs", "/dev", "tmpfs", 0, "")
	}
	unix.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755")
	// Kernel chatter (USB, scheduler, ...) would otherwise run through banner and prompts.
	os.WriteFile("/proc/sys/kernel/printk", []byte("4\t4\t1\t7\n"), 0)
	if _, err := os.Stat("/dev/console"); err != nil {
		unix.Mknod("/dev/console", unix.S_IFCHR|0o600, int(unix.Mkdev(5, 1)))
	}
}

// 2. modules: finit_module on a file, compressed or not (the kernel decompresses).
func insmod(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	flags := 0
	if !strings.HasSuffix(path, ".ko") {
		flags = unix.MODULE_INIT_COMPRESSED_FILE
	}
	return unix.FinitModule(fd, "", flags)
}

// 3. the LUKS container
func waitLUKS(con *Console, uuid string) string {
	if uuid == "" {
		halt(con, "no LUKS UUID: set luks.uuid in wisp.conf (the builder takes it from /etc/crypttab) or rd.luks.uuid= on the command line")
	}
	deadline := time.Now().Add(deviceWait)
	for {
		if dev, err := luks.FindByUUID(uuid); err == nil {
			return dev
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	halt(con, "LUKS device %s not found", uuid)
	return ""
}

// 6. the root file system: root=UUID=<uuid> is searched by superblock UUID
// (the opened mapping first, then every block device); root=/dev/... is used
// as given; without root= the opened mapping is the root.
func waitRoot(con *Console, c config) string {
	mapped := "/dev/mapper/" + c.luksName
	deadline := time.Now().Add(deviceWait)
	switch {
	case c.rootUUID != "":
		for {
			if dev, err := blockByFSUUID(c.rootUUID, mapped); err == nil {
				return dev
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		halt(con, "root=UUID=%s: no file system with this UUID found", c.rootUUID)
	case c.rootPath != "":
		for {
			if _, err := os.Stat(c.rootPath); err == nil {
				return c.rootPath
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		halt(con, "root=%s not found (root on LVM needs a recorded volume table, see wisp.conf(5))", c.rootPath)
	case c.key == keyNone:
		halt(con, "key=none needs root= in wisp.conf or on the command line")
	}
	return mapped
}

// mountRoot mounts read-only (the system remounts per fstab); the type comes
// from rootfstype or the superblock.
func mountRoot(con *Console, dev, fstype string) {
	if fstype == "" {
		t, _, err := fsProbe(dev)
		if err != nil {
			halt(con, "%v", err)
		}
		fstype = t
	}
	if err := unix.Mount(dev, "/sysroot", fstype, unix.MS_RDONLY, ""); err != nil {
		halt(con, "mount %s (%s) on /sysroot: %v", dev, fstype, err)
	}
}

// 7. switch_root
func switchRoot(con *Console) {
	for _, fs := range []string{"/proc", "/sys", "/dev", "/run"} {
		unix.Mount(fs, "/sysroot"+fs, "", unix.MS_MOVE, "")
	}
	if err := unix.Chdir("/sysroot"); err != nil {
		halt(con, "chdir /sysroot: %v", err)
	}
	if err := unix.Mount("/sysroot", "/", "", unix.MS_MOVE, ""); err != nil {
		halt(con, "mount --move /sysroot /: %v", err)
	}
	if err := unix.Chroot("."); err != nil {
		halt(con, "chroot: %v", err)
	}
	unix.Chdir("/")
	con.Close()
	err := unix.Exec("/sbin/init", []string{"/sbin/init"}, os.Environ())
	con = openConsole()
	halt(con, "exec /sbin/init: %v", err)
}

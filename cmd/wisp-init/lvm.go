// SPDX-License-Identifier: GPL-2.0-only

package main

// Step 5b: a logical volume behind LUKS without lvm2 and without parsing LVM
// metadata. The builder recorded the root LV's device-mapper table at build
// time into /etc/wisp/lvm.tab, with the backing device replaced by the
// placeholder @crypt@ (the dm-crypt device's major:minor is only known at
// boot). Here the placeholder is filled in and the table is replayed with the
// same device-mapper ioctl that created the dm-crypt device.
//
// Not security relevant: a wrong offset fails to mount, it bypasses nothing;
// the data is already decrypted and the key is gone. Limits: linear (or
// striped) segments over the one crypt device; not thin, cache or RAID.
// Without lvm.tab this is a plain-LUKS system and nothing happens.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"wisp/internal/luks"
)

const lvmTabPath = "/etc/wisp/lvm.tab"

func activateVolumes(con *Console, cryptName string) {
	tab, err := os.ReadFile(lvmTabPath)
	if err != nil {
		return
	}
	cryptDevno, err := dmDevno(cryptName)
	if err != nil {
		halt(con, "volumes: dm-crypt device %q not found: %v", cryptName, err)
	}
	name, uuid, targets, err := parseLvmTab(string(tab), cryptDevno)
	if err != nil {
		halt(con, "volumes: %s: %v", lvmTabPath, err)
	}
	if err := luks.MapTable(name, uuid, targets); err != nil {
		halt(con, "volumes: mapping %q: %v", name, err)
	}
	con.Say("wisp-init: volume %s mapped over dm-crypt %s (%d segment(s))", name, cryptDevno, len(targets))
	mapperNodes(con)
}

// parseLvmTab reads lvm.tab: one `name <dmname>` line, an optional
// `uuid <dm uuid>` line (so that lvm2 in the booted system recognises the
// device as its own), and one `start length type params...` line per
// segment (512-byte sectors, as `dmsetup table` prints). Every @crypt@ in
// the params becomes cryptDevno.
func parseLvmTab(s, cryptDevno string) (name, uuid string, targets []luks.Target, err error) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "name "); ok {
			name = strings.TrimSpace(rest)
			continue
		}
		if rest, ok := strings.CutPrefix(line, "uuid "); ok {
			uuid = strings.TrimSpace(rest)
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			return "", "", nil, fmt.Errorf("segment line too short: %q", line)
		}
		start, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return "", "", nil, fmt.Errorf("start %q: %w", f[0], err)
		}
		length, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return "", "", nil, fmt.Errorf("length %q: %w", f[1], err)
		}
		params := strings.ReplaceAll(strings.Join(f[3:], " "), "@crypt@", cryptDevno)
		targets = append(targets, luks.Target{Start: start, Length: length, Type: f[2], Params: params})
	}
	if name == "" {
		return "", "", nil, fmt.Errorf("no name line")
	}
	if len(targets) == 0 {
		return "", "", nil, fmt.Errorf("no segments")
	}
	return name, uuid, targets, nil
}

// dmDevno returns "major:minor" of the dm device with this name, from sysfs.
func dmDevno(name string) (string, error) {
	dirs, _ := filepath.Glob("/sys/class/block/dm-*")
	for _, d := range dirs {
		n, err := os.ReadFile(filepath.Join(d, "dm", "name"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(n)) != name {
			continue
		}
		dev, err := os.ReadFile(filepath.Join(d, "dev"))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(dev)), nil
	}
	return "", fmt.Errorf("no dm device named %q in /sys/class/block", name)
}

// mapperNodes creates /dev/mapper/<name> for every named dm device, as udev would.
func mapperNodes(con *Console) {
	dirs, _ := filepath.Glob("/sys/class/block/dm-*")
	for _, d := range dirs {
		name, err := os.ReadFile(filepath.Join(d, "dm", "name"))
		if err != nil {
			continue
		}
		dev, err := os.ReadFile(filepath.Join(d, "dev"))
		if err != nil {
			continue
		}
		var major, minor uint32
		if _, err := fmt.Sscanf(strings.TrimSpace(string(dev)), "%d:%d", &major, &minor); err != nil {
			continue
		}
		node := "/dev/mapper/" + strings.TrimSpace(string(name))
		if _, err := os.Stat(node); err == nil {
			continue
		}
		os.MkdirAll("/dev/mapper", 0o755)
		if err := unix.Mknod(node, unix.S_IFBLK|0o600, int(unix.Mkdev(major, minor))); err != nil {
			con.Say("wisp-init: mknod %s: %v", node, err)
		}
	}
}

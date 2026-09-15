// SPDX-License-Identifier: GPL-2.0-only

package main

// What the builder learns from the running system, deliberately little:
// the LUKS container from /etc/crypttab, and the root LV's device-mapper
// table if the root file system lives on a logical volume over the container.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"wisp/internal/luks"
)

// crypttabEntry is one line of /etc/crypttab.
type crypttabEntry struct {
	target, source, options string
}

func readCrypttab(path string) ([]crypttabEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []crypttabEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) < 2 {
			continue
		}
		e := crypttabEntry{target: fs[0], source: fs[1]}
		if len(fs) >= 4 {
			e.options = fs[3]
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// luksUUIDOf resolves a crypttab source to the container UUID.
func luksUUIDOf(source string) (string, error) {
	if u, ok := strings.CutPrefix(source, "UUID="); ok {
		return strings.ToLower(u), nil
	}
	if strings.HasPrefix(source, "/dev/disk/by-uuid/") {
		return strings.ToLower(filepath.Base(source)), nil
	}
	return luks.UUID(source)
}

// rootDevice returns the source device of the root mount from /proc/self/mountinfo.
func rootDevice() (string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		// mount ID, parent ID, major:minor, root, mount point, options, optional..., "-", fstype, source, super options
		if len(fs) < 10 || fs[4] != "/" {
			continue
		}
		for i := 6; i < len(fs); i++ {
			if fs[i] == "-" && i+2 < len(fs) {
				return fs[i+2], nil
			}
		}
	}
	return "", fmt.Errorf("root mount not found in /proc/self/mountinfo")
}

// dmInfo describes a device-mapper device from sysfs.
type dmInfo struct {
	node  string // dm-N
	name  string
	uuid  string
	devno string // major:minor
}

// dmOf resolves /dev/mapper/<name>, /dev/dm-N or a major:minor to its dm info.
func dmOf(dev string) (*dmInfo, error) {
	target := dev
	if resolved, err := filepath.EvalSymlinks(dev); err == nil {
		target = resolved
	}
	base := filepath.Base(target)
	dirs, _ := filepath.Glob("/sys/class/block/dm-*")
	for _, d := range dirs {
		node := filepath.Base(d)
		name, _ := os.ReadFile(filepath.Join(d, "dm", "name"))
		uuid, _ := os.ReadFile(filepath.Join(d, "dm", "uuid"))
		devno, _ := os.ReadFile(filepath.Join(d, "dev"))
		info := &dmInfo{node: node, name: strings.TrimSpace(string(name)), uuid: strings.TrimSpace(string(uuid)), devno: strings.TrimSpace(string(devno))}
		if node == base || info.name == strings.TrimPrefix(dev, "/dev/mapper/") || info.devno == dev {
			return info, nil
		}
	}
	return nil, fmt.Errorf("%s is not a device-mapper device", dev)
}

// rootLayout is what the builder needs to know about the root file system.
type rootLayout struct {
	device string  // the root mount's source
	crypt  *dmInfo // the dm-crypt device, if root is on or over one
	lvmTab string  // recorded lvm.tab content, if root is a linear LV over crypt
	lvName string
	onDM   bool
}

// inspectRoot classifies the root file system: plain device, directly on
// dm-crypt, or a logical volume over dm-crypt (then the LV table is
// recorded with the crypt device replaced by @crypt@). Any other topology
// is an error: the initramfs could not find the root.
func inspectRoot() (*rootLayout, error) {
	dev, err := rootDevice()
	if err != nil {
		return nil, err
	}
	lay := &rootLayout{device: dev}
	info, err := dmOf(dev)
	if err != nil {
		return lay, nil // a plain partition
	}
	lay.onDM = true
	switch {
	case strings.HasPrefix(info.uuid, "CRYPT-"):
		lay.crypt = info
		return lay, nil
	case strings.HasPrefix(info.uuid, "LVM-"):
	default:
		return nil, fmt.Errorf("root is on device-mapper device %s (%s), which is neither dm-crypt nor LVM", info.name, info.uuid)
	}
	out, err := exec.Command("dmsetup", "table", info.name).Output()
	if err != nil {
		return nil, fmt.Errorf("dmsetup table %s: %w (root privileges and the dmsetup package are needed)", info.name, err)
	}
	var lines []string
	backing := ""
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fs := strings.Fields(line)
		if len(fs) < 5 || fs[2] != "linear" {
			return nil, fmt.Errorf("root LV %s has a %q segment; only linear volumes over one device are supported", info.name, line)
		}
		if backing == "" {
			backing = fs[3]
		} else if backing != fs[3] {
			return nil, fmt.Errorf("root LV %s spans more than one physical volume; not supported", info.name)
		}
		lines = append(lines, strings.ReplaceAll(line, fs[3], "@crypt@"))
	}
	crypt, err := dmOf(backing)
	if err != nil || !strings.HasPrefix(crypt.uuid, "CRYPT-") {
		return nil, fmt.Errorf("root LV %s does not sit directly on a dm-crypt device (backing %s); LVM without LUKS is not supported yet", info.name, backing)
	}
	lay.crypt = crypt
	lay.lvName = info.name
	lay.lvmTab = "# recorded by wisp build: device-mapper table of the root LV; @crypt@ = the dm-crypt device at boot\nname " + info.name + "\nuuid " + info.uuid + "\n" + strings.Join(lines, "\n") + "\n"
	return lay, nil
}

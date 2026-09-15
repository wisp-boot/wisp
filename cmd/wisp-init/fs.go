// SPDX-License-Identifier: GPL-2.0-only

package main

// File system type and UUID straight from the superblock: there is no udev
// and no /dev/disk/by-uuid in the initramfs.
//   ext2/3/4  superblock at 1024: magic 0xEF53 at +0x38, UUID at +0x68 (16 bytes)
//   xfs       superblock at 0:    magic "XFSB" at 0,       UUID at 0x20 (16 bytes)
//   btrfs     superblock at 65536: magic "_BHRfS_M" at +0x40, FSID at +0x20 (16 bytes)

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func fsProbe(dev string) (fstype, uuid string, err error) {
	f, err := os.Open(dev)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	b := make([]byte, 65536+4096)
	n, _ := f.ReadAt(b, 0)
	b = b[:n]
	fmtUUID := func(u []byte) string {
		return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	}
	switch {
	case len(b) >= 1024+0x78 && binary.LittleEndian.Uint16(b[1024+0x38:]) == 0xEF53:
		return "ext4", fmtUUID(b[1024+0x68 : 1024+0x78]), nil
	case len(b) >= 0x30 && bytes.Equal(b[0:4], []byte("XFSB")):
		return "xfs", fmtUUID(b[0x20:0x30]), nil
	case len(b) >= 65536+0x48 && bytes.Equal(b[65536+0x40:65536+0x48], []byte("_BHRfS_M")):
		return "btrfs", fmtUUID(b[65536+0x20 : 65536+0x30]), nil
	}
	return "", "", fmt.Errorf("%s: no ext4/xfs/btrfs superblock", dev)
}

// blockByFSUUID finds the block device carrying this file system UUID: the
// given candidate first, then everything under /sys/class/block.
func blockByFSUUID(uuid string, first string) (string, error) {
	uuid = strings.ToLower(uuid)
	cands := []string{first}
	if names, err := filepath.Glob("/sys/class/block/*"); err == nil {
		for _, n := range names {
			cands = append(cands, "/dev/"+filepath.Base(n))
		}
	}
	for _, dev := range cands {
		if _, u, err := fsProbe(dev); err == nil && u == uuid {
			return dev, nil
		}
	}
	return "", os.ErrNotExist
}

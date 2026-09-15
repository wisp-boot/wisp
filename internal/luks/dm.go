// SPDX-License-Identifier: GPL-2.0-only

package luks

// Device-mapper mappings through the ioctl interface on /dev/mapper/control,
// without libdevmapper: DM_DEV_CREATE, DM_TABLE_LOAD, then DM_DEV_SUSPEND as
// the resume. Kernel ABI: struct dm_ioctl (312 bytes) followed by struct
// dm_target_spec (40 bytes) and the parameter string; the ioctl numbers are
// _IOWR(0xfd, cmd, 312). Needs root.

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	dmNameLen = 128
	dmUUIDLen = 129
	dmIoctlSz = 312 // sizeof(struct dm_ioctl)
	dmSpecSz  = 40  // sizeof(struct dm_target_spec)

	dmVersionMajor = 4

	dmIoctlBase  = (uintptr(3) << 30) | (uintptr(dmIoctlSz) << 16) | (uintptr(0xfd) << 8)
	dmDevCreate  = dmIoctlBase | 3
	dmDevSuspend = dmIoctlBase | 6
	dmTableLoad  = dmIoctlBase | 9
)

// deviceSize returns the size in bytes: BLKGETSIZE64 for a block device, the
// file size for a regular file.
func deviceSize(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if fi.Mode().IsRegular() {
		return uint64(fi.Size()), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var sz uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&sz)))
	if errno != 0 {
		return 0, fmt.Errorf("luks: BLKGETSIZE64 %s: %v", path, errno)
	}
	return sz, nil
}

// MapCrypt creates /dev/mapper/<name> as a dm-crypt device over dataDev with
// the volume key in v.
func MapCrypt(name, dataDev string, v *Volume) error {
	sizeBytes, err := strconv.ParseUint(v.Size, 10, 64)
	if err != nil {
		return fmt.Errorf("luks: segment size %q: %w", v.Size, err)
	}
	sector := v.SectorSize
	if sector == 0 {
		sector = 512
	}
	if v.Offset%512 != 0 || sizeBytes%512 != 0 {
		return fmt.Errorf("luks: offset/size not 512-byte aligned")
	}
	// crypt target line: "<cipher> <key_hex> <iv_offset> <device> <data_offset_sectors> [<#opt> <opt>...]"
	// start/length/offset are in 512-byte sectors regardless of the crypto sector size.
	params := fmt.Sprintf("%s %s %d %s %d",
		v.Encryption, hex.EncodeToString(v.MasterKey), v.IvTweak, dataDev, v.Offset/512)
	if sector != 512 {
		params += fmt.Sprintf(" 1 sector_size:%d", sector)
	}
	uuid := fmt.Sprintf("CRYPT-LUKS2-%s-%s", stripDashes(v.UUID), name)
	return MapTable(name, uuid, []Target{{Start: 0, Length: sizeBytes / 512, Type: "crypt", Params: params}})
}

// Target is one line of a dm table: start and length in 512-byte sectors,
// the target type ("linear", "crypt", ...) and the finished parameter string.
type Target struct {
	Start, Length uint64
	Type          string
	Params        string
}

// MapTable creates /dev/mapper/<name> with an arbitrary, possibly
// multi-segment table. uuid may be empty.
func MapTable(name, uuid string, targets []Target) error {
	if len(targets) == 0 {
		return fmt.Errorf("luks: empty dm table for %s", name)
	}
	var blob []byte
	for _, t := range targets {
		if t.Length == 0 {
			return fmt.Errorf("luks: dm target with length 0 (%s)", name)
		}
		blob = append(blob, targetBlob(t.Start, t.Length, t.Type, t.Params)...)
	}
	ctrl, err := os.OpenFile("/dev/mapper/control", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("luks: /dev/mapper/control: %w", err)
	}
	defer ctrl.Close()
	if err := dmIoctl(ctrl, dmDevCreate, name, uuid, 0, 0, nil); err != nil {
		return fmt.Errorf("luks: DM_DEV_CREATE %s: %w", name, err)
	}
	if err := dmIoctl(ctrl, dmTableLoad, name, "", uint32(len(targets)), 0, blob); err != nil {
		return fmt.Errorf("luks: DM_TABLE_LOAD %s: %w", name, err)
	}
	if err := dmIoctl(ctrl, dmDevSuspend, name, "", 0, 0, nil); err != nil {
		return fmt.Errorf("luks: DM_DEV_SUSPEND(resume) %s: %w", name, err)
	}
	return nil
}

// targetBlob builds dm_target_spec plus the NUL-terminated, 8-byte-aligned parameter string.
func targetBlob(start, length uint64, ttype, params string) []byte {
	p := append([]byte(params), 0)
	specLen := dmSpecSz + len(p)
	if pad := specLen % 8; pad != 0 {
		p = append(p, make([]byte, 8-pad)...)
		specLen = dmSpecSz + len(p)
	}
	b := make([]byte, specLen)
	le := func(off int, v uint64) { *(*uint64)(unsafe.Pointer(&b[off])) = v }
	le32 := func(off int, v uint32) { *(*uint32)(unsafe.Pointer(&b[off])) = v }
	le(0, start)              // sector_start
	le(8, length)             // length
	le32(16, 0)               // status
	le32(20, uint32(specLen)) // next
	copy(b[24:24+16], ttype)  // target_type[16]
	copy(b[dmSpecSz:], p)
	return b
}

func dmIoctl(ctrl *os.File, req uintptr, name, uuid string, targetCount uint32, flags uint32, targets []byte) error {
	total := dmIoctlSz + len(targets)
	buf := make([]byte, total)
	le32 := func(off int, v uint32) { *(*uint32)(unsafe.Pointer(&buf[off])) = v }
	le32(0, dmVersionMajor) // version[3]
	le32(4, 0)
	le32(8, 0)
	le32(12, uint32(total)) // data_size
	le32(16, dmIoctlSz)     // data_start
	le32(20, targetCount)   // target_count
	le32(24, 0)             // open_count
	le32(28, flags)         // flags
	le32(32, 0)             // event_nr
	le32(36, 0)             // padding
	if name != "" {
		if len(name) >= dmNameLen {
			return fmt.Errorf("luks: dm name too long")
		}
		copy(buf[48:48+dmNameLen], name)
	}
	if uuid != "" {
		if len(uuid) >= dmUUIDLen {
			return fmt.Errorf("luks: dm uuid too long")
		}
		copy(buf[48+dmNameLen:48+dmNameLen+dmUUIDLen], uuid)
	}
	if len(targets) > 0 {
		copy(buf[dmIoctlSz:], targets)
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, ctrl.Fd(), req, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return fmt.Errorf("ioctl: %v", errno)
	}
	return nil
}

func stripDashes(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

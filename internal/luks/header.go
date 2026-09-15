// SPDX-License-Identifier: GPL-2.0-only

// Package luks opens LUKS2 containers in pure Go: it reads the binary header
// and JSON metadata straight from the block device, recovers the volume key
// from a keyslot with a passphrase or raw key bytes, and creates the dm-crypt
// mapping through the device-mapper ioctl interface. No cryptsetup, no
// libdevmapper, no udev.
//
// The implementation follows the LUKS2 on-disk format specification. It is
// deliberately narrow: aes-xts (the LUKS2 default) and hashes of the SHA-2 and
// SHA-3 families. Other ciphers and hashes are not compiled in.
package luks

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LUKS2 binary header (4096 bytes, big-endian): magic(6) version(2)
// hdr_size(8) seqid(8) label(48) csum_alg(32) salt(64) uuid(40) subsystem(48)
// hdr_offset(8) ... followed by the JSON area up to hdr_size.
const (
	binSize = 4096
	offVer  = 6
	offSize = 8
	offUUID = 168
	lenUUID = 40
)

var magic = []byte("LUKS\xba\xbe")

// header reads the binary header; ok is false if the device is not LUKS2.
func header(dev string) (hdr []byte, ok bool, err error) {
	f, err := os.Open(dev)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b := make([]byte, binSize)
	if _, err := f.ReadAt(b, 0); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(b[:6], magic) {
		return nil, false, nil
	}
	if v := binary.BigEndian.Uint16(b[offVer:]); v != 2 {
		return nil, false, fmt.Errorf("%s: LUKS version %d, only LUKS2 is supported", dev, v)
	}
	return b, true, nil
}

func uuidOf(hdr []byte) string {
	u := hdr[offUUID : offUUID+lenUUID]
	if i := bytes.IndexByte(u, 0); i >= 0 {
		u = u[:i]
	}
	return string(u)
}

// FindByUUID scans /sys/class/block for the LUKS2 device with this UUID
// (like blkid -U, without a cache).
func FindByUUID(uuid string) (string, error) {
	uuid = strings.ToLower(uuid)
	names, err := filepath.Glob("/sys/class/block/*")
	if err != nil {
		return "", err
	}
	for _, n := range names {
		dev := "/dev/" + filepath.Base(n)
		hdr, ok, err := header(dev)
		if err != nil || !ok {
			continue
		}
		if strings.ToLower(uuidOf(hdr)) == uuid {
			return dev, nil
		}
	}
	return "", fmt.Errorf("no LUKS2 device with UUID %s", uuid)
}

// UUID returns the UUID of a LUKS2 device.
func UUID(dev string) (string, error) {
	hdr, ok, err := header(dev)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%s: no LUKS2 header", dev)
	}
	return uuidOf(hdr), nil
}

// HeaderJSON returns the JSON area of the primary header without the NUL
// padding. It holds keyslots, tokens, segments and digests: every new keyslot
// or token changes it.
func HeaderJSON(dev string) ([]byte, error) {
	hdr, ok, err := header(dev)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s: no LUKS2 header", dev)
	}
	size := binary.BigEndian.Uint64(hdr[offSize:])
	if size <= binSize || size > 64<<20 {
		return nil, fmt.Errorf("%s: implausible hdr_size %d", dev, size)
	}
	f, err := os.Open(dev)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	js := make([]byte, size-binSize)
	if _, err := f.ReadAt(js, binSize); err != nil {
		return nil, err
	}
	if i := bytes.IndexByte(js, 0); i >= 0 {
		js = js[:i]
	}
	return js, nil
}

// HeaderDigest is SHA-256(HeaderJSON).
func HeaderDigest(dev string) ([]byte, error) {
	js, err := HeaderJSON(dev)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(js)
	return d[:], nil
}

// FindAll lists every LUKS2 block device.
func FindAll() ([]string, error) {
	names, err := filepath.Glob("/sys/class/block/*")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		dev := "/dev/" + filepath.Base(n)
		if _, ok, err := header(dev); err == nil && ok {
			out = append(out, dev)
		}
	}
	return out, nil
}

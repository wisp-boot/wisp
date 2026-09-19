// SPDX-License-Identifier: GPL-2.0-only

package luks

// Volume key recovery: from a secret (a passphrase, or raw key bytes handed
// over by a key provider) to the LUKS2 volume key, without cryptsetup.
// Per keyslot: KDF (argon2id, argon2i or pbkdf2) -> keyslot key; decrypt the
// keyslot area with AES-XTS (512-byte sectors, tweak = sector index);
// anti-forensic merge (hash diffusion) -> volume key candidate; verify against
// the pbkdf2 digest. Correctness is checked by the differential test against
// cryptsetup (unlock_test.go): the recovered key must equal cryptsetup's.

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/xts"

	"wisp/internal/lukstab"
)

const (
	afStripes  = 4000 // LUKS requires exactly 4000 anti-forensic stripes
	slotSector = 512  // sector size of the keyslot area
	maxKeySize = 4096 // bound: key_size * 4000 sizes the allocation
	// maxArgon2Memory bounds kdf memory (KiB): cryptsetup never asks for more
	// than 4 GiB, and above it a table would only exhaust memory before the
	// passphrase is even checked. The builder refuses such headers; the init
	// checks again, because the table is the only input it trusts.
	maxArgon2Memory = 4 << 20
)

// ErrNoKeyslot: no keyslot opened with the given secret (wrong passphrase or key).
var ErrNoKeyslot = errors.New("luks: no keyslot opens with this secret")

// ErrHeaderChanged: the JSON area on the device is not the one the table was
// built from.
var ErrHeaderChanged = errors.New("luks: header changed since the initramfs was built (luksAddKey, luksChangeKey, ...): run wisp build")

// Volume is a recovered volume key plus the segment parameters needed for
// the dm-crypt mapping.
type Volume struct {
	MasterKey  []byte
	UUID       string
	Encryption string // e.g. aes-xts-plain64
	SectorSize uint64
	Offset     uint64 // data offset in the backing device (bytes)
	Size       string // "dynamic" or a decimal byte count
	IvTweak    uint64
}

// CheckHeader hashes the JSON area of headerSrc and compares it with the
// table's. The init calls this before anything else touches the header: on
// a match the table describes exactly the header on the device, without a
// mismatch nothing on the device is parsed.
func CheckHeader(headerSrc string, tab *lukstab.Table) error {
	d, err := HeaderDigest(headerSrc)
	if err != nil {
		return err
	}
	if !constEqual(d, tab.HeaderSHA256) {
		return ErrHeaderChanged
	}
	return nil
}

// Recover recovers the volume key with secret from the keyslots the table
// describes, reading only the keyslot areas of headerSrc (the device, or a
// detached header file). Every keyslot is tried in table order; ErrNoKeyslot
// if none matches. dataDev is the backing device (needed when the segment
// size is "dynamic"); it may equal headerSrc.
func Recover(tab *lukstab.Table, headerSrc, dataDev string, secret []byte) (*Volume, error) {
	f, err := os.Open(headerSrc)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	for i := range tab.Keyslots {
		ks := &tab.Keyslots[i]
		mk, err := recoverFromKeyslot(f, ks, tab, secret)
		if err != nil {
			if errors.Is(err, ErrNoKeyslot) {
				continue
			}
			return nil, err
		}
		seg, err := cryptSegmentFor(tab, ks.ID)
		if err != nil {
			clear(mk)
			return nil, err
		}
		size := seg.Size
		if size == "dynamic" {
			size, err = dynamicSize(dataDev, seg.Offset)
			if err != nil {
				clear(mk)
				return nil, err
			}
		}
		return &Volume{
			MasterKey:  mk,
			UUID:       tab.UUID,
			Encryption: seg.Encryption,
			SectorSize: seg.SectorSize,
			Offset:     seg.Offset,
			Size:       size,
			IvTweak:    seg.IvTweak,
		}, nil
	}
	return nil, ErrNoKeyslot
}

func recoverFromKeyslot(f *os.File, ks *lukstab.Keyslot, tab *lukstab.Table, secret []byte) ([]byte, error) {
	// Bound the sizes before allocating from them, whatever the table says.
	if ks.KeySize == 0 || ks.KeySize > maxKeySize || ks.AreaKeySize == 0 || ks.AreaKeySize > maxKeySize {
		return nil, fmt.Errorf("luks: keyslot %s: key_size %d/%d outside 1..%d", ks.ID, ks.KeySize, ks.AreaKeySize, maxKeySize)
	}
	// 1. keyslot key from the secret (KDF), length = area key size
	afKey, err := deriveKey(ks, secret, int(ks.AreaKeySize))
	if err != nil {
		return nil, err
	}
	defer clear(afKey)
	// 2. read the keyslot area (key_size * stripes bytes), decrypt sector by sector
	if ks.AfStripes != afStripes {
		return nil, fmt.Errorf("luks: keyslot %s: %d AF stripes, only %d supported", ks.ID, ks.AfStripes, afStripes)
	}
	slotLen := int(ks.KeySize) * afStripes
	if slotLen%slotSector != 0 {
		return nil, fmt.Errorf("luks: keyslot %s: length %d not sector aligned", ks.ID, slotLen)
	}
	if uint64(slotLen) > ks.AreaSize {
		return nil, fmt.Errorf("luks: keyslot %s: area too small (%d < %d)", ks.ID, ks.AreaSize, slotLen)
	}
	if ks.AreaOffset > 1<<62 {
		return nil, fmt.Errorf("luks: keyslot %s: area offset %d", ks.ID, ks.AreaOffset)
	}
	buf := make([]byte, slotLen)
	if _, err := f.ReadAt(buf, int64(ks.AreaOffset)); err != nil {
		return nil, fmt.Errorf("luks: keyslot %s: read area: %w", ks.ID, err)
	}
	ciph, err := xtsCipher(ks.AreaEncryption, afKey)
	if err != nil {
		return nil, err
	}
	for i := 0; i < slotLen/slotSector; i++ {
		b := buf[i*slotSector : (i+1)*slotSector]
		ciph.Decrypt(b, b, uint64(i))
	}
	// 3. anti-forensic merge -> volume key candidate
	afh, _ := hashFor(ks.AfHash)
	if afh == nil {
		return nil, fmt.Errorf("luks: keyslot %s: unknown AF hash %q", ks.ID, ks.AfHash)
	}
	mk := afMerge(buf, int(ks.KeySize), afStripes, afh())
	clear(buf)
	// 4. verify against the digest; a mismatch means a wrong secret
	dig := digestForKeyslot(tab, ks.ID)
	if dig == nil {
		clear(mk)
		return nil, fmt.Errorf("luks: no digest for keyslot %s", ks.ID)
	}
	ok, err := digestMatches(dig, mk)
	if err != nil {
		clear(mk)
		return nil, err
	}
	if !ok {
		clear(mk)
		return nil, ErrNoKeyslot
	}
	return mk, nil
}

func deriveKey(ks *lukstab.Keyslot, secret []byte, keyLen int) ([]byte, error) {
	switch ks.KdfType {
	case "pbkdf2":
		h, _ := hashFor(ks.KdfHash)
		if h == nil {
			return nil, fmt.Errorf("luks: unknown kdf hash %q", ks.KdfHash)
		}
		if ks.KdfIterations == 0 || ks.KdfIterations > 1<<31 {
			return nil, fmt.Errorf("luks: pbkdf2 iterations %d out of range", ks.KdfIterations)
		}
		return pbkdf2.Key(secret, ks.Salt, int(ks.KdfIterations), keyLen, h), nil
	case "argon2i", "argon2id":
		// x/crypto/argon2 panics on time 0 or cpus 0, and memory is an allocation.
		if ks.KdfTime == 0 || ks.KdfTime > 1<<31 || ks.KdfCpus == 0 || ks.KdfCpus > 255 || ks.KdfMemory == 0 || ks.KdfMemory > maxArgon2Memory {
			return nil, fmt.Errorf("luks: argon2 parameters out of range (time %d, memory %d KiB, cpus %d)", ks.KdfTime, ks.KdfMemory, ks.KdfCpus)
		}
		if ks.KdfType == "argon2i" {
			return argon2.Key(secret, ks.Salt, uint32(ks.KdfTime), uint32(ks.KdfMemory), uint8(ks.KdfCpus), uint32(keyLen)), nil
		}
		return argon2.IDKey(secret, ks.Salt, uint32(ks.KdfTime), uint32(ks.KdfMemory), uint8(ks.KdfCpus), uint32(keyLen)), nil
	default:
		return nil, fmt.Errorf("luks: unknown kdf type %q", ks.KdfType)
	}
}

func digestMatches(dig *lukstab.Digest, mk []byte) (bool, error) {
	h, size := hashFor(dig.Hash)
	if h == nil {
		return false, fmt.Errorf("luks: unknown digest hash %q", dig.Hash)
	}
	if dig.Iterations == 0 || dig.Iterations > 1<<31 {
		return false, fmt.Errorf("luks: digest iterations %d out of range", dig.Iterations)
	}
	got := pbkdf2.Key(mk, dig.Salt, int(dig.Iterations), size, h)
	if len(dig.Digest) == 0 || len(dig.Digest) > len(got) {
		return false, nil
	}
	return constEqual(got[:len(dig.Digest)], dig.Digest), nil
}

func digestForKeyslot(tab *lukstab.Table, id string) *lukstab.Digest {
	for i := range tab.Digests {
		for _, k := range tab.Digests[i].Keyslots {
			if k == id {
				return &tab.Digests[i]
			}
		}
	}
	return nil
}

func cryptSegmentFor(tab *lukstab.Table, id string) (*lukstab.Segment, error) {
	dig := digestForKeyslot(tab, id)
	if dig == nil {
		return nil, fmt.Errorf("luks: no digest (segment) for keyslot %s", id)
	}
	for _, sid := range dig.Segments {
		for i := range tab.Segments {
			if tab.Segments[i].ID == sid {
				return &tab.Segments[i], nil
			}
		}
	}
	return nil, fmt.Errorf("luks: no crypt segment for keyslot %s", id)
}

func dynamicSize(dataDev string, offset uint64) (string, error) {
	if dataDev == "" {
		return "", fmt.Errorf("luks: segment size is dynamic but no data device given")
	}
	total, err := deviceSize(dataDev)
	if err != nil {
		return "", err
	}
	if total < offset {
		return "", fmt.Errorf("luks: device size %d smaller than offset %d", total, offset)
	}
	return strconv.FormatUint(total-offset, 10), nil
}

func xtsCipher(encryption string, key []byte) (*xts.Cipher, error) {
	name, mode := splitEnc(encryption)
	if name != "aes" {
		return nil, fmt.Errorf("luks: cipher %q not supported (only aes)", name)
	}
	if mode != "xts" {
		return nil, fmt.Errorf("luks: mode %q not supported (only xts)", mode)
	}
	return xts.NewCipher(aes.NewCipher, key)
}

// splitEnc splits "cipher-mode-iv" (e.g. aes-xts-plain64) into cipher and mode.
func splitEnc(s string) (name, mode string) {
	first := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			if first < 0 {
				first = i
				name = s[:i]
			} else {
				mode = s[first+1 : i]
				return
			}
		}
	}
	return name, ""
}

func hashFor(name string) (func() hash.Hash, int) {
	switch name {
	case "sha1":
		return sha1.New, sha1.Size
	case "sha224":
		return sha256.New224, sha256.Size224
	case "sha256":
		return sha256.New, sha256.Size
	case "sha384":
		return sha512.New384, sha512.Size384
	case "sha512":
		return sha512.New, sha512.Size
	case "sha3-256":
		return sha3.New256, 32
	case "sha3-384":
		return sha3.New384, 48
	case "sha3-512":
		return sha3.New512, 64
	default:
		return nil, 0
	}
}

// Anti-forensic merge with hash diffusion, as specified for LUKS.

func afMerge(src []byte, blockSize, blockNum int, h hash.Hash) []byte {
	buf := make([]byte, blockSize)
	for i := 0; i < blockNum-1; i++ {
		b := src[blockSize*i : blockSize*(i+1)]
		xorInto(buf, b, buf)
		buf = diffuse(buf, h)
	}
	xorInto(buf, src[blockSize*(blockNum-1):blockSize*blockNum], buf)
	return buf
}

func diffuse(src []byte, h hash.Hash) []byte {
	n := len(src)
	ds := h.Size()
	out := make([]byte, 0, n)
	full := n / ds
	for i := 0; i < full; i++ {
		out = hashBlock(src[i*ds:(i+1)*ds], h, i, out)
	}
	if pad := n % ds; pad != 0 {
		out = hashBlock(src[n-pad:], h, full, out)
		out = out[:n]
	}
	return out
}

func hashBlock(src []byte, h hash.Hash, iv int, out []byte) []byte {
	var pre [4]byte
	pre[0] = byte(iv >> 24)
	pre[1] = byte(iv >> 16)
	pre[2] = byte(iv >> 8)
	pre[3] = byte(iv)
	h.Reset()
	h.Write(pre[:])
	h.Write(src)
	return h.Sum(out)
}

func xorInto(a, b, dst []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

func constEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

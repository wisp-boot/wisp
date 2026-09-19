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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/xts"
)

const (
	afStripes  = 4000 // LUKS requires exactly 4000 anti-forensic stripes
	slotSector = 512  // sector size of the keyslot area
	maxKeySize = 4096 // bound against a manipulated header: key_size * 4000 sizes the allocation
	// maxArgon2Memory bounds kdf.memory (KiB) from the header: cryptsetup never
	// asks for more than 4 GiB, and above it a manipulated header would only
	// exhaust memory before the passphrase is even checked.
	maxArgon2Memory = 4 << 20
)

// ErrNoKeyslot: no keyslot opened with the given secret (wrong passphrase or key).
var ErrNoKeyslot = errors.New("luks: no keyslot opens with this secret")

type jsonMeta struct {
	Keyslots map[string]jsonKeyslot `json:"keyslots"`
	Segments map[string]jsonSegment `json:"segments"`
	Digests  map[string]jsonDigest  `json:"digests"`
}

type jsonKeyslot struct {
	Type    string   `json:"type"`
	KeySize uint     `json:"key_size"`
	Af      jsonAf   `json:"af"`
	Area    jsonArea `json:"area"`
	Kdf     jsonKdf  `json:"kdf"`
}

type jsonAf struct {
	Stripes uint   `json:"stripes"`
	Hash    string `json:"hash"`
}

type jsonArea struct {
	Encryption string      `json:"encryption"`
	KeySize    uint        `json:"key_size"`
	Offset     json.Number `json:"offset"`
	Size       json.Number `json:"size"`
}

type jsonKdf struct {
	Type       string `json:"type"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations uint   `json:"iterations"`
	Time       uint   `json:"time"`
	Memory     uint   `json:"memory"`
	Cpus       uint   `json:"cpus"`
}

type jsonSegment struct {
	Type       string      `json:"type"`
	Offset     json.Number `json:"offset"`
	IvTweak    json.Number `json:"iv_tweak"`
	Size       string      `json:"size"`
	Encryption string      `json:"encryption"`
	SectorSize uint        `json:"sector_size"`
}

type jsonDigest struct {
	Type       string   `json:"type"`
	Keyslots   []string `json:"keyslots"`
	Segments   []string `json:"segments"`
	Hash       string   `json:"hash"`
	Iterations uint     `json:"iterations"`
	Salt       string   `json:"salt"`
	Digest     string   `json:"digest"`
}

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

// Recover recovers the volume key from headerSrc (the device, or a detached
// header file) with secret. Every keyslot is tried; ErrNoKeyslot if none
// matches. dataDev is the backing device (needed when the segment size is
// "dynamic"); it may equal headerSrc.
func Recover(headerSrc, dataDev string, secret []byte) (*Volume, error) {
	jsRaw, err := HeaderJSON(headerSrc)
	if err != nil {
		return nil, err
	}
	var meta jsonMeta
	if err := json.Unmarshal(jsRaw, &meta); err != nil {
		return nil, fmt.Errorf("luks: unreadable JSON metadata: %w", err)
	}
	uuid, _ := UUID(headerSrc)

	f, err := os.Open(headerSrc)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	for idx, ks := range meta.Keyslots {
		if ks.Type != "luks2" {
			continue
		}
		mk, err := recoverFromKeyslot(f, idx, ks, meta, secret)
		if err != nil {
			if errors.Is(err, ErrNoKeyslot) {
				continue
			}
			return nil, err
		}
		seg, err := cryptSegmentFor(meta, idx)
		if err != nil {
			clear(mk)
			return nil, err
		}
		off, _ := seg.Offset.Int64()
		iv, _ := seg.IvTweak.Int64()
		size := seg.Size
		if size == "dynamic" {
			size, err = dynamicSize(dataDev, uint64(off))
			if err != nil {
				clear(mk)
				return nil, err
			}
		}
		return &Volume{
			MasterKey:  mk,
			UUID:       uuid,
			Encryption: seg.Encryption,
			SectorSize: uint64(seg.SectorSize),
			Offset:     uint64(off),
			Size:       size,
			IvTweak:    uint64(iv),
		}, nil
	}
	return nil, ErrNoKeyslot
}

func recoverFromKeyslot(f *os.File, idx string, ks jsonKeyslot, meta jsonMeta, secret []byte) ([]byte, error) {
	// Bound key_size from the (possibly manipulated) header before allocating from it.
	if ks.KeySize == 0 || ks.KeySize > maxKeySize || ks.Area.KeySize == 0 || ks.Area.KeySize > maxKeySize {
		return nil, fmt.Errorf("luks: keyslot %s: key_size %d/%d outside 1..%d", idx, ks.KeySize, ks.Area.KeySize, maxKeySize)
	}
	// 1. keyslot key from the secret (KDF), length = area key size
	afKey, err := deriveKey(ks.Kdf, secret, int(ks.Area.KeySize))
	if err != nil {
		return nil, err
	}
	defer clear(afKey)

	// 2. read the keyslot area (key_size * stripes bytes), decrypt sector by sector
	if ks.Af.Stripes != afStripes {
		return nil, fmt.Errorf("luks: keyslot %s: %d AF stripes, only %d supported", idx, ks.Af.Stripes, afStripes)
	}
	slotLen := int(ks.KeySize) * afStripes
	if slotLen%slotSector != 0 {
		return nil, fmt.Errorf("luks: keyslot %s: length %d not sector aligned", idx, slotLen)
	}
	areaSize, _ := ks.Area.Size.Int64()
	if int64(slotLen) > areaSize {
		return nil, fmt.Errorf("luks: keyslot %s: area too small (%d < %d)", idx, areaSize, slotLen)
	}
	off, _ := ks.Area.Offset.Int64()
	buf := make([]byte, slotLen)
	if _, err := f.ReadAt(buf, off); err != nil {
		return nil, fmt.Errorf("luks: keyslot %s: read area: %w", idx, err)
	}
	ciph, err := xtsCipher(ks.Area.Encryption, afKey)
	if err != nil {
		return nil, err
	}
	for i := 0; i < slotLen/slotSector; i++ {
		b := buf[i*slotSector : (i+1)*slotSector]
		ciph.Decrypt(b, b, uint64(i))
	}

	// 3. anti-forensic merge -> volume key candidate
	afh, _ := hashFor(ks.Af.Hash)
	if afh == nil {
		return nil, fmt.Errorf("luks: keyslot %s: unknown AF hash %q", idx, ks.Af.Hash)
	}
	mk := afMerge(buf, int(ks.KeySize), afStripes, afh())
	clear(buf)

	// 4. verify against the digest; a mismatch means a wrong secret
	dig := digestForKeyslot(meta, idx)
	if dig == nil {
		clear(mk)
		return nil, fmt.Errorf("luks: no digest for keyslot %s", idx)
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

func deriveKey(kdf jsonKdf, secret []byte, keyLen int) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(kdf.Salt)
	if err != nil {
		return nil, fmt.Errorf("luks: kdf.salt base64: %w", err)
	}
	switch kdf.Type {
	case "pbkdf2":
		h, _ := hashFor(kdf.Hash)
		if h == nil {
			return nil, fmt.Errorf("luks: unknown kdf hash %q", kdf.Hash)
		}
		return pbkdf2.Key(secret, salt, int(kdf.Iterations), keyLen, h), nil
	case "argon2i", "argon2id":
		// The header is unauthenticated input: x/crypto/argon2 panics on
		// time 0 or cpus 0, and memory is an allocation the header dictates.
		// Refuse before calling, with a reason, instead of dying as PID 1.
		if kdf.Time == 0 || kdf.Cpus == 0 || kdf.Cpus > 255 || kdf.Memory == 0 || kdf.Memory > maxArgon2Memory {
			return nil, fmt.Errorf("luks: argon2 parameters out of range (time %d, memory %d KiB, cpus %d)", kdf.Time, kdf.Memory, kdf.Cpus)
		}
		if kdf.Type == "argon2i" {
			return argon2.Key(secret, salt, uint32(kdf.Time), uint32(kdf.Memory), uint8(kdf.Cpus), uint32(keyLen)), nil
		}
		return argon2.IDKey(secret, salt, uint32(kdf.Time), uint32(kdf.Memory), uint8(kdf.Cpus), uint32(keyLen)), nil
	default:
		return nil, fmt.Errorf("luks: unknown kdf type %q", kdf.Type)
	}
}

func digestMatches(dig *jsonDigest, mk []byte) (bool, error) {
	if dig.Type != "pbkdf2" {
		return false, fmt.Errorf("luks: unknown digest type %q", dig.Type)
	}
	salt, err := base64.StdEncoding.DecodeString(dig.Salt)
	if err != nil {
		return false, fmt.Errorf("luks: digest.salt base64: %w", err)
	}
	want, err := base64.StdEncoding.DecodeString(dig.Digest)
	if err != nil {
		return false, fmt.Errorf("luks: digest.digest base64: %w", err)
	}
	h, size := hashFor(dig.Hash)
	if h == nil {
		return false, fmt.Errorf("luks: unknown digest hash %q", dig.Hash)
	}
	got := pbkdf2.Key(mk, salt, int(dig.Iterations), size, h)
	if len(want) > len(got) {
		return false, nil
	}
	return constEqual(got[:len(want)], want), nil
}

func digestForKeyslot(meta jsonMeta, idx string) *jsonDigest {
	for _, d := range meta.Digests {
		for _, k := range d.Keyslots {
			if k == idx {
				dd := d
				return &dd
			}
		}
	}
	return nil
}

func cryptSegmentFor(meta jsonMeta, idx string) (*jsonSegment, error) {
	dig := digestForKeyslot(meta, idx)
	if dig == nil {
		return nil, fmt.Errorf("luks: no digest (segment) for keyslot %s", idx)
	}
	for _, sid := range dig.Segments {
		if s, ok := meta.Segments[sid]; ok && s.Type == "crypt" {
			ss := s
			return &ss, nil
		}
	}
	return nil, fmt.Errorf("luks: no crypt segment for keyslot %s", idx)
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

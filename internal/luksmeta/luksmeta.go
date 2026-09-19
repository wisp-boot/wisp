// SPDX-License-Identifier: GPL-2.0-only

// Package luksmeta reads a LUKS2 header's JSON area and turns it into the
// table the initramfs carries (internal/lukstab). It runs in the builder,
// where a bad header may be loud; the init never sees JSON. Every value
// the init will act on is checked here against the bounds the init will
// check again: the table is the contract, and both sides hold it.
//
// Follows the LUKS2 on-disk format specification: keyslots (type luks2 with
// af, area and kdf), digests (pbkdf2 over the volume key, naming keyslots and
// segments) and segments (type crypt). Only aes-xts areas and SHA-2/SHA-3
// hashes are accepted, as in the init.
package luksmeta

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"wisp/internal/luks"
	"wisp/internal/lukstab"
)

type jsonMeta struct {
	Keyslots map[string]jsonKeyslot `json:"keyslots"`
	Segments map[string]jsonSegment `json:"segments"`
	Digests  map[string]jsonDigest  `json:"digests"`
}

type jsonKeyslot struct {
	Type    string   `json:"type"`
	KeySize uint64   `json:"key_size"`
	Af      jsonAf   `json:"af"`
	Area    jsonArea `json:"area"`
	Kdf     jsonKdf  `json:"kdf"`
}

type jsonAf struct {
	Type    string `json:"type"`
	Stripes uint64 `json:"stripes"`
	Hash    string `json:"hash"`
}

type jsonArea struct {
	Type       string      `json:"type"`
	Encryption string      `json:"encryption"`
	KeySize    uint64      `json:"key_size"`
	Offset     json.Number `json:"offset"`
	Size       json.Number `json:"size"`
}

type jsonKdf struct {
	Type       string `json:"type"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations uint64 `json:"iterations"`
	Time       uint64 `json:"time"`
	Memory     uint64 `json:"memory"`
	Cpus       uint64 `json:"cpus"`
}

type jsonSegment struct {
	Type       string      `json:"type"`
	Offset     json.Number `json:"offset"`
	IvTweak    json.Number `json:"iv_tweak"`
	Size       string      `json:"size"`
	Encryption string      `json:"encryption"`
	SectorSize uint64      `json:"sector_size"`
}

type jsonDigest struct {
	Type       string   `json:"type"`
	Keyslots   []string `json:"keyslots"`
	Segments   []string `json:"segments"`
	Hash       string   `json:"hash"`
	Iterations uint64   `json:"iterations"`
	Salt       string   `json:"salt"`
	Digest     string   `json:"digest"`
}

// Bounds the init enforces too (internal/luks).
const (
	maxKeySize      = 4096
	afStripes       = 4000
	maxArgon2Memory = 4 << 20 // KiB
	maxIterations   = 1 << 31
)

var hashes = map[string]bool{"sha1": true, "sha224": true, "sha256": true, "sha384": true, "sha512": true,
	"sha3-256": true, "sha3-384": true, "sha3-512": true}

// Read reads the header of headerSrc (a device or a detached header file)
// and returns the table, or an error naming what the init could not act on.
func Read(headerSrc string) (*lukstab.Table, error) {
	js, err := luks.HeaderJSON(headerSrc)
	if err != nil {
		return nil, err
	}
	uuid, err := luks.UUID(headerSrc)
	if err != nil {
		return nil, err
	}
	tab, err := FromJSON(js)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", headerSrc, err)
	}
	tab.UUID = uuid
	return tab, nil
}

// FromJSON converts a JSON area to a table. HeaderSHA256 is set to the hash
// of js; UUID is left for the caller.
func FromJSON(js []byte) (*lukstab.Table, error) {
	var meta jsonMeta
	if err := json.Unmarshal(js, &meta); err != nil {
		return nil, fmt.Errorf("luks header: unreadable JSON metadata: %w", err)
	}
	tab := &lukstab.Table{HeaderSHA256: luks.DigestOf(js)}
	num := func(what string, n json.Number) (uint64, error) {
		v, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("luks header: %s: %q is not an unsigned number", what, n.String())
		}
		return v, nil
	}
	b64 := func(what, s string) ([]byte, error) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("luks header: %s: not base64", what)
		}
		return b, nil
	}
	for _, id := range sortedKeys(meta.Segments) {
		s := meta.Segments[id]
		if s.Type != "crypt" {
			continue
		}
		off, err := num("segment "+id+" offset", s.Offset)
		if err != nil {
			return nil, err
		}
		iv := uint64(0)
		if s.IvTweak != "" {
			if iv, err = num("segment "+id+" iv_tweak", s.IvTweak); err != nil {
				return nil, err
			}
		}
		if s.Size != "dynamic" {
			if _, err := strconv.ParseUint(s.Size, 10, 64); err != nil {
				return nil, fmt.Errorf("luks header: segment %s: size %q", id, s.Size)
			}
		}
		switch s.SectorSize {
		case 512, 1024, 2048, 4096:
		default:
			return nil, fmt.Errorf("luks header: segment %s: sector_size %d", id, s.SectorSize)
		}
		if s.Encryption == "" {
			return nil, fmt.Errorf("luks header: segment %s: no encryption", id)
		}
		tab.Segments = append(tab.Segments, lukstab.Segment{ID: id, Encryption: s.Encryption, SectorSize: s.SectorSize, Offset: off, Size: s.Size, IvTweak: iv})
	}
	for _, id := range sortedKeys(meta.Digests) {
		d := meta.Digests[id]
		if d.Type != "pbkdf2" {
			return nil, fmt.Errorf("luks header: digest %s: type %q, only pbkdf2 is supported", id, d.Type)
		}
		if !hashes[d.Hash] {
			return nil, fmt.Errorf("luks header: digest %s: hash %q not supported", id, d.Hash)
		}
		if d.Iterations == 0 || d.Iterations > maxIterations {
			return nil, fmt.Errorf("luks header: digest %s: iterations %d", id, d.Iterations)
		}
		salt, err := b64("digest "+id+" salt", d.Salt)
		if err != nil {
			return nil, err
		}
		dig, err := b64("digest "+id+" digest", d.Digest)
		if err != nil {
			return nil, err
		}
		tab.Digests = append(tab.Digests, lukstab.Digest{ID: id, Hash: d.Hash, Iterations: d.Iterations, Salt: salt, Digest: dig,
			Keyslots: append([]string(nil), d.Keyslots...), Segments: append([]string(nil), d.Segments...)})
	}
	for _, id := range sortedKeys(meta.Keyslots) {
		k := meta.Keyslots[id]
		if k.Type != "luks2" {
			continue // reencrypt and placeholder slots hold no key
		}
		if k.KeySize == 0 || k.KeySize > maxKeySize || k.Area.KeySize == 0 || k.Area.KeySize > maxKeySize {
			return nil, fmt.Errorf("luks header: keyslot %s: key_size %d/%d outside 1..%d", id, k.KeySize, k.Area.KeySize, maxKeySize)
		}
		if k.Af.Type != "luks1" || k.Af.Stripes != afStripes || !hashes[k.Af.Hash] {
			return nil, fmt.Errorf("luks header: keyslot %s: af %s/%d/%s not supported", id, k.Af.Type, k.Af.Stripes, k.Af.Hash)
		}
		if k.Area.Type != "raw" || k.Area.Encryption == "" {
			return nil, fmt.Errorf("luks header: keyslot %s: area type %q", id, k.Area.Type)
		}
		off, err := num("keyslot "+id+" area offset", k.Area.Offset)
		if err != nil {
			return nil, err
		}
		size, err := num("keyslot "+id+" area size", k.Area.Size)
		if err != nil {
			return nil, err
		}
		if size < k.KeySize*afStripes {
			return nil, fmt.Errorf("luks header: keyslot %s: area %d smaller than key_size*stripes %d", id, size, k.KeySize*afStripes)
		}
		salt, err := b64("keyslot "+id+" kdf salt", k.Kdf.Salt)
		if err != nil {
			return nil, err
		}
		ks := lukstab.Keyslot{ID: id, KeySize: k.KeySize, AreaEncryption: k.Area.Encryption, AreaKeySize: k.Area.KeySize,
			AreaOffset: off, AreaSize: size, AfHash: k.Af.Hash, AfStripes: k.Af.Stripes, KdfType: k.Kdf.Type, Salt: salt}
		switch k.Kdf.Type {
		case "pbkdf2":
			if !hashes[k.Kdf.Hash] || k.Kdf.Iterations == 0 || k.Kdf.Iterations > maxIterations {
				return nil, fmt.Errorf("luks header: keyslot %s: pbkdf2 %s/%d not supported", id, k.Kdf.Hash, k.Kdf.Iterations)
			}
			ks.KdfHash, ks.KdfIterations = k.Kdf.Hash, k.Kdf.Iterations
		case "argon2i", "argon2id":
			if k.Kdf.Time == 0 || k.Kdf.Time > maxIterations || k.Kdf.Cpus == 0 || k.Kdf.Cpus > 255 || k.Kdf.Memory == 0 || k.Kdf.Memory > maxArgon2Memory {
				return nil, fmt.Errorf("luks header: keyslot %s: argon2 parameters out of range (time %d, memory %d KiB, cpus %d)", id, k.Kdf.Time, k.Kdf.Memory, k.Kdf.Cpus)
			}
			ks.KdfTime, ks.KdfMemory, ks.KdfCpus = k.Kdf.Time, k.Kdf.Memory, k.Kdf.Cpus
		default:
			return nil, fmt.Errorf("luks header: keyslot %s: kdf type %q not supported", id, k.Kdf.Type)
		}
		// every usable keyslot needs a digest that names a crypt segment
		found := false
		for _, d := range tab.Digests {
			for _, kk := range d.Keyslots {
				if kk != id {
					continue
				}
				for _, sid := range d.Segments {
					for _, s := range tab.Segments {
						if s.ID == sid {
							found = true
						}
					}
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("luks header: keyslot %s: no digest with a crypt segment", id)
		}
		tab.Keyslots = append(tab.Keyslots, ks)
	}
	if len(tab.Keyslots) == 0 {
		return nil, fmt.Errorf("luks header: no usable keyslot")
	}
	return tab, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		x, ex := strconv.Atoi(out[i])
		y, ey := strconv.Atoi(out[j])
		if ex == nil && ey == nil {
			return x < y
		}
		return out[i] < out[j]
	})
	return out
}

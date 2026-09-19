// SPDX-License-Identifier: GPL-2.0-only

// Package lukstab is the LUKS table an initrd carries at /etc/wisp/luks.tab:
// everything the init needs to know about the container's keyslots, digests
// and segments, as the builder read it from the LUKS2 header's JSON area
// (internal/luksmeta), plus the SHA-256 of that area. The init reads this
// one text file and never parses the header on the device; it only hashes
// the JSON area and compares. A header that changed since the build
// (luksAddKey, luksChangeKey, luksKillSlot) is a clear message, not a
// wrong-passphrase loop.
//
// Format, one record per line, tab-separated:
//
//	wisp-luks 1
//	header	<sha256 hex of the JSON area>	<uuid>
//	segment	<id>	<encryption>	<sector_size>	<offset>	<size|dynamic>	<iv_tweak>
//	digest	<id>	<hash>	<iterations>	<salt hex>	<digest hex>	<keyslot ids,…>	<segment ids,…>
//	keyslot	<id>	<key_size>	<area encryption>	<area key_size>	<area offset>	<area size>	<af hash>	<af stripes>	<kdf type>	<kdf hash>	<iterations>	<time>	<memory>	<cpus>	<salt hex>
//
// Numbers are unsigned decimals; unused KDF fields are 0. Records are
// sorted by id. A reader refuses any other format number and any
// incomplete record.
package lukstab

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Format is the table format this package writes and reads.
const Format = 1

// Path is where the table lives inside the initramfs.
const Path = "/etc/wisp/luks.tab"

// Keyslot is one luks2 keyslot.
type Keyslot struct {
	ID             string
	KeySize        uint64 // the volume key size this slot holds (bytes)
	AreaEncryption string // e.g. aes-xts-plain64
	AreaKeySize    uint64 // key size of the area cipher (bytes)
	AreaOffset     uint64 // byte offset of the keyslot area
	AreaSize       uint64 // byte size of the keyslot area
	AfHash         string
	AfStripes      uint64
	KdfType        string // pbkdf2 | argon2i | argon2id
	KdfHash        string // pbkdf2 only
	KdfIterations  uint64 // pbkdf2 only
	KdfTime        uint64 // argon2 only
	KdfMemory      uint64 // argon2 only (KiB)
	KdfCpus        uint64 // argon2 only
	Salt           []byte
}

// Digest verifies a volume key: pbkdf2 over the key.
type Digest struct {
	ID         string
	Hash       string
	Iterations uint64
	Salt       []byte
	Digest     []byte
	Keyslots   []string
	Segments   []string
}

// Segment is a crypt segment.
type Segment struct {
	ID         string
	Encryption string
	SectorSize uint64
	Offset     uint64
	Size       string // decimal bytes or "dynamic"
	IvTweak    uint64
}

// Table is the whole file.
type Table struct {
	HeaderSHA256 []byte
	UUID         string
	Keyslots     []Keyslot
	Digests      []Digest
	Segments     []Segment
}

func ids(a, b string) bool {
	x, ex := strconv.Atoi(a)
	y, ey := strconv.Atoi(b)
	if ex == nil && ey == nil {
		return x < y
	}
	return a < b
}

// Marshal writes the table in canonical form.
func (t *Table) Marshal() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "wisp-luks %d\n", Format)
	fmt.Fprintf(&b, "header\t%s\t%s\n", hex.EncodeToString(t.HeaderSHA256), t.UUID)
	segs := append([]Segment(nil), t.Segments...)
	sort.Slice(segs, func(i, j int) bool { return ids(segs[i].ID, segs[j].ID) })
	for _, s := range segs {
		fmt.Fprintf(&b, "segment\t%s\t%s\t%d\t%d\t%s\t%d\n", s.ID, s.Encryption, s.SectorSize, s.Offset, s.Size, s.IvTweak)
	}
	digs := append([]Digest(nil), t.Digests...)
	sort.Slice(digs, func(i, j int) bool { return ids(digs[i].ID, digs[j].ID) })
	for _, d := range digs {
		fmt.Fprintf(&b, "digest\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", d.ID, d.Hash, d.Iterations,
			hex.EncodeToString(d.Salt), hex.EncodeToString(d.Digest), strings.Join(d.Keyslots, ","), strings.Join(d.Segments, ","))
	}
	ks := append([]Keyslot(nil), t.Keyslots...)
	sort.Slice(ks, func(i, j int) bool { return ids(ks[i].ID, ks[j].ID) })
	for _, k := range ks {
		fmt.Fprintf(&b, "keyslot\t%s\t%d\t%s\t%d\t%d\t%d\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
			k.ID, k.KeySize, k.AreaEncryption, k.AreaKeySize, k.AreaOffset, k.AreaSize, k.AfHash, k.AfStripes,
			k.KdfType, k.KdfHash, k.KdfIterations, k.KdfTime, k.KdfMemory, k.KdfCpus, hex.EncodeToString(k.Salt))
	}
	return b.Bytes()
}

// Parse reads a table. The first line must name this format; every record
// must be complete and well-formed; anything else is an error with its line.
func Parse(data []byte) (*Table, error) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("luks table: empty")
	}
	var v int
	if n, _ := fmt.Sscanf(lines[0], "wisp-luks %d", &v); n != 1 {
		return nil, fmt.Errorf("luks table: line 1: not a wisp luks table")
	}
	if v != Format {
		return nil, fmt.Errorf("luks table: format %d, this wisp reads format %d", v, Format)
	}
	t := &Table{}
	for i, line := range lines[1:] {
		ln := i + 2
		f := strings.Split(line, "\t")
		bad := func(what string) (*Table, error) { return nil, fmt.Errorf("luks table: line %d: %s", ln, what) }
		num := func(s string) (uint64, bool) { n, err := strconv.ParseUint(s, 10, 64); return n, err == nil }
		hexb := func(s string) ([]byte, bool) { b, err := hex.DecodeString(s); return b, err == nil }
		list := func(s string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, ",")
		}
		switch f[0] {
		case "header":
			if len(f) != 3 || f[2] == "" {
				return bad("malformed header record")
			}
			h, ok := hexb(f[1])
			if !ok || len(h) != 32 {
				return bad("header hash is not 32 hex bytes")
			}
			t.HeaderSHA256, t.UUID = h, f[2]
		case "segment":
			if len(f) != 7 || f[1] == "" || f[2] == "" {
				return bad("malformed segment record")
			}
			ss, ok1 := num(f[3])
			off, ok2 := num(f[4])
			iv, ok3 := num(f[6])
			if !ok1 || !ok2 || !ok3 {
				return bad("segment numbers")
			}
			if f[5] != "dynamic" {
				if _, ok := num(f[5]); !ok {
					return bad("segment size")
				}
			}
			t.Segments = append(t.Segments, Segment{ID: f[1], Encryption: f[2], SectorSize: ss, Offset: off, Size: f[5], IvTweak: iv})
		case "digest":
			if len(f) != 8 || f[1] == "" || f[2] == "" {
				return bad("malformed digest record")
			}
			it, ok1 := num(f[3])
			salt, ok2 := hexb(f[4])
			dig, ok3 := hexb(f[5])
			if !ok1 || !ok2 || !ok3 {
				return bad("digest fields")
			}
			t.Digests = append(t.Digests, Digest{ID: f[1], Hash: f[2], Iterations: it, Salt: salt, Digest: dig, Keyslots: list(f[6]), Segments: list(f[7])})
		case "keyslot":
			if len(f) != 16 || f[1] == "" || f[3] == "" || f[7] == "" || f[9] == "" {
				return bad("malformed keyslot record")
			}
			var n [9]uint64
			for j, idx := range []int{2, 4, 5, 6, 8, 11, 12, 13, 14} {
				x, ok := num(f[idx])
				if !ok {
					return bad("keyslot numbers")
				}
				n[j] = x
			}
			salt, ok := hexb(f[15])
			if !ok {
				return bad("keyslot salt")
			}
			t.Keyslots = append(t.Keyslots, Keyslot{ID: f[1], KeySize: n[0], AreaEncryption: f[3], AreaKeySize: n[1], AreaOffset: n[2], AreaSize: n[3],
				AfHash: f[7], AfStripes: n[4], KdfType: f[9], KdfHash: f[10], KdfIterations: n[5], KdfTime: n[6], KdfMemory: n[7], KdfCpus: n[8], Salt: salt})
		default:
			return bad("unknown record")
		}
	}
	if t.HeaderSHA256 == nil {
		return nil, fmt.Errorf("luks table: no header record")
	}
	return t, nil
}

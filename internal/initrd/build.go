// SPDX-License-Identifier: GPL-2.0-only

package initrd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"wisp/internal/kmod"
)

// Result is a built initrd.
type Result struct {
	Cpio       []byte      // the uncompressed archive
	Resolution *Resolution // which modules went in
}

// SHA256 of the uncompressed archive, hex.
func (r *Result) SHA256() string {
	s := sha256.Sum256(r.Cpio)
	return hex.EncodeToString(s[:])
}

// Build assembles the initrd described by m. modulesRoot holds
// <kernel>/ (normally /lib/modules), or is that directory itself.
//
// The archive contains: the empty directories proc, sys, dev, etc, run; the
// resolved modules copied verbatim under lib/modules/<kernel>/ (never
// stripped or recompressed, that would break bit-reproducibility against the
// package); a pruned modules.order listing exactly the emitted set in load
// order; and the declared [files]. The [cmdline] is not placed in the
// archive: the kernel receives it from the boot entry and the initrd reads
// /proc/cmdline.
func Build(m *Manifest, modulesRoot string) (*Result, error) {
	moddir := modulesRoot
	if filepath.Base(filepath.Clean(moddir)) != m.Kernel {
		moddir = filepath.Join(moddir, m.Kernel)
	}
	if fi, err := os.Stat(moddir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("build: no module tree at %s", moddir)
	}
	tree := kmod.Load(moddir)
	res, err := Resolve(m.Modules, tree)
	if err != nil {
		return nil, err
	}
	if len(res.Missing) > 0 {
		return nil, fmt.Errorf("build: modules neither present nor builtin: %s", strings.Join(res.Missing, ", "))
	}

	t := NewTree()
	modBase := "lib/modules/" + m.Kernel
	for _, d := range []string{"proc", "sys", "dev", "etc", "run", modBase} {
		t.AddDir(d)
	}
	for _, rp := range res.Order {
		data, err := os.ReadFile(filepath.Join(moddir, filepath.FromSlash(rp)))
		if err != nil {
			return nil, err
		}
		if err := t.AddFile(modBase+"/"+rp, data, false); err != nil {
			return nil, err
		}
	}
	var order bytes.Buffer
	for _, rp := range res.Order {
		order.WriteString(rp + "\n")
	}
	if err := t.AddFile(modBase+"/modules.order", order.Bytes(), false); err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		if f.Link != "" {
			if err := t.AddSymlink(f.Archive, f.Link); err != nil {
				return nil, fmt.Errorf("build: [files] %s: %w", f.Archive, err)
			}
			continue
		}
		src := f.Source
		if !filepath.IsAbs(src) {
			src = filepath.Join(m.Dir, src)
		}
		fi, err := os.Stat(src)
		if err != nil {
			return nil, fmt.Errorf("build: [files] %s: %w", f.Archive, err)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("build: [files] %s: %w", f.Archive, err)
		}
		if err := t.AddFile(f.Archive, data, fi.Mode()&0o111 != 0); err != nil {
			return nil, fmt.Errorf("build: [files] %s: %w", f.Archive, err)
		}
	}
	return &Result{Cpio: WriteCpio(t.Entries(), m.SourceEpoch), Resolution: res}, nil
}

// CompressZstd compresses an archive deterministically: best level, one
// thread, no content checksum. The output depends only on the input bytes and
// the vendored zstd implementation, never on the machine.
func CompressZstd(b []byte) ([]byte, error) {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(false),
		zstd.WithZeroFrames(true),
	)
	if err != nil {
		return nil, err
	}
	out := enc.EncodeAll(b, make([]byte, 0, len(b)/3))
	enc.Close()
	return out, nil
}

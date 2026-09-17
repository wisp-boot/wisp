// SPDX-License-Identifier: GPL-2.0-only

package initrd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FormatVersion is the manifest format this wisp reads and writes. The format
// is a contract with every verifier that reproduces archives: a change in what
// a manifest means gets a new number, and a reader refuses what it does not know
// instead of building a different archive from it.
const FormatVersion = 1

// Manifest is the declarative description of an initrd. It names inputs
// instead of scanning a machine:
//
//	format        = 1                    first line (comments aside); any other number is refused
//	kernel        = 6.8.0-45-generic     the module tree /lib/modules/<kernel>
//	source_epoch  = 0                    the mtime stamped on every entry
//	firmware      = modules              copy the firmware files the selected modules name
//	                                     (from /lib/firmware, symlinks kept); absent: no firmware
//	microcode     = all                  prepend an uncompressed cpio with the CPU microcode
//	                                     (/lib/firmware/{amd,intel}-ucode concatenated); absent: none
//
//	[modules]                            module names and/or directory selectors
//	nvme                                   a name (dependencies are resolved)
//	+dir:kernel/drivers/usb                every module under the subtree
//	-dir:kernel/drivers/usb/gadget         remove a subtree again (wins over +dir)
//
//	[cmdline]                            the boot entry's command line, declared
//	root=/dev/mapper/root                 here for a verifier; NOT placed in the initrd
//
//	[files]                              archive path = source path
//	/init = /usr/lib/wisp/wisp-init        copied, executable bit preserved
//	/lib64 = link:usr/lib64                a symlink entry
//
// Comments are full-line '#' only, so a cmdline may contain anything. An unknown
// key, an unknown section and a top-level line without '=' are errors: what
// this reader does not understand, it does not skip.
type Manifest struct {
	Kernel      string
	SourceEpoch int64
	Firmware    string // "" (none) or "modules"
	Microcode   string // "" (none) or "all"
	Modules     []string
	Cmdline     []string
	Files       []FileSpec
	Dir         string // directory the manifest was read from; relative sources resolve against it
}

// FileSpec is one [files] line. Either Source (a path) or Link (a symlink target) is set.
type FileSpec struct {
	Archive string
	Source  string
	Link    string
}

// ParseManifest reads a manifest file.
func ParseManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := ParseManifestReader(bufio.NewScanner(f))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, _ := filepath.Abs(path)
	m.Dir = filepath.Dir(abs)
	return m, nil
}

// ParseManifestString parses manifest text; relative sources resolve against dir.
func ParseManifestString(text, dir string) (*Manifest, error) {
	m, err := ParseManifestReader(bufio.NewScanner(strings.NewReader(text)))
	if err != nil {
		return nil, err
	}
	m.Dir = dir
	return m, nil
}

// ParseManifestReader parses lines from a scanner.
func ParseManifestReader(sc *bufio.Scanner) (*Manifest, error) {
	m := &Manifest{}
	section := ""
	first := true
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		// The format line comes before anything is interpreted, so a manifest
		// of another format fails on its number and not on a detail.
		if first {
			first = false
			k, v, ok := strings.Cut(s, "=")
			if !ok || strings.TrimSpace(k) != "format" {
				return nil, fmt.Errorf("line %d: a manifest starts with `format = %d`", line, FormatVersion)
			}
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("line %d: format %q: %w", line, strings.TrimSpace(v), err)
			}
			if n != FormatVersion {
				return nil, fmt.Errorf("line %d: manifest format %d, this wisp reads format %d", line, n, FormatVersion)
			}
			continue
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			section = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		switch section {
		case "":
			k, v, ok := strings.Cut(s, "=")
			if !ok {
				return nil, fmt.Errorf("line %d: line without '=': %q", line, s)
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "format":
				return nil, fmt.Errorf("line %d: `format` is the first line and appears once", line)
			case "kernel":
				m.Kernel = strings.ReplaceAll(v, " ", "")
			case "source_epoch":
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("source_epoch %q: %w", v, err)
				}
				m.SourceEpoch = n
			case "firmware":
				if v != "modules" && v != "none" && v != "" {
					return nil, fmt.Errorf("firmware = %q: expected modules or none", v)
				}
				if v == "none" {
					v = ""
				}
				m.Firmware = v
			case "microcode":
				if v != "all" && v != "none" && v != "" {
					return nil, fmt.Errorf("microcode = %q: expected all or none", v)
				}
				if v == "none" {
					v = ""
				}
				m.Microcode = v
			default:
				return nil, fmt.Errorf("line %d: unknown key %q", line, k)
			}
		case "modules":
			m.Modules = append(m.Modules, s)
		case "cmdline":
			m.Cmdline = append(m.Cmdline, s)
		case "files":
			k, v, ok := strings.Cut(s, "=")
			if !ok {
				return nil, fmt.Errorf("[files] line without '=': %q", s)
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if target, ok := strings.CutPrefix(v, "link:"); ok {
				m.Files = append(m.Files, FileSpec{Archive: k, Link: target})
			} else {
				m.Files = append(m.Files, FileSpec{Archive: k, Source: v})
			}
		default:
			return nil, fmt.Errorf("unknown section [%s]", section)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if first {
		return nil, fmt.Errorf("a manifest starts with `format = %d`", FormatVersion)
	}
	if m.Kernel == "" {
		return nil, fmt.Errorf("no `kernel = <version>`")
	}
	return m, nil
}

// CmdlineString returns the declared command line as one line (first
// non-empty [cmdline] line), or "".
func (m *Manifest) CmdlineString() string {
	for _, l := range m.Cmdline {
		if strings.TrimSpace(l) != "" {
			return l
		}
	}
	return ""
}

// String renders the manifest back in its file format.
func (m *Manifest) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "format        = %d\n", FormatVersion)
	fmt.Fprintf(&b, "kernel        = %s\nsource_epoch  = %d\n", m.Kernel, m.SourceEpoch)
	if m.Firmware != "" {
		fmt.Fprintf(&b, "firmware      = %s\n", m.Firmware)
	}
	if m.Microcode != "" {
		fmt.Fprintf(&b, "microcode     = %s\n", m.Microcode)
	}
	if len(m.Modules) > 0 {
		b.WriteString("\n[modules]\n")
		for _, x := range m.Modules {
			b.WriteString(x + "\n")
		}
	}
	if len(m.Cmdline) > 0 {
		b.WriteString("\n[cmdline]\n")
		for _, x := range m.Cmdline {
			b.WriteString(x + "\n")
		}
	}
	if len(m.Files) > 0 {
		b.WriteString("\n[files]\n")
		for _, f := range m.Files {
			if f.Link != "" {
				fmt.Fprintf(&b, "%s = link:%s\n", f.Archive, f.Link)
			} else {
				fmt.Fprintf(&b, "%s = %s\n", f.Archive, f.Source)
			}
		}
	}
	return b.String()
}

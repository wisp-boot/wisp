// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// versionLess orders like GNU `sort -V`: digit runs numerically, the rest bytewise.
func versionLess(a, b string) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		ad, bd := a[i] >= '0' && a[i] <= '9', b[j] >= '0' && b[j] <= '9'
		if ad && bd {
			si, sj := i, j
			for i < len(a) && a[i] >= '0' && a[i] <= '9' {
				i++
			}
			for j < len(b) && b[j] >= '0' && b[j] <= '9' {
				j++
			}
			na, nb := strings.TrimLeft(a[si:i], "0"), strings.TrimLeft(b[sj:j], "0")
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			if na != nb {
				return na < nb
			}
		} else {
			if a[i] != b[j] {
				return a[i] < b[j]
			}
			i++
			j++
		}
	}
	return len(a)-i < len(b)-j
}

// installedKernels lists the versions with a vmlinuz in bootDir, newest last.
func installedKernels(bootDir string) []string {
	ks, _ := filepath.Glob(filepath.Join(bootDir, "vmlinuz-*"))
	var out []string
	for _, k := range ks {
		v := strings.TrimPrefix(filepath.Base(k), "vmlinuz-")
		if fi, err := os.Stat(filepath.Join("/lib/modules", v)); err == nil && fi.IsDir() {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return versionLess(out[i], out[j]) })
	return out
}

func runningKernel() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

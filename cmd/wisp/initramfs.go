// SPDX-License-Identifier: GPL-2.0-only

package main

// The initramfs-tools compatible surface: the update-initramfs facade that
// other packages call, and the kernel maintainer hooks.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func updateInitramfs(args []string) int {
	mode, kver, bootDir := "", "", "/boot"
	verbose := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch a {
		case "-c", "-u", "-d":
			mode = a
		case "-k":
			kver = next()
		case "-b":
			bootDir = next()
		case "-v":
			verbose = true
		case "-t":
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: update-initramfs -c|-u|-d [-k <version>|all] [-b <bootdir>] [-v]")
			return 0
		default:
			if strings.HasPrefix(a, "-k") && len(a) > 2 {
				kver = a[2:]
				continue
			}
			return die("update-initramfs: unknown option %s", a)
		}
	}
	if mode == "" {
		return die("update-initramfs: one of -c, -u or -d is required")
	}
	var versions []string
	switch kver {
	case "all":
		versions = installedKernels(bootDir)
	case "":
		ks := installedKernels(bootDir)
		if len(ks) == 0 {
			return die("update-initramfs: no kernel found in %s", bootDir)
		}
		versions = ks[len(ks)-1:]
	default:
		versions = []string{kver}
	}
	rc := 0
	for _, v := range versions {
		out := filepath.Join(bootDir, "initrd.img-"+v)
		if mode == "-d" {
			if err := os.Remove(out); err != nil && !os.IsNotExist(err) {
				rc = die("update-initramfs: %v", err)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "removed %s\n", out)
			}
			// the copy the package kept at its first installation goes with its kernel
			os.Remove(out + ".pre-wisp")
			continue
		}
		bargs := []string{"-k", v, "-o", out}
		if verbose {
			bargs = append(bargs, "-v")
		}
		if r := cmdBuild(bargs); r != 0 {
			rc = r
		}
	}
	return rc
}

// kernelHook mirrors the initramfs-tools hook contract: $1 is the version,
// $2 optionally the kernel image path (its directory receives the initrd);
// INITRD=No means the kernel needs none; DEB_MAINT_PARAMS filters the
// maintainer script phase.
func kernelHook(phase string, args []string) int {
	if len(args) == 0 || args[0] == "" {
		fmt.Fprintln(os.Stderr, "wisp: kernel hook called without a version")
		return 2
	}
	version := args[0]
	if os.Getenv("INITRD") == "No" {
		return 0
	}
	if p := os.Getenv("DEB_MAINT_PARAMS"); p != "" {
		want := "configure"
		if phase == "postrm" {
			want = "remove"
		}
		if !strings.HasPrefix(strings.Trim(strings.Fields(p)[0], "'\""), want) {
			return 0
		}
	}
	bootDir := "/boot"
	if len(args) > 1 && args[1] != "" {
		bootDir = filepath.Dir(args[1])
	}
	if phase == "postrm" {
		return updateInitramfs([]string{"-d", "-k", version, "-b", bootDir})
	}
	return updateInitramfs([]string{"-c", "-k", version, "-b", bootDir})
}

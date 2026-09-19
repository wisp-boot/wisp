// SPDX-License-Identifier: GPL-2.0-only

// wisp is the host-side tool: it builds the initramfs for a kernel from the
// declared configuration under /etc/wisp, and it stands in for
// update-initramfs and the kernel maintainer hooks so that the rest of the
// system keeps calling what it always called.
//
// The same binary is reached under several names (symlinks):
//
//	wisp                      the verbs below
//	update-initramfs          the initramfs-tools compatible facade (-c/-u/-d -k <version>)
//	/etc/kernel/postinst.d/wisp, /etc/kernel/postrm.d/wisp   the kernel hooks
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func usage() {
	fmt.Fprint(os.Stderr, `wisp <verb> [options]

  build      [-k <version>] [-o <file>] [--compress none|zstd] [--manifest <file>] [--stage <dir>]
             build the initramfs for a kernel (default: the running one) into /boot/initrd.img-<version>
  manifest   [-k <version>] [--stage <dir>]
             print the manifest build would use; with --stage also write the generated files there
  resolve    [-k <version>] <module|+dir:...|-dir:...>...
             show the module resolution against /lib/modules/<version>
  luks-tab   <device|header file>
             print the LUKS table build places at /etc/wisp/luks.tab for this container
  update-initramfs  -c|-u|-d [-k <version>|all] [-b <dir>] [-v]
             initramfs-tools compatible facade (also reachable as update-initramfs)
  version
  help
`)
}

func main() {
	self := filepath.Base(os.Args[0])
	dir := filepath.Dir(os.Args[0])
	switch {
	case self == "update-initramfs":
		os.Exit(updateInitramfs(os.Args[1:]))
	case strings.HasSuffix(dir, "/kernel/postinst.d"):
		os.Exit(kernelHook("postinst", os.Args[1:]))
	case strings.HasSuffix(dir, "/kernel/postrm.d"):
		os.Exit(kernelHook("postrm", os.Args[1:]))
	}
	verb := "help"
	if len(os.Args) > 1 {
		verb = os.Args[1]
	}
	args := os.Args[min(2, len(os.Args)):]
	switch verb {
	case "build":
		os.Exit(cmdBuild(args))
	case "manifest":
		os.Exit(cmdManifest(args))
	case "resolve":
		os.Exit(cmdResolve(args))
	case "luks-tab":
		os.Exit(cmdLuksTab(args))
	case "update-initramfs":
		os.Exit(updateInitramfs(args))
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "wisp: unknown verb %q\n", verb)
		usage()
		os.Exit(1)
	}
}

func die(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "wisp: "+format+"\n", a...)
	return 1
}

// SPDX-License-Identifier: GPL-2.0-only

package main

// The measured runtime configuration: /etc/wisp/wisp.conf inside the
// initramfs. It is part of the initrd bytes and therefore of whatever
// measures the initrd, so a boot mode cannot be downgraded from outside.
//
//	key         = none | passphrase | credential | <provider>   how the volume key is obtained
//	luks.uuid   = <uuid>            the LUKS2 container (the builder takes it from /etc/crypttab)
//	luks.name   = <name>            device-mapper name of the opened container (default root)
//	luks.header = <path>            optional detached header copy inside the initrd
//	root        = <device|UUID=x>   the root file system (else from the kernel command line)
//	rootfstype  = <type>            optional; else probed from the superblock
//
// Lines are key=value, '#' starts a comment, whitespace is trimmed, unknown keys
// are ignored (an unknown key never stops a boot). The kernel command line is
// consulted only for values the file does not set: root=, rootfstype=,
// rd.luks.uuid=, rd.luks.name=.

import (
	"os"
	"strings"
)

const (
	keyNone       = "none"
	keyPassphrase = "passphrase"
	keyCredential = "credential"

	configPath = "/etc/wisp/wisp.conf"
)

type config struct {
	key        string
	luksUUID   string
	luksName   string
	luksHeader string
	rootUUID   string // root=UUID=...
	rootPath   string // root=/dev/...
	rootfstype string
}

func parseConfig(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// configFrom merges the file values with the kernel command line.
func configFrom(file map[string]string, cmdline string) config {
	c := config{key: keyPassphrase, luksName: "root"}
	cl := map[string]string{}
	for _, tok := range strings.Fields(cmdline) {
		k, v, _ := strings.Cut(tok, "=")
		cl[k] = v
	}
	pick := func(fileKey, clKey string) string {
		if v := file[fileKey]; v != "" {
			return v
		}
		return cl[clKey]
	}
	if v := file["key"]; v != "" {
		c.key = v
	}
	c.luksUUID = strings.ToLower(pick("luks.uuid", "rd.luks.uuid"))
	if v := pick("luks.name", "rd.luks.name"); v != "" {
		c.luksName = v
	}
	c.luksHeader = file["luks.header"]
	root := pick("root", "root")
	if u, ok := strings.CutPrefix(root, "UUID="); ok {
		c.rootUUID = strings.ToLower(u)
	} else {
		c.rootPath = root
	}
	c.rootfstype = pick("rootfstype", "rootfstype")
	return c
}

func loadConfig(con *Console) config {
	file := map[string]string{}
	if b, err := os.ReadFile(configPath); err == nil {
		file = parseConfig(string(b))
	} else {
		con.Say("wisp-init: %s missing, using defaults (key=passphrase) and the kernel command line", configPath)
	}
	cl, _ := os.ReadFile("/proc/cmdline")
	return configFrom(file, string(cl))
}

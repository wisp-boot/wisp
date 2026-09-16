// SPDX-License-Identifier: GPL-2.0-only

package main

// The console keyboard layout for the passphrase and provider prompts.
//
// wisp.conf `keymap`:
//
//	system (default)      the layout in /etc/default/keyboard (XKBLAYOUT, XKBVARIANT;
//	                      the first of a comma-separated list); no file: no keymap
//	none                  no keymap, the kernel's built-in US table
//	<layout>[:<variant>]  an explicit XKB layout
//
// The package ships every XKB layout and variant precompiled under
// /usr/share/wisp/keymaps (tools/mkkeymaps.sh, run at package build with
// pinned xkb-data, console-setup and kbd). The builder copies one of them to
// /etc/wisp/keymap.bin in the initramfs, so the bytes there are a function of
// the wisp version and the layout name alone: nothing is generated on the
// machine, and a verifier finds the same file in the wisp package. XKB options
// and models are not applied.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultKeyboard = "/etc/default/keyboard"

var keymapsDir = "/usr/share/wisp/keymaps"

type keyboardConf struct {
	model, layout, variant, options string
}

// parseDefaultKeyboard reads the shell-style KEY="value" lines of
// /etc/default/keyboard.
func parseDefaultKeyboard(s string) keyboardConf {
	var kc keyboardConf
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		switch strings.TrimSpace(k) {
		case "XKBMODEL":
			kc.model = v
		case "XKBLAYOUT":
			kc.layout = v
		case "XKBVARIANT":
			kc.variant = v
		case "XKBOPTIONS":
			kc.options = v
		}
	}
	return kc
}

// first returns the first entry of a comma-separated XKB list.
func first(s string) string {
	s, _, _ = strings.Cut(s, ",")
	return strings.TrimSpace(s)
}

// keymapFile maps a layout[:variant] to its file in the package.
func keymapFile(layout, variant string) string {
	name := layout
	if variant != "" {
		name += "+" + variant
	}
	return filepath.Join(keymapsDir, name+".bkmap")
}

// resolveKeymap turns the wisp.conf setting into the value to record and the
// package file to place at /etc/wisp/keymap.bin; both empty when there is no
// keymap.
func resolveKeymap(setting string) (record, file string, err error) {
	var layout, variant string
	switch setting {
	case "none":
		return "", "", nil
	case "", "system":
		b, err := os.ReadFile(defaultKeyboard)
		if err != nil {
			return "", "", nil // no configured layout: the US table
		}
		kc := parseDefaultKeyboard(string(b))
		layout, variant = first(kc.layout), first(kc.variant)
		if layout == "" {
			return "", "", nil
		}
	default:
		layout, variant, _ = strings.Cut(setting, ":")
	}
	if strings.ContainsAny(layout+variant, "/ \t") {
		return "", "", fmt.Errorf("keymap: bad layout name %q", setting)
	}
	record = layout
	if variant != "" {
		record += ":" + variant
	}
	file = keymapFile(layout, variant)
	if _, err := os.Stat(file); err != nil {
		return "", "", fmt.Errorf("keymap %s: no precompiled layout %s (keymap = none builds without a layout)", record, file)
	}
	return record, file, nil
}

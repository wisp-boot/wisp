// SPDX-License-Identifier: GPL-2.0-only

package main

// The console keyboard layout for the passphrase and provider prompts.
//
// wisp.conf `keymap`:
//
//	system (default)   the layout configured in /etc/default/keyboard (XKBMODEL,
//	                   XKBLAYOUT, XKBVARIANT, XKBOPTIONS); no file there: no keymap
//	none               no keymap, the kernel's built-in US table
//	<layout>[:<variant>]  an explicit XKB layout, model pc105
//
// The layout is compiled by ckbcomp (console-setup) into a console keymap and
// by `loadkeys -b -u` (kbd) into the binary table wisp-init loads with ioctls;
// the result is a pure function of the two packages' versions and the layout,
// so a rebuild gives the same bytes. Like lvm.tab it is data about this
// machine, staged as keymap.bin and placed at /etc/wisp/keymap.bin.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const defaultKeyboard = "/etc/default/keyboard"

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

// stageKeymap resolves the keymap setting and, when a layout results, writes
// <stage>/keymap.bin. It returns the value to record in wisp.conf and the
// staged file, both empty when there is no keymap.
func stageKeymap(setting, stage string) (record, file string, err error) {
	var kc keyboardConf
	switch setting {
	case "none":
		return "", "", nil
	case "", "system":
		b, err := os.ReadFile(defaultKeyboard)
		if err != nil {
			return "", "", nil // no configured layout: the US table
		}
		kc = parseDefaultKeyboard(string(b))
		if kc.layout == "" {
			return "", "", nil
		}
		record = kc.layout
		if kc.variant != "" {
			record += ":" + kc.variant
		}
	default:
		record = setting
		kc.layout, kc.variant, _ = strings.Cut(setting, ":")
		kc.model = "pc105"
	}
	for _, bin := range []string{"ckbcomp", "loadkeys"} {
		if _, err := exec.LookPath(bin); err != nil {
			return "", "", fmt.Errorf("keymap %s: %s is not installed (console-setup and kbd are needed; keymap = none builds without a layout)", record, bin)
		}
	}
	var args []string // UTF-8 is ckbcomp's default; -charmap is for legacy encodings only
	if kc.model != "" {
		args = append(args, "-model", kc.model)
	}
	args = append(args, "-layout", kc.layout)
	if kc.variant != "" {
		args = append(args, "-variant", kc.variant)
	}
	if kc.options != "" {
		args = append(args, "-option", kc.options)
	}
	var stderr bytes.Buffer
	cmd := exec.Command("ckbcomp", args...)
	cmd.Stderr = &stderr // warnings about unknown keysyms are normal; shown only on failure
	txt, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("keymap %s: ckbcomp: %v\n%s", record, err, stderr.String())
	}
	kmap := filepath.Join(stage, "keymap.kmap")
	if err := os.WriteFile(kmap, txt, 0o644); err != nil {
		return "", "", err
	}
	stderr.Reset()
	cmd = exec.Command("loadkeys", "-b", "-u", kmap)
	cmd.Stderr = &stderr
	bin, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("keymap %s: loadkeys -b: %v\n%s", record, err, stderr.String())
	}
	if !bytes.HasPrefix(bin, []byte("bkeymap")) {
		return "", "", fmt.Errorf("keymap %s: loadkeys -b did not produce a bkeymap", record)
	}
	file = filepath.Join(stage, "keymap.bin")
	if err := os.WriteFile(file, bin, 0o644); err != nil {
		return "", "", err
	}
	return record, file, nil
}

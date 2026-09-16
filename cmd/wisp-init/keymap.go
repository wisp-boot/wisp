// SPDX-License-Identifier: GPL-2.0-only

package main

// Console keyboard layout. The builder places /etc/wisp/keymap.bin in the
// initramfs: the binary keymap that `loadkeys -b -u` writes for the system's
// layout (the format busybox loadkmap reads). Applying it needs no keymap
// parser, the file is the kernel's own table encoding, entry by entry:
//
//	"bkeymap"                  7 bytes magic
//	flags[256]                 one byte per table (shift state), 1 = present
//	for each present table     128 keycodes × uint16, little-endian
//
// The values are what KDSKBENT takes: K(type, value) for keysyms, ucs ^ 0xf000
// for Unicode characters. The kernel accepts the latter only while the keyboard
// is in Unicode mode, so K_UNICODE is set first. Without the file, or on a
// console that is not a virtual terminal, the layout stays the kernel's
// built-in US table and the init says so.

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	keymapPath   = "/etc/wisp/keymap.bin"
	bkeymapMagic = "bkeymap"
	maxNrKeymaps = 256
	nrKeys       = 128

	kdSKBMode = 0x4B45 // KDSKBMODE: set the keyboard translation mode
	kdSKBEnt  = 0x4B47 // KDSKBENT: set one keymap entry
	kUnicode  = 0x03   // K_UNICODE
)

// kbEntry is struct kbentry: table (shift state), index (keycode), value.
type kbEntry struct {
	table uint8
	index uint8
	value uint16
}

// parseBkeymap returns the entries of a bkeymap in file order and the number
// of tables present.
func parseBkeymap(b []byte) ([]kbEntry, int, error) {
	if len(b) < len(bkeymapMagic)+maxNrKeymaps || string(b[:len(bkeymapMagic)]) != bkeymapMagic {
		return nil, 0, fmt.Errorf("not a bkeymap file")
	}
	flags := b[len(bkeymapMagic) : len(bkeymapMagic)+maxNrKeymaps]
	rest := b[len(bkeymapMagic)+maxNrKeymaps:]
	var out []kbEntry
	tables := 0
	for t := 0; t < maxNrKeymaps; t++ {
		if flags[t] == 0 {
			continue
		}
		if len(rest) < nrKeys*2 {
			return nil, 0, fmt.Errorf("bkeymap truncated in table %d", t)
		}
		for k := 0; k < nrKeys; k++ {
			out = append(out, kbEntry{table: uint8(t), index: uint8(k), value: binary.LittleEndian.Uint16(rest[2*k:])})
		}
		rest = rest[nrKeys*2:]
		tables++
	}
	if len(rest) != 0 {
		return nil, 0, fmt.Errorf("bkeymap has %d trailing bytes", len(rest))
	}
	return out, tables, nil
}

// applyKeymap loads /etc/wisp/keymap.bin into the console, if present.
func applyKeymap(con *Console) {
	b, err := os.ReadFile(keymapPath)
	if err != nil {
		return // no keymap in this initramfs: the kernel's US table
	}
	entries, tables, err := parseBkeymap(b)
	if err != nil {
		con.Say("wisp-init: keymap: %v; keeping the US layout", err)
		return
	}
	fd := int(con.f.Fd())
	if err := unix.IoctlSetInt(fd, kdSKBMode, kUnicode); err != nil {
		con.Say("wisp-init: keymap: console is not a virtual terminal (%v); keeping the US layout", err)
		return
	}
	failed := 0
	for i := range entries {
		e := entries[i]
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), kdSKBEnt, uintptr(unsafe.Pointer(&e))); errno != 0 {
			failed++
		}
	}
	if failed > 0 {
		con.Say("wisp-init: keymap: %d tables, %d entries rejected by the kernel", tables, failed)
		return
	}
	con.Say("wisp-init: keymap: %d tables loaded", tables)
}

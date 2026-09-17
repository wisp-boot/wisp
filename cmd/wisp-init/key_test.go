// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadKey(t *testing.T) {
	key32 := bytes.Repeat([]byte{0xA5}, 32)
	got, err := readKey(bytes.NewReader(key32))
	if err != nil || !bytes.Equal(got, key32) {
		t.Fatalf("%x %v", got, err)
	}
	// the key lives in one buffer of fixed size: clearing the slice the caller
	// holds must leave nothing of it behind in that buffer
	if cap(got) != maxKeyLen+1 {
		t.Fatalf("cap %d, want the fixed buffer of %d", cap(got), maxKeyLen+1)
	}
	clear(got)
	if !bytes.Equal(got[:cap(got)], make([]byte, maxKeyLen+1)) {
		t.Fatal("key bytes left in the buffer after clear")
	}

	// a provider that writes byte by byte
	got, err = readKey(iotest.OneByteReader(bytes.NewReader(key32)))
	if err != nil || !bytes.Equal(got, key32) {
		t.Fatalf("one byte at a time: %x %v", got, err)
	}
	// nothing written: empty, and the caller halts on len 0
	if got, err = readKey(bytes.NewReader(nil)); err != nil || len(got) != 0 {
		t.Fatalf("empty: %d %v", len(got), err)
	}
	// exactly the limit is a key, one more is recognisably too long
	if got, _ = readKey(bytes.NewReader(make([]byte, maxKeyLen))); len(got) != maxKeyLen {
		t.Fatalf("at the limit: %d", len(got))
	}
	if got, _ = readKey(bytes.NewReader(make([]byte, maxKeyLen+100))); len(got) != maxKeyLen+1 {
		t.Fatalf("over the limit: %d, want %d so that the caller rejects it", len(got), maxKeyLen+1)
	}
	// a read error yields no key
	boom := errors.New("boom")
	if got, err = readKey(io.MultiReader(bytes.NewReader(key32), iotest.ErrReader(boom))); !errors.Is(err, boom) || got != nil {
		t.Fatalf("read error: %v %v", got, err)
	}
}

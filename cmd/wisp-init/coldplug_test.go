// SPDX-License-Identifier: GPL-2.0-only

package main

// Hermetic tests of the fnmatch matcher: literals, * ?, character classes
// with ranges and negation, backslash escapes, and real modalias/alias pairs.

import "testing"

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, str string
		want     bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"", "", true},
		{"", "x", false},
		{"a", "", false},

		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"???", "abc", true},
		{"???", "ab", false},

		{"*", "", true},
		{"*", "anything", true},
		{"a*", "a", true},
		{"a*", "abcdef", true},
		{"a*f", "abcdef", true},
		{"a*f", "abcde", false},
		{"*.ko", "nvme.ko", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},

		{"[abc]", "b", true},
		{"[abc]", "d", false},
		{"[a-z]", "m", true},
		{"[a-z]", "M", false},
		{"[0-9]*", "1abc", true},
		{"[0-9]*", "abc", false},
		{"[!abc]", "d", true},
		{"[!abc]", "a", false},
		{"[^0-9]", "x", true},
		{"[^0-9]", "5", false},
		{"[abc", "[abc", true},
		{"[abc", "a", false},

		{`a\*b`, "a*b", true},
		{`a\*b`, "axb", false},
		{`\?`, "?", true},

		{"pci:v000010DEd*sv*sd*bc03sc*i*", "pci:v000010DEd00001C82sv00001458sd00003763bc03sc00i00", true},
		{"pci:v00008086d*sv*sd*bc*sc*i*", "pci:v000010DEd00001C82sv00001458sd00003763bc03sc00i00", false},
		{"usb:v*p*d*dc*dsc*dp*ic03isc*ip*in*", "usb:v046Dp0825d0011dc00dsc00dp00ic03isc00ip00in00", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.str); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pat, c.str, got, c.want)
		}
	}
}

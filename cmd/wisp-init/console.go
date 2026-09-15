// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Console is /dev/console: messages, prompts, and secrets without echo.
type Console struct {
	f *os.File
	r *bufio.Reader
}

func openConsole() *Console {
	path := "/dev/console"
	if os.Getpid() != 1 {
		path = "/dev/tty"
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wisp-init: console:", err)
		os.Exit(1)
	}
	return &Console{f: f, r: bufio.NewReader(f)}
}

func (c *Console) Close() { c.f.Close() }

func (c *Console) Say(format string, a ...any) { fmt.Fprintf(c.f, format+"\n", a...) }

func (c *Console) Line(prompt string) string {
	fmt.Fprint(c.f, prompt)
	s, _ := c.r.ReadString('\n')
	return strings.TrimRight(s, "\r\n")
}

// Secret reads a line without echo (falls back to a plain line if the
// console is not a terminal).
func (c *Console) Secret(prompt string) string {
	fmt.Fprint(c.f, prompt)
	b, err := term.ReadPassword(int(c.f.Fd()))
	fmt.Fprintln(c.f)
	if err != nil {
		return c.Line("")
	}
	return string(b)
}

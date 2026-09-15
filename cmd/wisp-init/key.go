// SPDX-License-Identifier: GPL-2.0-only

package main

// Step 4: obtaining the volume key. Three sources are built in and one is a
// process boundary:
//
//	none        no LUKS at all; the root file system is mounted directly
//	passphrase  asked on the console, three attempts, then halt
//	credential  read from /.extra/credentials/cryptsetup.passphrase, the file a
//	            pre-kernel stage may append to the initramfs as an extra cpio
//	            (the systemd-stub credential convention). The file is unlinked
//	            after reading. If it is missing, the passphrase prompt is the
//	            recovery path.
//	<name>      a key provider: the executable /usr/lib/wisp/key/<name>, with its
//	            configuration under /etc/wisp/key/<name>/, both placed in the
//	            initramfs by the builder. Protocol version 1:
//	              argv     <name> --protocol 1 --device <luks device> --name <dm name>
//	              fd 0,1,2 the console (the provider runs its own dialogue)
//	              fd 3     write end of a pipe: the raw key bytes, then exit 0
//	              exit     0 success; 10 wrong secret; 11 state or policy mismatch;
//	                       12 hardware missing; 13 aborted by the user; else failure
//	            The provider process owns everything sensitive it computes; it
//	            ends before LUKS is opened. wisp does not retry a provider.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"wisp/internal/luks"
)

const (
	credentialPath = "/.extra/credentials/cryptsetup.passphrase"
	providerDir    = "/usr/lib/wisp/key/"
	providerProto  = "1"
	maxKeyLen      = 512
)

var providerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// obtainKey returns the secret that opens the container. For key=passphrase
// it returns nil: the passphrase dialogue happens in openLUKS, because a
// wrong passphrase must be retried against the keyslots, not against a
// provider.
func obtainKey(con *Console, c config, luksDev string) []byte {
	switch c.key {
	case keyPassphrase:
		return nil
	case keyCredential:
		b, err := os.ReadFile(credentialPath)
		if err != nil {
			con.Say("wisp-init: no credential at %s, falling back to the passphrase prompt (recovery)", credentialPath)
			return nil
		}
		os.Remove(credentialPath)
		if len(b) == 0 {
			halt(con, "credential file is empty")
		}
		con.Say("wisp-init: key from credential (%d bytes)", len(b))
		return b
	}
	if !providerName.MatchString(c.key) {
		halt(con, "wisp.conf: key=%q is not a valid provider name", c.key)
	}
	return runProvider(con, c, luksDev)
}

func runProvider(con *Console, c config, luksDev string) []byte {
	path := providerDir + c.key
	if _, err := os.Stat(path); err != nil {
		halt(con, "key provider %s is not in this initramfs (rebuild with the provider package installed)", path)
	}
	r, w, err := os.Pipe()
	if err != nil {
		halt(con, "pipe: %v", err)
	}
	cmd := exec.Command(path, "--protocol", providerProto, "--device", luksDev, "--name", c.luksName)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = con.f, con.f, con.f
	cmd.ExtraFiles = []*os.File{w} // fd 3
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "WISP_PROTOCOL=" + providerProto,
		"WISP_LUKS_DEVICE=" + luksDev, "WISP_LUKS_NAME=" + c.luksName}
	if err := cmd.Start(); err != nil {
		halt(con, "key provider %s: %v", c.key, err)
	}
	w.Close()
	key, readErr := io.ReadAll(io.LimitReader(r, maxKeyLen+1))
	r.Close()
	waitErr := cmd.Wait()
	if waitErr != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			if st, ok := ee.Sys().(syscall.WaitStatus); ok {
				code = st.ExitStatus()
			}
		}
		clear(key)
		halt(con, "key provider %s: %s", c.key, providerVerdict(code))
	}
	if readErr != nil || len(key) == 0 || len(key) > maxKeyLen {
		clear(key)
		halt(con, "key provider %s returned no usable key", c.key)
	}
	return key
}

func providerVerdict(code int) string {
	switch code {
	case 10:
		return "wrong secret"
	case 11:
		return "state or policy mismatch (this boot does not match the sealed state)"
	case 12:
		return "hardware missing"
	case 13:
		return "aborted"
	default:
		return fmt.Sprintf("failed (exit %d)", code)
	}
}

// openLUKS opens the container: with a key from a provider or credential, or
// with passphrases from the console.
func openLUKS(con *Console, c config, dev string, key []byte) {
	hdr := dev
	if c.luksHeader != "" {
		if _, err := os.Stat(c.luksHeader); err != nil {
			halt(con, "luks.header %s: %v", c.luksHeader, err)
		}
		hdr = c.luksHeader
	}
	if key != nil {
		v, err := luks.Recover(hdr, dev, key)
		if err != nil {
			halt(con, "LUKS: %v", err)
		}
		mapVolume(con, c.luksName, dev, hdr, v)
		return
	}
	for i := 0; i < 3; i++ {
		pw := con.Secret("Passphrase for " + strings.TrimPrefix(dev, "/dev/") + ": ")
		v, err := luks.Recover(hdr, dev, []byte(pw))
		if errors.Is(err, luks.ErrNoKeyslot) {
			con.Say("wisp-init: wrong passphrase")
			continue
		}
		if err != nil {
			halt(con, "LUKS: %v", err)
		}
		mapVolume(con, c.luksName, dev, hdr, v)
		return
	}
	halt(con, "LUKS: too many failed attempts")
}

func mapVolume(con *Console, name, dev, hdr string, v *luks.Volume) {
	if err := luks.MapCrypt(name, dev, v); err != nil {
		halt(con, "dm-crypt mapping: %v", err)
	}
	clear(v.MasterKey)
	con.Say("wisp-init: LUKS opened (header %s) -> /dev/mapper/%s", hdr, name)
}

# Test vectors

Language-neutral inputs with their expected outputs. Every implementation of the
algorithms in this repository, in whatever language, must reproduce these bytes exactly.
The Go tests read them (`go test ./...`); a port in another language is done when it
passes the same files.

Regenerate with `go test ./internal/... -update` (needs objcopy and cryptsetup); commit
the result only when the format itself changed deliberately, and say so in CHANGELOG.md.

## cpio/

`tree/` is a small directory: an executable `init`, `usr/bin/tool`, `etc/cmdline`, and the
symlink `usr/modules -> ../lib/modules`. `expected.cpio` is its reproducible newc archive
with source epoch 0, `expected.sha256` its digest, `expected-epoch-1700000000.sha256` the
digest with the mtime pinned to 1700000000 (a control: the epoch must change the bytes).

## modules/

`9.9.9-test/` is a synthetic `/lib/modules/<version>` tree of tiny ELF64 modules whose
`.modinfo` carries `depends=` and `name=` (built with objcopy), plus `modules.builtin`.
`manifest` selects subtrees with cutouts. `expected.order` is the resolved load order,
`expected.cpio` the built initrd (uncompressed, source epoch 0), `expected.sha256` its digest.
The resolution must come from the modules' own `.modinfo`, never from a depmod output.

## luks/

`luks2.img` is a LUKS2 container (aes-xts-plain64, sha256, argon2id with tiny parameters,
reduced metadata and keyslot areas) formatted by cryptsetup with the passphrase in
`passphrase.txt`. `master-key.hex` is the volume key cryptsetup dumped for it;
`segment.txt` lists encryption, sector size, data offset and size. A volume-key recovery
must yield exactly `master-key.hex` from the image and the passphrase, and must reject
`wrong-passphrase.txt`.

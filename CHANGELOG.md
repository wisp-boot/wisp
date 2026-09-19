# Changelog

## 0.3.0 (2026-09-18)

- The LUKS2 header is parsed by the builder, not by the init. `wisp build` reads the header of
  the container (or the detached header) and writes `/etc/wisp/luks.tab`: keyslots, digests and
  segments with every parameter checked against the bounds the init enforces, plus the SHA-256 of
  the header's JSON area. wisp-init hashes the header on the device, compares, and recovers the
  key from the table; `encoding/json` is gone from the init, and the only bytes an attacker can
  write that the init still parses are the 4 KiB binary head (magic, version, size, UUID) and the
  superblock probe. The price: after `luksAddKey`, `luksChangeKey`, `luksKillSlot` or a changed
  PBKDF the initramfs must be rebuilt, or the boot halts with a message saying so. New verb
  `wisp luks-tab`, new vector `vectors/luks/expected.luks.tab`.
- wisp-init checks the provider name with a loop instead of `regexp`, which cost a quarter
  megabyte of binary for one check.
- The archive carries a module table, `lib/modules/<version>/modules.wisp`: for every module its
  `depends=`, `softdep=` and `alias=` patterns as the builder read them from the `.modinfo`
  section, plus the kernel's builtin list. wisp-init reads this one file and no longer opens a
  module before `finit_module`, so it needs neither the `.modinfo` reader nor the zstd, xz and
  gzip decompressors (the binary shrinks by about 450 kB) and spends no boot time decompressing
  thousands of modules. Replaces the pruned `modules.order`. The module vector gained aliases and
  a softdep, so its bytes changed.
- Package: an upgrade from one wisp version to the next rebuilds the initramfs of every installed
  kernel; the first installation still builds only the running kernel's, so that an older kernel
  keeps the way back.

## 0.2.0 (2026-09-17)

- `wisp build` refuses, before a reboot, a btrfs root that is a subvolume (no root mount options
  yet), a provider name or file that wisp-init would halt on, and archive entries that do not
  fit the newc format or whose parent is not a directory. It recognises the root logical volume
  also when its device-mapper UUID is empty.
- The manifest format carries its number: `format = 1` is the first line, written by
  `wisp manifest` and required by `wisp build --manifest`. Another number, an unknown key,
  an unknown section or a top-level line without `=` is an error, so a reader never builds a
  different archive from a manifest it does not fully understand. A verifier must do the same.
- wisp-init reads a key provider's key into one fixed buffer, so that clearing it reaches every
  copy.
- Documentation: what the archive's bytes depend on, what a verifier needs, the way back with
  one installed kernel; the man pages list the archive's contents as they are.

## 0.1.0 (2026-09-15)

First release.

- `wisp-init`: pure-Go `/init`. Coldplug from `/sys/devices` against the modules' own
  alias patterns, LUKS2 volume-key recovery and dm-crypt mapping without cryptsetup,
  linear logical volume over dm-crypt without lvm2 (recorded table), root by UUID or
  path, switch_root. Key sources: none, passphrase, credential, external key provider
  (protocol 1). Kernel command-line module parameters are passed to finit_module as
  modprobe would. Halts on failure, no shell.
- Default module selection like initramfs-tools' "most": every module except network, sound,
  media, staging, InfiniBand, Bluetooth, IIO, hwmon, kheaders, ZFS and GPUs (the console before
  the passphrase runs on the firmware frame buffer, as in Ubuntu's own initramfs).
- Firmware: the files named by the selected modules are placed under /lib/firmware in the
  archive (`firmware = modules`, the default), symlinks kept so each file is stored once.
  About 78 MB for the default selection on an Ubuntu kernel, microcode included.
- Blacklists from /etc/modprobe.d are honoured by the coldplug (alias matches only).
- Console keyboard layout: every XKB layout and variant is precompiled at package build
  (ckbcomp, loadkeys -b -u; tools/mkkeymaps.sh) into /usr/share/wisp/keymaps; the builder
  copies the system's layout (/etc/default/keyboard) to /etc/wisp/keymap.bin and the init
  loads it with KDSKBENT before the first prompt (`keymap = system | none |
  <layout>[:<variant>]`). The file in the initramfs is a byte copy of a package file.
- The package listens to the `update-initramfs` dpkg trigger and to the microcode
  directories, so firmware and microcode updates rebuild the initramfs as with
  initramfs-tools.
- CPU microcode (`microcode = all`, the default): the amd64-microcode and intel-microcode files
  concatenated into the uncompressed early cpio the kernel's early loader reads, prepended to
  the archive. No selection tool; a pure function of the two packages.
- Manifest keys `firmware` and `microcode` are additions to the manifest format; a verifier
  that reproduces archives must implement them.
- `wisp`: manifest assembly from `/etc/wisp` and `/etc/crypttab`, deterministic newc cpio,
  module resolution from `.modinfo` (no depmod), deterministic zstd, `update-initramfs`
  facade, kernel hooks.
- Debian package replacing initramfs-tools (`Provides: linux-initramfs-tool`).
- Boots the reference laptop (ThinkPad, Ubuntu 24.04, LUKS2 on a linear LVM volume) through
  stock shim and GRUB with Secure Boot enabled; GRUB and the kernel's EFI stub both measure the
  initramfs with the digest the builder printed.
- Hermetic build: ubuntu:24.04 pinned by digest
  `sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254`, apt snapshot
  `20260914T000000Z` (golang-go 2:1.22~2build1).

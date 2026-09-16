# Changelog

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
- Console keyboard layout: the builder compiles the layout from /etc/default/keyboard
  (ckbcomp, loadkeys -b -u) into /etc/wisp/keymap.bin; the init loads it with KDSKBENT
  before the first prompt (`keymap = system | none | <layout>[:<variant>]`).
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

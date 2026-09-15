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
  GPUs, media, staging, InfiniBand, Bluetooth, IIO, hwmon, kheaders and ZFS (about 3200 modules,
  53 MB compressed on an Ubuntu kernel).
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

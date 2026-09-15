# wisp

A reproducible initramfs for encrypted root file systems, in one static Go binary.

`wisp build` assembles an initramfs whose bytes are a pure function of a declared manifest and
the kernel package's module tree. Same inputs, same bytes, bit for bit, on any machine. Nothing
is scanned from the running system, no binaries are collected by following shared libraries, no
file system times leak into the archive. The archive contains one program, `wisp-init`, which
finds the hardware without udev, opens LUKS2 without cryptsetup, activates a linear logical
volume without lvm2, and hands over to the real system.

The point of reproducibility is that someone who does not trust the machine can still predict
what it should have booted: rebuild the archive from the same public inputs and compare hashes.
The point of one static binary is that there is little to read, little to measure, and nothing
to reach a shell through.

## How a boot works

1. Mount proc, sysfs, devtmpfs and a tmpfs on `/run`.
2. Coldplug: read every `modalias` under `/sys/devices`, match it against the alias patterns of
   the modules in the archive (the kernel's own fnmatch semantics), load the matches with their
   dependencies, repeat until a round loads nothing new. Fallbacks: all storage modules if the
   container has not appeared, all input modules if there is no input device.
3. Wait for the LUKS2 container with the configured UUID.
4. Obtain the key: `none`, `passphrase`, `credential`, or a key provider process.
5. Recover the volume key from a keyslot and create the dm-crypt mapping through the
   device-mapper ioctl. Replay the recorded volume table over it, if root is on a logical volume.
6. Find the root file system by UUID or path, mount it read-only.
7. Move the pseudo file systems, chroot, exec `/sbin/init`.

On any failure the init says why and halts. There is no rescue shell.

## Install (Ubuntu 24.04, Debian 12 and later)

```
sudo apt install ./wisp_0.1.0_amd64.deb
sudo reboot
```

wisp provides `linux-initramfs-tool` and replaces initramfs-tools, like dracut does. On
installation it builds the initramfs for the running kernel only; older kernels keep their
previous initrd, which is the way back if wisp does not boot your machine: pick the older kernel
in the boot menu, then `apt install initramfs-tools` (which removes wisp) and
`update-initramfs -u`.

Kernel updates call the hook under `/etc/kernel/postinst.d`, packages that call
`update-initramfs` reach the compatible facade. Both are the `wisp` binary.

## Configuration

Everything lives under `/etc/wisp`; none of the files is required for a standard installation
(LUKS2 with a linear logical volume, or LUKS2 with the root file system inside, or no
encryption at all). See `wisp.conf(5)` for the full reference.

`/etc/wisp/wisp.conf`, the runtime configuration. The builder completes it from `/etc/crypttab`
and the running system and places the completed copy in the archive, where it is part of the
bytes and therefore of whatever measures them:

```
key        = passphrase   # none | passphrase | credential | <provider name>
luks.uuid  = ...          # from /etc/crypttab when absent
luks.name  = dm_crypt-0   # device-mapper name of the opened container
root       = /dev/mapper/ubuntu--vg-ubuntu--lv
```

`/etc/wisp/modules`, module names and directory selectors (`+dir:kernel/drivers/nvme`,
`-dir:kernel/drivers/usb/gadget`). Without it a broad laptop-oriented selection is used, about
22 MB compressed on an Ubuntu kernel. Modules are loaded at boot only when hardware matches, so
declaring many costs size, not time.

`/etc/wisp/lvm.tab`, the device-mapper table of the root logical volume. Recorded from the
running system when absent. Rebuild the initramfs after resizing the root volume.

## Key sources

| `key =`      | what happens at boot                                                                     |
|--------------|------------------------------------------------------------------------------------------|
| `none`       | no LUKS; the root file system is mounted directly                                        |
| `passphrase` | asked on the console, three attempts                                                     |
| `credential` | read from `/.extra/credentials/cryptsetup.passphrase`, a file a pre-kernel stage may append to the initramfs as an extra cpio (the systemd-stub convention); missing file: passphrase prompt |
| `<name>`     | the executable `/usr/lib/wisp/key/<name>` with `/etc/wisp/key/<name>/` as its configuration, both placed in the archive by the builder |

A key provider runs once, with the console on file descriptors 0 to 2 and a pipe on descriptor
3 into which it writes the raw key bytes. Its exit status distinguishes a wrong secret, a state
mismatch, missing hardware and a user abort. The provider owns everything sensitive it computes
and has ended before the container is opened. The protocol is in `wisp.conf(5)`.

## Building and verifying

```
make            # build/wisp-init and build/wisp
make test       # unit tests; the root-only tests are opt-in: WISP_DM_TEST=1, WISP_LVM_TEST=1
make deb        # the Debian package in a container (podman), with SHA256SUMS
```

To verify an initramfs on another machine, take the manifest and the generated files from the
machine that built it (`wisp manifest --stage <dir>` writes both), fetch the same kernel
package, and run `wisp build --manifest <dir>/manifest --compress none` there. The uncompressed
archives must be byte-identical; `wisp build` prints their SHA-256. The module resolution reads
each module's own `.modinfo` section and never `modules.dep`, so it does not depend on the
depmod version of either machine.

Releases are built with `GOFLAGS=-mod=vendor -trimpath`, `CGO_ENABLED=0` and
`-ldflags "-s -w -buildid="` from the vendored dependencies; with the same Go toolchain the
binaries are byte-identical. Release conditions: the package builds in the container, the
tests pass, and the initramfs built for the current distribution kernel boots to `switch_root`
in a virtual machine. The last point is the guard against upstream changes in module
packaging (a new compression format, a new `.modinfo` field) and belongs in continuous
integration against every new kernel package.

## Supported layouts

Ubuntu's standard encrypted installation (LUKS2 with a linear logical volume holding ext4), LUKS2
with the root file system directly inside, a root file system without encryption on a plain
partition; ext4, xfs and single-device btrfs. Not supported in this release: LUKS1, software
RAID, multi-device btrfs, LUKS on a logical volume, LVM without LUKS, striped, thin or RAID
logical volumes, resume from hibernation, network root, firmware files in the archive.
Unsupported layouts are rejected by `wisp build`, before a reboot.

## Layout of the repository

```
cmd/wisp-init/     the /init: coldplug, key sources, LUKS, volumes, root, switch_root
cmd/wisp/          the builder, update-initramfs facade and kernel hooks
internal/kmod/     .modinfo reader and module decompression (zstd, xz, gzip) in pure Go
internal/initrd/   manifest, deterministic cpio, module resolution, build
internal/luks/     LUKS2 volume-key recovery and device-mapper ioctls
debian/            the package
man/               wisp(8), wisp.conf(5), wisp-init(7)
vendor/            pinned dependencies (all BSD or MIT)
```

## License

GPL-2.0-only. The pattern matcher in `cmd/wisp-init/coldplug.go` is a port of `lib/glob.c`
from the Linux kernel. The LUKS2 code is written from the on-disk format specification.

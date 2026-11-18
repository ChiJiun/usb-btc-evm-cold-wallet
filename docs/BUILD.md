# Buildroot image build

## Pinned inputs

The appliance build fixes:

- Buildroot: `2026.08.2`
- Linux: `6.12.47` (using Buildroot's supplied pc-board hash set)
- Python target: CPython `3.14`
- `embit`: `0.8.0` source tarball
- `eth-account`: `0.14.0`
- `cryptography`: `47.0.0`
- every transitive target wheel filename + SHA-256

Lock files:

- `infra/buildroot.env`
- `infra/embit.env`
- `infra/wheelhouse-requirements.txt`
- `infra/wheelhouse.sha256`

## Build host prerequisites

Buildroot requires a normal Linux development host. The scripts check for:

```
make gcc g++ patch rsync perl tar cpio file bc awk sed grep gzip bzip2 xz python3
```

Ubuntu/Debian reference packages:

```
build-essential make gcc g++ patch rsync perl tar cpio file bc gawk gzip bzip2 xz-utils python3 python3-venv curl
```

Do **not** install compilers or package managers into the cold-wallet target image; these are build-host tools only.

## Online preparation

```bash
make prepare-sources
```

This does three things:

1. downloads and verifies the pinned CPython 3.14 x86_64 wheelhouse;
2. downloads/verifies the pinned Buildroot source tree;
3. resolves the external defconfig and asks Buildroot to fetch all source artifacts into `build/dl/`.

After this succeeds, retain the repository plus `build/cache`, `build/wheelhouse`, `build/buildroot` and `build/dl`.

## Offline image build

After the source cache has been prepared, the build host may be disconnected:

```bash
make image
```

The scripts first re-check local hashes. Existing valid wheelhouse/Buildroot archives are reused rather than downloaded again.

Output:

```
build/output/images/usb-cold-wallet.img
build/output/images/usb-cold-wallet.img.sha256
build/output/images/bzImage.sha256
```

## Static verification

```bash
make verify
```

Checks include:

- generated image SHA-256;
- protective MBR + GPT header;
- exactly two GPT partitions;
- first partition is EFI System Partition;
- Linux final config has `CONFIG_NET` disabled;
- USB storage + VFAT are enabled;
- ATA/NVMe/MMC/VirtIO block are not enabled;
- appliance launchers exist in target rootfs;
- common networking applets do not exist in target rootfs.

The Buildroot post-build hook performs another networking-tool check before the image is emitted.

## Why Buildroot

A general-purpose Ubuntu/Tails-style live environment carries far more services, drivers and parsers than this signer needs. The current design uses a small Buildroot rootfs and a custom kernel config so the network subsystem is removed at compile time and no persistent root filesystem is required.

The design was informed by projects such as SignerOS, but this repository does not copy SignerOS source code because its repository did not advertise a license at the time of review.

## Reproducibility status

The inputs used by this project are pinned, and the build scripts produce image checksums. That is **not yet equivalent to demonstrated reproducible builds**.

Before claiming reproducibility:

1. build the same commit on at least two clean compatible build hosts;
2. compare `usb-cold-wallet.img`, `bzImage` and relevant rootfs manifests;
3. identify timestamps/build paths or other nondeterministic fields;
4. set a controlled `SOURCE_DATE_EPOCH` and remove nondeterminism;
5. repeat until hashes match.

Until then the correct status is: **pinned-input image build, reproducibility not yet independently demonstrated**.

## Current Devspace verification limitation

The project VM used during initial implementation is ARM64 and intentionally lacks Buildroot host development tools such as `make`, `gcc`, `g++` and `bzip2`. Project policy forbids modifying host system packages. Therefore that VM can verify wheel hashes, Python tests, scripts and target payload assembly, but cannot complete the x86_64 Buildroot image compilation itself.

A full build must run on a compatible build host with the prerequisites above or in CI once the repository's workflow authorization is available.

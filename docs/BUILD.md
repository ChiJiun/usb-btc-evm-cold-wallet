# Buildroot image build

## Pinned and authenticated inputs

The appliance build fixes:

- Buildroot: `2026.08.2`
- Linux: `6.12.47` (using Buildroot's supplied pc-board hash set)
- Python target: CPython `3.14`
- `embit`: `0.8.0` source tarball
- `eth-account`: `0.14.0`
- `cryptography`: `50.0.2` (kept in sync with the hardened main project dependency)
- every transitive target wheel filename + SHA-256
- a fixed `SOURCE_DATE_EPOCH` for generated metadata

Lock/provenance files:

- `infra/buildroot.env`
- `infra/buildroot-release-key.asc`
- `infra/reproducible.env`
- `infra/embit.env`
- `infra/wheelhouse-requirements.txt`
- `infra/wheelhouse.sha256`

### Buildroot release authentication

This design does **not** use a prebuilt Linux distribution ISO. The upstream OS/build-system input is the Buildroot release tarball instead, so the equivalent ISO trust check is performed on that release.

`scripts/fetch_buildroot.sh` verifies the following chain before extracting Buildroot:

1. the vendored Buildroot release public key file matches its pinned SHA-256;
2. the key's primary fingerprint matches the pinned fingerprint;
3. the downloaded `.tar.xz.sign` clear-signed release manifest matches its pinned SHA-256;
4. `gpgv` validates that manifest with only the pinned release key;
5. the SHA-256 named inside the verified manifest matches the repository's pinned SHA-256;
6. the downloaded `.tar.xz` matches that signed SHA-256.

The verification uses a temporary keyring. It does not import the Buildroot key into the operator's normal GPG keyring.

## Build host prerequisites

Buildroot requires a normal Linux development host. The scripts check for:

```
make gcc g++ patch rsync perl tar cpio file bc awk sed grep gzip bzip2 xz
python3 curl wget sha256sum gpg gpgv mktemp find touch cmp diff
```

Ubuntu/Debian reference packages:

```
build-essential make gcc g++ patch rsync perl tar cpio file bc gawk gzip bzip2
xz-utils python3 python3-venv curl wget gnupg gpgv coreutils findutils diffutils
```

Do **not** install compilers or package managers into the cold-wallet target image; these are build-host tools only.

## Online preparation

```bash
make prepare-sources
```

This:

1. downloads and verifies the pinned CPython 3.14 x86_64 wheelhouse;
2. authenticates and extracts the pinned Buildroot release;
3. resolves the external defconfig and asks Buildroot to fetch all source artifacts into `build/dl/`.

After this succeeds, retain the repository plus `build/cache`, `build/wheelhouse`, `build/buildroot` and `build/dl`.

## Offline image build

After the source cache has been prepared, the build host may be disconnected:

```bash
make image
```

The scripts re-check local hashes and the Buildroot release signature before using cached inputs.

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
- protective MBR plus primary/backup GPT headers, partition tables, CRCs and geometry consistency;
- exactly three GPT partitions for the single-USB image;
- deterministic GPT disk and partition UUIDs;
- first partition is an EFI System Partition and is marked GPT read-only;
- second partition is the writable FAT `COLD_VAULT`, but uses the Linux filesystem GPT type so normal Windows Explorer does not treat it as the shared data volume;
- third partition is the writable FAT32 `TX_TRANSFER` with deterministic PARTUUID and is the only Microsoft Basic Data partition intended for Windows;
- Linux final config has `CONFIG_NET` disabled;
- USB storage + VFAT are enabled;
- ATA/NVMe/MMC/VirtIO block are not enabled;
- appliance launchers exist in target rootfs;
- common networking applets do not exist in target rootfs.

The Buildroot post-build hook performs another networking-tool and secret-looking-file check before the image is emitted.

## Reproducible image build

The repository now enables and constrains reproducibility rather than merely pinning inputs:

- `BR2_REPRODUCIBLE=y`;
- `SOURCE_DATE_EPOCH=1794940300` is fixed in `infra/reproducible.env`;
- GPT disk/partition UUIDs are fixed;
- both FAT filesystems use `mkfs.fat --invariant`;
- EFI input mtimes are normalized before genimage serializes them.

Run:

```bash
make reproducibility-check
```

That target performs **two isolated clean Buildroot rebuilds at the same canonical `O=build/output` path** and requires identical SHA-256 values for both `usb-cold-wallet.img` and `bzImage`. After the first build and digest snapshot, the complete generated tree is moved to `build/output-repro-1`; `build/output` is asserted absent before the second build starts from zero. The first and second generated trees therefore remain separate while both builds see the same absolute build path. The second clean output remains as the verified image consumed by later UEFI/artifact steps.\n\nBoth builds intentionally share only the same authenticated/hash-locked source/download cache and fixed Buildroot source tree. They do not share generated Buildroot output state. This avoids confusing absolute build-path sensitivity with artifact nondeterminism while preserving the independent-clean-tree gate; successful CI is still not a claim of independent third-party reproducibility.

## Runtime memory / swap / persistence audit

At boot, `S01airgap` performs a fail-closed audit before wallet operations are enabled:

- `/proc/net` must be absent;
- no swap may be active;
- `/` must be a RAM-backed `rootfs` or `tmpfs`;
- the boot and vault partitions must each resolve uniquely by their fixed GPT PARTUUIDs;
- the verified boot and vault partitions must share the same block-device parent discovered through sysfs;
- `COLD_VAULT` must be mounted from that exact verified vault device as VFAT with `rw,noexec,nodev,nosuid,sync`;
- no other writable non-memory filesystem may be mounted.

If two cloned cold-wallet USBs with the same deterministic PARTUUIDs are attached, uniqueness fails and the appliance enters lockdown rather than guessing which device is authoritative.

Any failure creates `/run/usb-wallet/lockdown`. The appliance console then disables wallet creation/signing and only permits power-off.

## Build verification environments

The Devspace VM is ARM64 and intentionally lacks the normal Buildroot host compiler toolchain, so it is used for unit/static tests, source/hash verification and cross-platform wheelhouse validation only. The repository also includes an x86_64 GitHub Actions workflow that performs the authoritative full Buildroot image build, two-clean-build reproducibility comparison and OVMF/QEMU UEFI boot smoke test.

The automated UEFI smoke test validates firmware → bootloader → kernel/initramfs → startup-audit execution for the generated image. It does not claim graphical UI startup because CI currently runs QEMU with `-display none`; framebuffer-native UI interaction and physical removable-media acceptance remain separate evidence gates.


## Single-USB development image

The current single-USB branch builds a deterministic GPT layout:

| Partition | Size | GPT type | FAT label | Purpose |
| --- | ---: | --- | --- | --- |
| 1 | 64 MiB | EFI System | `USBCOLD_EFI` | UEFI/GRUB/kernel; GPT read-only intent |
| 2 | 64 MiB | Linux filesystem | `COLD_VAULT` | app-level encrypted vault/policy only |
| 3 | 512 MiB | Microsoft Basic Data | `TX_TRANSFER` | Windows/Linux transaction exchange and Portable Companion |

The Portable Companion integration path is fixed at
`TX_TRANSFER:/COMPANION/usb-cold-companion.exe`; transaction files live below
`TX_TRANSFER:/TRANSACTIONS/`. This branch deliberately does not copy a Windows
binary from an unverified build. After the portable packaging artifact and PR
#68 image-artifact pipeline are merged, the integration job must insert the
already-verified EXE before final image hashing/reproducibility verification.

A normal USB has no hardware write protection. The Linux GPT type merely keeps
`COLD_VAULT` out of ordinary Windows drive-letter mounting; an administrator,
malware, firmware, or raw-disk tool can still modify any USB sector. This
testnet development image therefore does not claim Secure Boot, authenticated
boot, anti-rollback, or resistance to an already-compromised Windows host.


## Preparing a larger physical USB (testnet development)

The reproducible raw image has a fixed capacity; a larger target device
requires protective-MBR and secondary-GPT geometry for the actual device.
Do not relax the cold boot verifier. After confirming the actual byte capacity
and independently obtained raw CI image SHA-256, on a 64-bit Python host:

```bash
python -m scripts.prepare_usb_capacity_image usb-cold-wallet.img prepared-32gb.img \
  --capacity-bytes 31457280000 --expected-sha256 <trusted-raw-ci-sha256>
python scripts/verify_image.py prepared-32gb.img
```

The helper only reads regular input files and creates a new regular output;
it cannot flash a physical USB. It verifies the source hash, strict GPT/FAT
layout, relocates only GPT metadata, removes the obsolete secondary GPT,
preserves the exact partition entries and verifies the derived layout again.
It prints separate source/derived SHA-256 and size. The output is not the
original reproducible release artifact. It may consume the target capacity
in disk space, especially on filesystems without sparse-file support.
The independent post-flash device readback and physical boot still have to
be verified against the prepared output, and flashing remains an explicitly
authorized external operation. Secure Boot remains a separate issue.

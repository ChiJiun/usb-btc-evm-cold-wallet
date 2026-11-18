# Reproducible Live USB image

Issue #1 adds a rootless remaster pipeline around a **pinned official Debian Live 13.7.0 amd64 standard ISO**. The repository still targets test networks only and has not received an independent security audit.

## What is pinned

- Base image: `debian-live-13.7.0-amd64-standard.iso`
- Base SHA-256: `040a44f35186321eb6cdaab52a8a2d06224fe6b77f6fbb9f1861ad89c14e17ec`
- Debian CD signing key: `DF9B9C49EAA9298432589D76DA87E80D6294BE9B`
- Python runtime in the base image: Python 3.13
- 27 Python runtime artifacts: exact filenames + SHA-256 in `image/python-artifacts.lock.json`
- ISO build tools: xorriso 1.5.6, unsquashfs/mksquashfs 4.6.1 in `image/build-tools.json`

Debian publishes signed checksum files beside official images. `tools.fetch_base_iso` first checks the downloaded public key against the repository-pinned fingerprint, verifies the OpenPGP signature on `SHA256SUMS`, checks that the signed checksum equals our repository pin, and only then accepts the ISO.

## Build host requirements

The builder itself does not need root. It needs:

- Python 3.12+
- GnuPG (`gpg`)
- xorriso 1.5.6
- squashfs-tools 4.6.1 (`unsquashfs` / `mksquashfs`)
- Git

The exact xorriso/squashfs versions are enforced because changing image-building tools can change output bytes.

## Fetch and authenticate inputs

```bash
python3 -m tools.fetch_base_iso --cache-dir build/cache/base
python3 -m tools.fetch_python_artifacts --artifact-dir build/cache/python-amd64-py313
```

After the first fetch, both can be rechecked with no network:

```bash
python3 -m tools.fetch_base_iso --cache-dir build/cache/base --offline
python3 -m tools.fetch_python_artifacts --artifact-dir build/cache/python-amd64-py313 --offline
```

No package setup script is executed when the image is assembled. Wheels are safely unpacked and the pinned pure-Python `embit` source subtree is copied directly from its verified sdist.

## Build

Release builds require a clean Git tree. When `SOURCE_DATE_EPOCH` is not supplied, the builder uses the current Git commit timestamp.

```bash
python3 -m tools.build_live_iso \
  --base-iso build/cache/base/debian-live-13.7.0-amd64-standard.iso \
  --artifact-dir build/cache/python-amd64-py313 \
  --output dist/usb-btc-evm-cold-wallet-amd64.iso
```

The builder:

1. verifies the base ISO SHA-256 again;
2. verifies every Python artifact again;
3. checks exact xorriso / squashfs-tools versions;
4. extracts the official hybrid BIOS/UEFI ISO and SquashFS without root;
5. injects the wallet package and locked dependencies under `/opt/usb-cold-wallet`;
6. installs air-gap, swap/core-dump, udev and boot-audit controls;
7. masks network services and `swap.target`;
8. statically audits the extracted root filesystem;
9. rebuilds SquashFS with fixed timestamps and deterministic zstd level-15 / 1 MiB block options;
10. adds `nopersistence`, IPv6 disablement and radio module blacklist boot parameters;
11. regenerates ISO MD5/SHA-256 content manifests;
12. replays the original Debian hybrid BIOS/UEFI boot layout with fixed ISO timestamps;
13. emits `<image>.sha256`.

After a build, audit the **finished ISO** rather than trusting only the build log:

```bash
python3 -m tools.audit_live_iso \
  --iso dist/usb-btc-evm-cold-wallet-amd64.iso \
  --sha256-sidecar dist/usb-btc-evm-cold-wallet-amd64.iso.sha256
```

The post-build audit checks the sidecar hash, BIOS + UEFI hybrid boot entries, required non-persistent boot flags, embedded build metadata, runtime controls and the complete 27-artifact manifest inside SquashFS.

A dirty-tree smoke build is deliberately marked as non-release:

```bash
python3 -m tools.build_live_iso ... --allow-dirty
```

## Reproducibility check

Build the same clean Git commit twice, preferably on two fresh hosts with the exact pinned build-tool versions, and compare:

```bash
sha256sum build-a/usb-btc-evm-cold-wallet-amd64.iso
sha256sum build-b/usb-btc-evm-cold-wallet-amd64.iso
cmp build-a/usb-btc-evm-cold-wallet-amd64.iso \
    build-b/usb-btc-evm-cold-wallet-amd64.iso
```

A byte-for-byte match is the release criterion. Do not publish a reproducibility claim for a commit until this comparison succeeds.

## Boot-time controls

The image does not merely omit network configuration.

- all common network manager / supplicant services are systemd-masked;
- all currently present non-loopback interfaces are flushed and administratively set DOWN;
- a udev rule repeats the DOWN operation for newly attached network interfaces;
- nftables base chains default DROP for IPv4/IPv6 and ARP;
- Wi-Fi/Bluetooth framework modules are blacklisted as defense in depth;
- DNS configuration is empty;
- swap is disabled and `swap.target` is masked;
- suspend, hibernate and hybrid-sleep targets are masked so decrypted memory is not intentionally written to disk;
- process core dumps are disabled and the boot audit requires `RLIMIT_CORE=0`;
- live-boot receives `nopersistence`;
- the boot medium must be mounted read-only and the root filesystem must be a RAM-backed live overlay;
- `usb-cold-wallet` refuses to run unless `usb-cold-wallet-offline-audit` has passed during the current boot.

These are software controls. **Physically disconnect Ethernet and disable/remove radio hardware before unlocking a wallet.** A compromised firmware/kernel can bypass all software policy.

## What this does not prove

- no cold-boot or DMA attack;
- no secret remnants in RAM after Python creates immutable strings;
- no malicious firmware, USB controller or BIOS/UEFI;
- no security of the wallet transaction parser beyond current tests;
- no mainnet readiness.

Always power the machine fully off after signing; do not suspend or hibernate.

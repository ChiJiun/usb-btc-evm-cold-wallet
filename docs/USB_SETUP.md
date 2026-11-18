# USB setup and operator guide

> **TESTNET research only. The image is not independently audited.**

The intended workflow uses **USB-A as the cold boot device** and **USB-B only as a transaction transport device**. The live root is read-only and non-persistent.

## 1. Build or obtain the image

For source builds, follow [LIVE_IMAGE.md](LIVE_IMAGE.md). Before flashing, verify the sidecar:

```bash
sha256sum -c usb-btc-evm-cold-wallet-amd64.iso.sha256
```

The project build additionally authenticates the pinned Debian base ISO using Debian's signed `SHA256SUMS` and the pinned Debian CD signing-key fingerprint.

## 2. Flash USB-A

Use an 8 GB+ USB stick and a raw-image writer (for example Rufus in DD/raw mode, Etcher, or `dd`). **Flashing destroys the selected USB device.** Verify the device identity yourself before writing.

Linux example:

```bash
sudo dd if=usb-btc-evm-cold-wallet-amd64.iso of=/dev/REPLACE_USB_DEVICE \
  bs=4M conv=fsync status=progress
```

Do not use a mounted partition path such as `/dev/sdX1`; the target is the whole USB device.

The ISO root is intentionally non-persistent. If you want a two-stick workflow, USB-A needs a separate writable data partition (for example an ext4 partition labeled `COLDVAULT`) in unused space after the ISO image. **The current repository does not automate partition-table changes**, because selecting the wrong block device would destroy data. Create that partition only after independently identifying USB-A. Never mount that vault partition on an online computer.

If USB-A has no `COLDVAULT` partition, use a third, offline-only storage device for `wallet.vault`.

## 3. Prepare USB-B

USB-B is a normal small transport drive. It may touch the online computer, so it must contain **only**:

- public watch-only data;
- unsigned PSBT / EVM transaction JSON;
- signed PSBT / raw EVM transaction output.

Never put these on USB-B:

- BIP39 words;
- BIP39 passphrase;
- `wallet.vault`;
- raw private keys.

Treat every file arriving from USB-B as attacker-controlled input.

## 4. Boot offline

1. Fully shut down the signing computer.
2. Disconnect Ethernet.
3. Disable/remove Wi-Fi and Bluetooth hardware where practical.
4. Boot from USB-A.
5. **Do not insert USB-B yet.**
6. Check the automatic boot audit:

```bash
sudo usb-cold-wallet-offline-audit
```

Expected final line:

```text
OFFLINE AUDIT: PASS
```

The wallet launcher refuses to run without the current-boot PASS marker.

Useful manual checks:

```bash
cat /proc/swaps
cat /proc/cmdline
ip -o addr show scope global
findmnt /run/live/medium
sudo nft list chain inet usb_cold_wallet output
```

Expected: no active swap, `nopersistence` in the kernel command line, no global IP address, live medium mounted `ro`, nftables output policy `drop`.

## 5. Mount the offline vault

For a USB-A data partition labeled `COLDVAULT`:

```bash
sudo mkdir -p /mnt/coldvault
sudo mount -o nodev,nosuid,noexec /dev/disk/by-label/COLDVAULT /mnt/coldvault
```

Create a wallet **only on the physically offline machine**:

```bash
usb-cold-wallet --vault /mnt/coldvault/wallet.vault \
  init --offline-ack --i-have-paper-backup
```

Write the displayed BIP39 words on paper/metal and keep that recovery material separate from the USB. Never photograph it.

Export public data:

```bash
usb-cold-wallet --vault /mnt/coldvault/wallet.vault addresses --count 3
```

Only the resulting public data may go to USB-B.

## 6. Sign with USB-B

Insert USB-B **after the boot audit has passed** and mount it with restrictive options:

```bash
sudo mkdir -p /mnt/transport
sudo mount -o nodev,nosuid,noexec /dev/REPLACE_TRANSPORT_PARTITION /mnt/transport
```

### EVM Sepolia

```bash
usb-cold-wallet --vault /mnt/coldvault/wallet.vault sign-evm \
  --tx /mnt/transport/sepolia-unsigned.json \
  --to 0x000000000000000000000000000000000000dEaD \
  --wei 1000000000000 \
  --out /mnt/transport/sepolia-signed.json
```

### Bitcoin testnet

```bash
usb-cold-wallet --vault /mnt/coldvault/wallet.vault sign-btc \
  --psbt /mnt/transport/unsigned.psbt \
  --to tb1qREPLACE_WITH_INDEPENDENTLY_VERIFIED_ADDRESS \
  --sats 50000 \
  --max-fee-sats 2000 \
  --change-index 0 \
  --out /mnt/transport/signed.json
```

Verify recipient, amount, network and fee from an independent trusted source, not solely from text supplied by the online computer.

Then:

```bash
sync
sudo umount /mnt/transport
```

Move USB-B to the online computer and broadcast the signed transaction using a separate wallet/node. Broadcasting is intentionally absent from this project.

## 7. End the signing session

Unmount the vault and fully power off:

```bash
sync
sudo umount /mnt/coldvault
sudo poweroff
```

Do not suspend/hibernate. The encrypted vault is protected at rest, but decrypted seed material and derived keys may have existed in RAM during the session.

## Current limitations

- Physical boot on representative x86_64 hardware must still be tested for each release.
- No secure element or trusted hardware display.
- No automatic creation of USB-A's writable vault partition.
- No mainnet signing, ERC-20, EIP-712, Taproot, multisig or QR transport.
- Recovery rehearsal and safer media workflow are tracked separately.

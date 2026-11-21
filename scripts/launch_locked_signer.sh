#!/bin/sh
# Intended as the single-purpose #1 Buildroot boot image entrypoint.
# NEVER execute as a service on a connected host; deployment requires #1 audit.
set -eu
umask 077

# Keep shell history, Python debug tools and interactive prompting disabled.
unset HISTFILE PYTHONSTARTUP PYTHONINSPECT
# All secret input is in the LOCAL Tk password dialog; never CLI args/env.
# The GUI itself fails closed if the boot audit is missing / swap or networking exists.
exec /usr/bin/python3 -m usb_cold_wallet.gui \
  --vault /mnt/cold-vault/wallet.vault \
  --transfer-dir /mnt/transfer \
  --lang zh-TW

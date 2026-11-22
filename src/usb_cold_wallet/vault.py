"""Scrypt + AES-256-GCM encrypted mnemonic container. No network functions."""
import base64
import errno
import json
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from embit import bip39

_AAD = b"usb-btc-evm-cold-wallet-v1"
_N = 1 << 17
_R = 8
_P = 1


def new_mnemonic() -> str:
    """Generate 256 bits using the operating system CSPRNG. Call only on a trusted offline OS."""
    return bip39.mnemonic_from_bytes(os.urandom(32))


def validate_mnemonic(mnemonic: str) -> str:
    words = " ".join(mnemonic.strip().split())
    if len(words.split()) not in (12, 15, 18, 21, 24):
        raise ValueError("BIP39 mnemonic must have 12/15/18/21/24 words")
    # Reject malformed mnemonics / invalid BIP39 checksums.
    bip39.mnemonic_to_bytes(words)
    return words


def _derive(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Wallet encryption passphrase needs at least 12 characters")
    return Scrypt(salt=salt, length=32, n=_N, r=_R, p=_P).derive(passphrase.encode("utf-8"))


def encrypt_mnemonic(mnemonic: str, passphrase: str) -> dict:
    mnemonic = validate_mnemonic(mnemonic)
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt)
    encrypted = AESGCM(key).encrypt(nonce, mnemonic.encode("utf-8"), _AAD)
    return {
        "format": "usb-btc-evm-cold-wallet",
        "version": 1,
        "kdf": {"name": "scrypt", "n": _N, "r": _R, "p": _P, "salt": base64.b64encode(salt).decode()},
        "cipher": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(encrypted).decode(),
    }


def decrypt_mnemonic(data: dict, passphrase: str) -> str:
    if (type(data) is not dict or
            set(data) != {"format", "version", "kdf", "cipher", "nonce", "ciphertext"} or
            data["format"] != "usb-btc-evm-cold-wallet" or
            type(data["version"]) is not int or data["version"] != 1):
        raise ValueError("Unknown wallet format")
    kdf = data["kdf"]
    if (type(kdf) is not dict or
            set(kdf) != {"name", "n", "r", "p", "salt"} or
            any(type(kdf[key]) is not int for key in ("n", "r", "p")) or
            (kdf["name"], kdf["n"], kdf["r"], kdf["p"]) != ("scrypt", _N, _R, _P)):
        raise ValueError("Unexpected KDF parameters")
    if data.get("cipher") != "AES-256-GCM":
        raise ValueError("Unexpected cipher")
    if (type(kdf["salt"]) is not str or type(data["nonce"]) is not str or
            type(data["ciphertext"]) is not str):
        raise ValueError("Malformed wallet")
    salt = base64.b64decode(kdf["salt"], validate=True)
    nonce = base64.b64decode(data["nonce"], validate=True)
    ciphertext = base64.b64decode(data["ciphertext"], validate=True)
    if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) > 2048:
        raise ValueError("Malformed wallet")
    try:
        return validate_mnemonic(AESGCM(_derive(passphrase, salt)).decrypt(nonce, ciphertext, _AAD).decode())
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise ValueError("Incorrect passphrase or corrupted wallet") from exc


def _atomic_rename_noreplace(parent_fd: int, stage: str, final: str) -> None:
    """Linux renameat2(RENAME_NOREPLACE), including FAT32; never overwrite.

    os.rename/os.replace may overwrite on Linux; hard links are unsupported on
    FAT32. An unavailable renameat2 must fail closed.
    """
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(38, "renameat2 is unavailable; refusing unsafe export")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(stage), parent_fd,
                 os.fsencode(final), 1) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), final)


def _require_private_export_directory(parent_fd: int) -> None:
    """Enforce one security identity for the staging/publish directory.

    A directory shared with another local UID/GID admits a stat/rename/unlink
    race. VFAT has no per-file ACL: the offline OS must mount it with a private
    uid/gid + dmask=0077 (or umask=0077). This cannot protect against a
    *compromised process with the same UID/root permissions*.
    """
    info = os.fstat(parent_fd)
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
        raise PermissionError(
            errno.EACCES,
            "Atomic export needs a signer-private directory (mode 0700)",
        )


def atomic_create_at(parent_fd: int, name: str, data: bytes) -> None:
    """Atomically publish complete bytes in a verified private Linux directory.

    FAT32 requires the entire TX_TRANSFER mount to be private to the signer.
    Concurrent actors with the same UID/root can still manipulate directory
    entries; the offline boot/runtime security boundary must exclude them.
    """
    import secrets

    if (type(name) is not str or not name or name in (".", "..")
            or "/" in name or "\x00" in name):
        raise ValueError("Invalid atomic export filename")
    if type(data) is not bytes:
        raise TypeError("Atomic export requires bytes")
    # Reject unsafe mount masks/ownership before creating a single entry.
    # FAT32 exposes mount-wide permissions, not effective chmod ACLs.
    _require_private_export_directory(parent_fd)
    stage = f".usbwallet-{secrets.token_hex(16)}.partial"
    fd = None
    identity = None
    try:
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0),
                     0o600, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Export stage is not regular")
        identity = (info.st_dev, info.st_ino)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("Short write while staging export")
            offset += written
        os.fsync(fd)
        # Keep the staged file descriptor open across publication so that a
        # replaced name cannot be silently accepted as our completed bytes.
        staged = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(staged.st_mode) or
                (staged.st_dev, staged.st_ino) != identity):
            raise OSError(errno.ESTALE, "USB staging file changed during export")
        _atomic_rename_noreplace(parent_fd, stage, name)
        # Check AFTER rename, using a fresh fstat: VFAT inode numbering may
        # change on rename. Comparing current fd vs the published directory
        # entry detects a staged-name swap during the rename boundary.
        published = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        held = os.fstat(fd)
        if (not stat.S_ISREG(published.st_mode) or
                (published.st_dev, published.st_ino) != (held.st_dev, held.st_ino)
                or published.st_size != len(data)):
            raise OSError(
                errno.ESTALE,
                "USB published file does not match staged descriptor; refusing success",
            )
        os.fsync(parent_fd)
        os.close(fd)
        fd = None
    finally:
        if fd is not None:
            os.close(fd)
        if identity is not None:
            try:
                staged = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
                if (stat.S_ISREG(staged.st_mode) and
                        (staged.st_dev, staged.st_ino) == identity):
                    os.unlink(stage, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                # USB removal may prevent cleanup. Never publish .partial.
                pass


def save_vault(path: Path, data: dict) -> None:
    """Create-only, synced wallet/policy/transfer JSON (no partial final file)."""
    path = Path(path)
    raw = (json.dumps(data, indent=2) + "\n").encode("utf-8")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     getattr(os, "O_NOFOLLOW", 0))
    try:
        atomic_create_at(parent, path.name, raw)
    finally:
        os.close(parent)


def _unique_wallet_object(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate wallet JSON field")
        obj[key] = value
    return obj


def _reject_wallet_constant(value: str):
    raise ValueError("Non-finite wallet JSON value")


def load_vault(path: Path, passphrase: str) -> str:
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError as exc:
        raise ValueError("Vault file not found") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise ValueError("Vault file unexpectedly large or not regular")
        raw = os.read(fd, 4097)
        if len(raw) > 4096:
            raise ValueError("Vault file unexpectedly large")
    finally:
        os.close(fd)
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_wallet_object,
                      parse_constant=_reject_wallet_constant)
    return decrypt_mnemonic(data, passphrase)

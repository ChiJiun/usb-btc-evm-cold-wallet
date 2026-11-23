"""Socket-free Linux fbdev/VT transaction review frontend.

The rendering path accepts an already-verified ReviewPlan and returns a
ReviewIntent without wallet keys or signing. A narrow authorization adapter can
bind a confirmed intent to the existing SignerSession only after rebuilding the
same ReviewPlan and repeating the runtime audit. Linux VT/fbdev/evdev operations
use only local device/ioctl/mmap primitives and do not require CONFIG_NET,
AF_UNIX, X11, Wayland, SDL, or any network socket family.
"""
from __future__ import annotations

import array
from dataclasses import dataclass
import fcntl
import hashlib
import math
import mmap
import os
from pathlib import Path
import re
import select
import stat
import struct
import time
import termios
import tty
from typing import Callable

from .review import ReviewField, ReviewPage, ReviewPlan, _canonical, _review_document
from .signer_session import DEFAULT_IDLE_SECONDS, MAX_IDLE_SECONDS, SignerSession

# linux/fb.h
FBIOGET_VSCREENINFO = 0x4600
FBIOGET_FSCREENINFO = 0x4602
# linux/kd.h
KDSETMODE = 0x4B3A
KDGETMODE = 0x4B3B
KD_TEXT = 0x00
KD_GRAPHICS = 0x01
# linux/vt.h
VT_GETSTATE = 0x5603
VT_LOCKSWITCH = 0x560B
VT_UNLOCKSWITCH = 0x560C

# linux/input-event-codes.h / linux/input.h
EV_KEY = 0x01
KEY_ESC = 1
KEY_C = 46
KEY_ENTER = 28
KEY_UP = 103
KEY_LEFT = 105
KEY_RIGHT = 106
KEY_DOWN = 108
_INPUT_EVENT = struct.Struct("@llHHi")

PSF2_MAGIC = 0x864AB572
MAX_PLAN_CHARS = 256 * 1024
MAX_PAGES = 64
_SECRET_FIELD_MARKERS = (
    "mnemonic",
    "passphrase",
    "private key",
    "private_key",
    "xprv",
    "seed phrase",
    "seed_phrase",
)


@dataclass(frozen=True)
class ReviewIntent:
    """Non-authorizing result from the display-only POC."""

    review_digest: str
    reviewed: bool
    reason: str


class InputDeviceChanged(OSError):
    """Input topology changed during an attended review."""


def _decode_evdev(data: bytes) -> str:
    """Decode one or more Linux input_event records into a reviewed action."""
    if not data or len(data) % _INPUT_EVENT.size:
        raise OSError("Malformed evdev input record")
    for offset in range(0, len(data), _INPUT_EVENT.size):
        _sec, _usec, event_type, code, value = _INPUT_EVENT.unpack_from(data, offset)
        if event_type != EV_KEY:
            continue
        if value == 1:
            action = {
                KEY_ESC: "ESC",
                KEY_ENTER: "ENTER",
                KEY_C: "CONFIRM",
                KEY_UP: "UP",
                KEY_DOWN: "DOWN",
                KEY_LEFT: "LEFT",
                KEY_RIGHT: "RIGHT",
            }.get(code)
            if action:
                return action
        if value == 2:
            action = {
                KEY_UP: "UP",
                KEY_DOWN: "DOWN",
                KEY_LEFT: "LEFT",
                KEY_RIGHT: "RIGHT",
            }.get(code)
            if action:
                return action
    return ""


class EvdevInput:
    """Fail-closed keyboard input directly from /dev/input/event*.

    Mouse/button events are deliberately unsupported in this minimal frontend:
    only the reviewed keyboard keycodes above can navigate or confirm.
    """

    def __init__(self, directory: Path = Path("/dev/input")):
        self.directory = directory
        self.paths: tuple[str, ...] = ()
        self._fds: dict[int, str] = {}
        self._identities: dict[str, tuple[int, int, int]] = {}

    def _discover(self) -> tuple[str, ...]:
        try:
            candidates = [
                str(path)
                for path in self.directory.glob("event*")
                if path.name[5:].isdigit()
            ]
        except OSError as exc:
            raise OSError("Unable to enumerate evdev input devices") from exc
        return tuple(sorted(candidates))

    def __enter__(self) -> "EvdevInput":
        self.paths = self._discover()
        if not self.paths:
            raise OSError("No /dev/input/event* device available")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            for path in self.paths:
                fd = os.open(path, flags)
                stat = os.fstat(fd)
                self._fds[fd] = path
                self._identities[path] = (stat.st_dev, stat.st_ino, stat.st_rdev)
        except Exception:
            self.close()
            raise
        return self

    def close(self) -> None:
        for fd in tuple(self._fds):
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds.clear()
        self._identities.clear()

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    def _assert_stable(self) -> None:
        if self._discover() != self.paths:
            raise InputDeviceChanged("Input device set changed during review")
        for path, expected in self._identities.items():
            try:
                stat = os.stat(path, follow_symlinks=False)
            except OSError as exc:
                raise InputDeviceChanged("Input device disappeared during review") from exc
            current = (stat.st_dev, stat.st_ino, stat.st_rdev)
            if current != expected:
                raise InputDeviceChanged("Input device identity changed during review")

    def drain(self) -> None:
        """Discard input queued before the current stable rendered frame."""
        self._assert_stable()
        for fd in tuple(self._fds):
            while True:
                try:
                    data = os.read(fd, _INPUT_EVENT.size)
                except BlockingIOError:
                    break
                except OSError as exc:
                    raise InputDeviceChanged("Input device disappeared during review") from exc
                if not data:
                    raise InputDeviceChanged("Input device disappeared during review")
                if len(data) != _INPUT_EVENT.size:
                    raise OSError("Malformed evdev input record")
        self._assert_stable()

    def read_key(self, timeout: float = 1.0) -> str:
        self._assert_stable()
        ready, _, _ = select.select(tuple(self._fds), [], [], timeout)
        if not ready:
            self._assert_stable()
            return ""
        for fd in ready:
            try:
                data = os.read(fd, _INPUT_EVENT.size)
            except BlockingIOError:
                continue
            except OSError as exc:
                raise InputDeviceChanged("Input device disappeared during review") from exc
            if not data:
                raise InputDeviceChanged("Input device disappeared during review")
            action = _decode_evdev(data)
            if action:
                return action
        self._assert_stable()
        return ""


def _validate_plan(plan: ReviewPlan) -> None:
    if type(plan) is not ReviewPlan:
        raise TypeError("Framebuffer UI accepts only the exact existing ReviewPlan type")
    if type(plan.pages) is not tuple or not 1 <= len(plan.pages) <= MAX_PAGES:
        raise ValueError("ReviewPlan page count outside display bounds")
    if not re.fullmatch(r"[0-9a-f]{64}", plan.review_digest):
        raise ValueError("ReviewPlan digest is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", plan.request_digest):
        raise ValueError("ReviewPlan request digest is invalid")
    if len(plan.pages) < 2 or plan.pages[1].key != "integrity":
        raise ValueError("ReviewPlan integrity page is missing")
    integrity = plan.pages[1]
    expected_integrity = (
        ReviewField("request_digest", plan.request_digest, "verified exchange envelope.sha256"),
        ReviewField("review_digest", plan.review_digest, "SHA-256(canonical offline reviewed fields)"),
    )
    if integrity.fields != expected_integrity:
        raise ValueError("ReviewPlan integrity page is inconsistent")
    reviewed_pages = (plan.pages[0], *plan.pages[2:])
    calculated = hashlib.sha256(
        _canonical(_review_document(plan.kind, plan.request_digest, reviewed_pages))
    ).hexdigest()
    if calculated != plan.review_digest:
        raise ValueError("ReviewPlan pages do not match review digest")
    total = 0
    for page in plan.pages:
        if type(page) is not ReviewPage or type(page.fields) is not tuple or not page.fields:
            raise TypeError("ReviewPlan contains non-canonical page objects")
        for value in (page.key,):
            if type(value) is not str:
                raise TypeError("ReviewPlan contains non-text display metadata")
            if any(ord(ch) < 32 or ord(ch) > 126 for ch in value):
                raise ValueError("ReviewPlan contains non-ASCII display metadata")
            total += len(value)
        for field in page.fields:
            if type(field) is not ReviewField:
                raise TypeError("ReviewPlan contains non-canonical field objects")
            values = (field.key, field.value, field.source)
            if not all(type(value) is str for value in values):
                raise TypeError("ReviewPlan contains non-text display fields")
            if any(any(ord(ch) < 32 or ord(ch) > 126 for ch in value) for value in values):
                raise ValueError("ReviewPlan contains characters this font cannot represent exactly")
            normalized = (field.key + " " + field.source).lower()
            if any(marker in normalized for marker in _SECRET_FIELD_MARKERS):
                raise ValueError("Secret-bearing fields must never enter framebuffer review")
            total += len(field.key) + len(field.value) + len(field.source)
            if total > MAX_PLAN_CHARS:
                raise ValueError("ReviewPlan exceeds framebuffer display bound")


def load_psf2(path: Path) -> tuple[int, int, bytes]:
    """Load the single reviewed 8x16, 256-slot direct-index PSF2 format."""
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("PSF2 header missing")
    magic, version, header_size, flags, length, charsize, height, width = struct.unpack_from("<8I", data)
    expected = header_size + length * charsize
    if (
        magic != PSF2_MAGIC
        or version != 0
        or header_size != 32
        or flags != 0
        or length != 256
        or charsize != 16
        or height != 16
        or width != 8
        or len(data) != expected
    ):
        raise ValueError("Unsupported PSF2 bitmap font")
    return width, height, data[header_size:]


class Surface:
    def __init__(self, width: int, height: int, font: tuple[int, int, bytes]):
        if not 320 <= width <= 4096 or not 240 <= height <= 2160:
            raise ValueError("Unsupported framebuffer geometry")
        if width * height > 8_847_360:
            raise ValueError("Framebuffer exceeds bounded render surface")
        self.width, self.height, self.font = width, height, font
        self.pixels = bytearray(width * height * 4)

    def rect(self, x: int, y: int, w: int, h: int, rgb: tuple[int, int, int]) -> None:
        r, g, b = rgb
        left, right = max(0, x), min(self.width, x + w)
        top, bottom = max(0, y), min(self.height, y + h)
        if right <= left or bottom <= top:
            return
        pixel = bytes((b, g, r, 0))
        row = pixel * (right - left)
        for yy in range(top, bottom):
            start = (yy * self.width + left) * 4
            self.pixels[start:start + len(row)] = row

    def text(self, x: int, y: int, value: str, rgb=(240, 242, 246)) -> None:
        fw, fh, glyphs = self.font
        stride = (fw + 7) // 8
        b, g, r = rgb[2], rgb[1], rgb[0]
        for ch in value:
            code = ord(ch)
            if code > 127 or code < 32:
                code = ord("?")
            glyph = glyphs[code * stride * fh:(code + 1) * stride * fh]
            for gy in range(fh):
                yy = y + gy
                if yy < 0 or yy >= self.height:
                    continue
                for gx in range(fw):
                    xx = x + gx
                    if xx < 0 or xx >= self.width:
                        continue
                    if glyph[gy * stride + gx // 8] & (0x80 >> (gx % 8)):
                        offset = (yy * self.width + xx) * 4
                        self.pixels[offset:offset + 4] = bytes((b, g, r, 0))
            x += fw
            if x >= self.width:
                break

    def ppm(self) -> bytes:
        """Offscreen test helper only; never accepted as guest GUI evidence."""
        out = bytearray(f"P6\n{self.width} {self.height}\n255\n".encode())
        for i in range(0, len(self.pixels), 4):
            b, g, r, _ = self.pixels[i:i + 4]
            out.extend((r, g, b))
        return bytes(out)


def _wrapped_lines(plan: ReviewPlan, page_index: int, columns: int) -> list[str]:
    if columns < 8:
        raise ValueError("Insufficient display width")
    page = plan.pages[page_index]
    content = [f"PAGE {page_index + 1}/{len(plan.pages)}: {page.key}", ""]
    for field in page.fields:
        content.extend((field.key + " [" + field.source + "]", field.value, ""))
    wrapped: list[str] = []
    for line in content:
        if not line:
            wrapped.append("")
        else:
            wrapped.extend(line[i:i + columns] for i in range(0, len(line), columns))
    return wrapped


def render_review(
    surface: Surface,
    plan: ReviewPlan,
    page_index: int,
    line_offset: int = 0,
    *,
    acknowledged: bool = False,
    locked: bool = False,
    confirm_ready: bool = False,
) -> int:
    """Render a complete ReviewPlan page and return its wrapped line count."""
    _validate_plan(plan)
    if not 0 <= page_index < len(plan.pages) or line_offset < 0:
        raise ValueError("Invalid review page/scroll position")
    surface.rect(0, 0, surface.width, surface.height, (17, 25, 39))
    fw, fh, _ = surface.font
    pad = 18
    columns = (surface.width - pad * 2) // fw
    surface.rect(0, 0, surface.width, 57, (28, 49, 76))
    surface.text(pad, 12, "OFFLINE / TESTNET / VERIFY ON THIS SCREEN", (255, 222, 147))
    if locked:
        surface.text(pad, 85, "LOCKED - REVIEW INTENT DISABLED", (255, 130, 130))
        return 0

    wrapped = _wrapped_lines(plan, page_index, columns)
    visible = max(1, (surface.height - 160) // (fh + 3))
    for index, line in enumerate(wrapped[line_offset:line_offset + visible]):
        surface.text(pad, 70 + index * (fh + 3), line)

    surface.rect(0, surface.height - 66, surface.width, 66, (28, 49, 76))
    surface.text(pad, surface.height - 56, "UP/DOWN scroll  LEFT/RIGHT pages  ESC cancel", (255, 222, 147))
    state = "ACKNOWLEDGED" if acknowledged else "REVIEW REQUIRED"
    if confirm_ready:
        surface.text(pad, surface.height - 32, "C: CONFIRM REVIEW  ESC: REJECT", (255, 222, 147))
    else:
        surface.text(pad, surface.height - 32, "ENTER: acknowledge page  " + state, (255, 222, 147))
    return len(wrapped)


class ReviewController:
    """Display acknowledgement only; no signer authorization is produced."""

    def __init__(
        self,
        plan: ReviewPlan,
        *,
        audit: Callable[[], bool],
        clock: Callable[[], float] = time.monotonic,
        idle_seconds: int = DEFAULT_IDLE_SECONDS,
    ):
        _validate_plan(plan)
        if type(idle_seconds) is not int or not 0 < idle_seconds <= MAX_IDLE_SECONDS:
            raise ValueError("Framebuffer idle timeout must be in 1..600 seconds")
        self.plan = plan
        self.audit = audit
        self.clock = clock
        self.idle_seconds = idle_seconds
        self.page = 0
        self.offset = 0
        self.seen: set[int] = set()
        self.cancelled = False
        self.locked = False
        self.lock_reason: str | None = None
        self.scroll_bottom = 0
        # This display-only controller cannot extend SignerSession lifetime.
        # Invalid clocks fail closed before opening the virtual terminal.
        self.last_activity = self._checked_clock()

    def _checked_clock(self) -> float:
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("Invalid monotonic clock")
        return float(now)

    def fail_closed(self, reason: str) -> None:
        self.locked = True
        self.lock_reason = reason
        self.seen.clear()

    def _audit_ok(self) -> bool:
        try:
            return self.audit() is True
        except Exception:
            return False

    def action(self, key: str) -> bool:
        if self.cancelled or self.locked:
            return False
        try:
            now = self._checked_clock()
        except Exception:
            self.fail_closed("clock_failed")
            return False
        if now < self.last_activity:
            self.fail_closed("clock_reversed")
            return False
        if now - self.last_activity >= self.idle_seconds:
            self.fail_closed("idle_timeout")
            return False
        if key == "ESC":
            self.cancelled = True
            self.seen.clear()
            return False
        if not self._audit_ok():
            self.fail_closed("audit_failed")
            return False
        if key in ("LEFT", "RIGHT", "DOWN", "UP", "ENTER", "CONFIRM"):
            self.last_activity = now
        if key == "LEFT":
            self.page = max(0, self.page - 1)
            self.offset = 0
        elif key == "RIGHT":
            self.page = min(len(self.plan.pages) - 1, self.page + 1)
            self.offset = 0
        elif key == "DOWN":
            self.offset = min(self.scroll_bottom, self.offset + 1)
        elif key == "UP":
            self.offset = max(0, self.offset - 1)
        elif key == "ENTER":
            if self.offset < self.scroll_bottom:
                return False
            self.seen.add(self.page)
            return False
        elif key == "CONFIRM":
            return (
                self.page == len(self.plan.pages) - 1
                and self.offset >= self.scroll_bottom
                and self.seen == set(range(len(self.plan.pages)))
            )
        return False


def _fb_geometry(fd: int) -> tuple[int, int, int, int]:
    vi = bytearray(160)
    fi = bytearray(80)
    fcntl.ioctl(fd, FBIOGET_VSCREENINFO, vi, True)
    fcntl.ioctl(fd, FBIOGET_FSCREENINFO, fi, True)
    xres, yres, xv, yv, xoff, yoff, bpp = struct.unpack_from("<7I", vi, 0)
    # struct fb_fix_screeninfo on x86_64: smem_len @ 24, line_length @ 48.
    smem_len = struct.unpack_from("<I", fi, 24)[0]
    line_length = struct.unpack_from("<I", fi, 48)[0]
    if (
        xoff
        or yoff
        or xres != xv
        or yres != yv
        or bpp not in (16, 32)
        or line_length < xres * (bpp // 8)
        or smem_len < line_length * yres
    ):
        raise ValueError("Unsupported framebuffer pixel layout")
    rgb = tuple(struct.unpack_from("<III", vi, offset) for offset in (32, 44, 56))
    if bpp == 32 and rgb != ((16, 8, 0), (8, 8, 0), (0, 8, 0)):
        raise ValueError("Unexpected XRGB8888 bitfields")
    if bpp == 16 and rgb != ((11, 5, 0), (5, 6, 0), (0, 5, 0)):
        raise ValueError("Unexpected RGB565 bitfields")
    return xres, yres, bpp, line_length


def _discover_framebuffer(fb_path: str | None = None, dev_root: Path = Path("/dev")) -> str:
    if fb_path is not None:
        return fb_path
    try:
        candidates = tuple(
            sorted(str(path) for path in dev_root.glob("fb*") if path.name[2:].isdigit())
        )
    except OSError as exc:
        raise OSError("Unable to enumerate framebuffer devices") from exc
    if len(candidates) != 1:
        raise OSError("Exactly one framebuffer device is required")
    return candidates[0]


def _open_framebuffer(fb_path: str, expected_identity: tuple[int, int, int] | None = None):
    """Pin the character device across every draw and final blank operation."""
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(fb_path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISCHR(info.st_mode):
            raise OSError("Framebuffer must be a character device")
        identity = (info.st_dev, info.st_ino, info.st_rdev)
        if expected_identity is not None and identity != expected_identity:
            raise OSError("Framebuffer device identity changed during review")
        return os.fdopen(fd, "r+b", buffering=0), identity
    except BaseException:
        os.close(fd)
        raise


def present(surface: Surface, fb_path: str = "/dev/fb0", *,
            expected_identity: tuple[int, int, int] | None = None) -> None:
    device, _ = _open_framebuffer(fb_path, expected_identity)
    with device:
        width, height, bpp, stride = _fb_geometry(device.fileno())
        if (width, height) != (surface.width, surface.height):
            raise ValueError("Framebuffer dimensions changed")
        data = surface.pixels
        with mmap.mmap(device.fileno(), stride * height, access=mmap.ACCESS_WRITE) as memory:
            for y in range(height):
                out = y * stride
                if bpp == 32:
                    memory[out:out + width * 4] = data[y * width * 4:(y + 1) * width * 4]
                else:
                    row = bytearray(width * 2)
                    for x in range(width):
                        i = (y * width + x) * 4
                        b, g, r = data[i:i + 3]
                        struct.pack_into("<H", row, x * 2, ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3))
                    memory[out:out + len(row)] = row


def _clear_framebuffer(fb_path: str, *,
                       expected_identity: tuple[int, int, int] | None = None) -> None:
    device, _ = _open_framebuffer(fb_path, expected_identity)
    with device:
        width, height, bpp, stride = _fb_geometry(device.fileno())
        row = bytes(width * (bpp // 8))
        with mmap.mmap(device.fileno(), stride * height, access=mmap.ACCESS_WRITE) as memory:
            for y in range(height):
                start = y * stride
                memory[start:start + len(row)] = row


def _tty_number(tty_path: str) -> int:
    match = re.fullmatch(r"/dev/tty([1-9][0-9]*)", tty_path)
    if not match:
        raise ValueError("A dedicated kernel virtual terminal is required")
    return int(match.group(1))


def _vt_is_active(fd: int, expected: int) -> bool:
    state = array.array("H", [0, 0, 0])
    fcntl.ioctl(fd, VT_GETSTATE, state, True)
    return state[0] == expected


def _get_kd_mode(fd: int) -> int:
    mode = array.array("i", [0])
    fcntl.ioctl(fd, KDGETMODE, mode, True)
    if mode[0] not in (KD_TEXT, KD_GRAPHICS):
        raise OSError("Unexpected VT display mode")
    return mode[0]


def _read_key(fd: int, timeout: float = 1.0) -> str:
    ready, _, _ = select.select([fd], [], [], timeout)
    if not ready:
        return ""
    first = os.read(fd, 1)
    if first in (b"\r", b"\n"):
        return "ENTER"
    if first != b"\x1b":
        return ""
    # Distinguish a lone Escape from split ANSI cursor sequences. Any malformed
    # or truncated escape sequence is treated as cancel, never as approval.
    ready, _, _ = select.select([fd], [], [], 0.05)
    if not ready:
        return "ESC"
    second = os.read(fd, 1)
    if second != b"[":
        return "ESC"
    ready, _, _ = select.select([fd], [], [], 0.05)
    if not ready:
        return "ESC"
    third = os.read(fd, 1)
    return {b"A": "UP", b"B": "DOWN", b"C": "RIGHT", b"D": "LEFT"}.get(third, "ESC")


def authorize_review_intent(
    plan: ReviewPlan,
    intent: ReviewIntent,
    signer: SignerSession,
    *,
    rebuild_plan: Callable[[], ReviewPlan],
    audit: Callable[[], bool],
) -> bool:
    """Bind human framebuffer confirmation to the existing SignerSession.

    The frontend still never handles wallet keys or signs.  The caller must
    have started this exact digest with SignerSession.start_review() before
    rendering, and must call SignerSession.signing() only after this returns
    True.  A fresh backend rebuild is required immediately before approval.
    """
    _validate_plan(plan)
    if not isinstance(signer, SignerSession):
        raise TypeError("Existing SignerSession is required")
    if type(intent) is not ReviewIntent:
        signer.lock("invalid_review_intent")
        raise TypeError("Canonical ReviewIntent is required")
    if not intent.reviewed:
        signer.lock("review_rejected")
        return False
    try:
        if intent.review_digest != plan.review_digest:
            raise ValueError("Framebuffer review digest changed")
        fresh = rebuild_plan()
        _validate_plan(fresh)
        if fresh != plan:
            raise ValueError("Transaction changed after framebuffer review")
        if audit() is not True:
            raise ValueError("Offline runtime safety audit failed before approval")
        signer.approve(plan.review_digest)
    except Exception as exc:
        signer.lock("framebuffer_authorization_failed")
        if isinstance(exc, (ValueError, TypeError)):
            raise
        raise ValueError("Framebuffer authorization failed closed") from exc
    return True


def _restore_tty_input(fd: int, original_settings: list) -> None:
    """Discard GUI keystrokes before restoring the appliance's line input.

    evdev and tty1 see the same physical key. The last GUI confirmation or
    cancel key can remain buffered by tty1 even after evdev consumes it;
    handing those bytes to the menu can corrupt the next menu choice.
    """
    flush_error = None
    try:
        termios.tcflush(fd, termios.TCIFLUSH)
    except Exception as exc:
        flush_error = exc
    try:
        # TCSAFLUSH also discards unread input during the mode transition.
        termios.tcsetattr(fd, termios.TCSAFLUSH, original_settings)
    except Exception as exc:
        raise RuntimeError("Unable to restore terminal mode") from exc
    if flush_error is not None:
        raise RuntimeError("Unable to clear buffered GUI keyboard input") from flush_error


def run_vt(
    plan: ReviewPlan,
    font_path: Path,
    *,
    audit: Callable[[], bool],
    tty_path: str = "/dev/tty1",
    fb_path: str | None = None,
    input_directory: Path = Path("/dev/input"),
    on_ready: Callable[[], None] | None = None,
    on_frame: Callable[[int, int, int, bool], None] | None = None,
    on_lifecycle: Callable[[str], None] | None = None,
) -> ReviewIntent:
    """Render a verified plan on the active VT and return non-signing intent."""
    _validate_plan(plan)
    try:
        initial_audit_ok = audit() is True
    except Exception:
        initial_audit_ok = False
    if not initial_audit_ok:
        return ReviewIntent(plan.review_digest, False, "audit_failed")
    font = load_psf2(font_path)
    fb_path = _discover_framebuffer(fb_path)
    fb, framebuffer_identity = _open_framebuffer(fb_path)
    with fb:
        width, height, _, _ = _fb_geometry(fb.fileno())
    display = Surface(width, height, font)
    controller = ReviewController(plan, audit=audit)
    tty_number = _tty_number(tty_path)

    with open(tty_path, "rb", buffering=0) as keyboard, EvdevInput(input_directory) as inputs:
        fd = keyboard.fileno()
        old_termios = termios.tcgetattr(fd)
        old_kd_mode = _get_kd_mode(fd)
        vt_locked = False
        cleanup_error: Exception | None = None
        try:
            if not _vt_is_active(fd, tty_number):
                raise OSError("Requested VT is not active")
            if on_lifecycle is not None:
                on_lifecycle("input_attached")
            fcntl.ioctl(fd, VT_LOCKSWITCH, 0)
            vt_locked = True
            tty.setraw(fd)
            fcntl.ioctl(fd, KDSETMODE, KD_GRAPHICS)
            if on_lifecycle is not None:
                on_lifecycle("vt_acquired")
            ready_reported = False
            last_reported_frame: tuple[int, int, int, bool] | None = None
            # Discard any input queued before the first stable frame and after
            # every visual state change. Approval cannot ride behind a
            # navigation/scroll key while the next frame is still being drawn.
            discard_queued_input = True
            while not controller.cancelled and not controller.locked:
                if not _vt_is_active(fd, tty_number):
                    controller.fail_closed("vt_failed")
                    break
                if not controller._audit_ok():
                    controller.fail_closed("audit_failed")
                    break
                total = render_review(
                    display,
                    plan,
                    controller.page,
                    controller.offset,
                    acknowledged=controller.page in controller.seen,
                    confirm_ready=(
                        controller.page == len(plan.pages) - 1
                        and controller.seen == set(range(len(plan.pages)))
                    ),
                )
                visible = max(1, (height - 160) // (font[1] + 3))
                controller.scroll_bottom = max(0, total - visible)
                controller.offset = min(controller.offset, controller.scroll_bottom)
                present(display, fb_path, expected_identity=framebuffer_identity)
                if discard_queued_input:
                    inputs.drain()
                    termios.tcflush(fd, termios.TCIFLUSH)
                    discard_queued_input = False
                if not ready_reported and on_ready is not None:
                    on_ready()
                    ready_reported = True
                # Report completed frames only; no request values or wallet material.
                frame_state = (controller.page + 1, controller.offset,
                               controller.scroll_bottom, controller.page in controller.seen)
                if on_frame is not None and frame_state != last_reported_frame:
                    on_frame(*frame_state)
                    last_reported_frame = frame_state
                try:
                    key = inputs.read_key()
                except InputDeviceChanged:
                    controller.fail_closed("input_changed")
                    if on_lifecycle is not None:
                        on_lifecycle("input_changed")
                    break
                before = (controller.page, controller.offset, frozenset(controller.seen))
                if controller.action(key):
                    # The final approval is also bound to live evdev, VT,
                    # runtime audit and framebuffer identity, not only the
                    # previous rendered frame. Any failure discards intent.
                    try:
                        inputs._assert_stable()
                    except InputDeviceChanged:
                        controller.fail_closed("input_changed")
                        if on_lifecycle is not None:
                            on_lifecycle("input_changed")
                        break
                    if not _vt_is_active(fd, tty_number):
                        raise OSError("VT changed before approval")
                    if not controller._audit_ok():
                        raise OSError("Runtime audit failed before approval")
                    check, _ = _open_framebuffer(fb_path, framebuffer_identity)
                    check.close()
                    return ReviewIntent(plan.review_digest, True, "reviewed")
                after = (controller.page, controller.offset, frozenset(controller.seen))
                if after != before:
                    discard_queued_input = True
            reason = "cancelled" if controller.cancelled else (controller.lock_reason or "fail_closed")
            return ReviewIntent(plan.review_digest, False, reason)
        finally:
            # A reviewed result is suppressed if secure cleanup cannot complete.
            try:
                _clear_framebuffer(fb_path, expected_identity=framebuffer_identity)
            except Exception as exc:
                cleanup_error = exc
            try:
                fcntl.ioctl(fd, KDSETMODE, old_kd_mode)
            except Exception as exc:
                cleanup_error = cleanup_error or exc
            if vt_locked:
                try:
                    fcntl.ioctl(fd, VT_UNLOCKSWITCH, 0)
                except Exception as exc:
                    cleanup_error = cleanup_error or exc
            try:
                _restore_tty_input(fd, old_termios)
            except Exception as exc:
                cleanup_error = cleanup_error or exc
            if on_lifecycle is not None:
                on_lifecycle("vt_released" if cleanup_error is None else "vt_release_failed")
            if cleanup_error is not None:
                raise RuntimeError("Framebuffer/VT cleanup failed; review intent discarded") from cleanup_error

"""Socket-free Linux fbdev/VT transaction review frontend.

This module is intentionally limited to rendering an already-verified
ReviewPlan and returning a ReviewIntent. It never parses a transaction, handles
wallet secrets, calls SignerSession, or signs. Linux VT/fbdev operations use
only local device/ioctl/mmap primitives and do not require CONFIG_NET, AF_UNIX,
X11, Wayland, SDL, or any network socket family.
"""
from __future__ import annotations

import array
from dataclasses import dataclass
import fcntl
import mmap
import os
from pathlib import Path
import re
import select
import struct
import termios
import tty
from typing import Callable

from .review import ReviewPlan

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


def _validate_plan(plan: ReviewPlan) -> None:
    if not isinstance(plan, ReviewPlan):
        raise TypeError("Framebuffer UI accepts only the existing ReviewPlan type")
    if not 1 <= len(plan.pages) <= MAX_PAGES:
        raise ValueError("ReviewPlan page count outside display bounds")
    if not re.fullmatch(r"[0-9a-f]{64}", plan.review_digest):
        raise ValueError("ReviewPlan digest is invalid")
    total = 0
    for page in plan.pages:
        if not page.fields:
            raise ValueError("ReviewPlan contains an empty page")
        for value in (page.key,):
            if type(value) is not str:
                raise TypeError("ReviewPlan contains non-text display metadata")
            total += len(value)
        for field in page.fields:
            if not all(type(value) is str for value in (field.key, field.value, field.source)):
                raise TypeError("ReviewPlan contains non-text display fields")
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
    surface.text(pad, surface.height - 32, "ENTER: acknowledge page  " + state, (255, 222, 147))
    return len(wrapped)


class ReviewController:
    """Display acknowledgement only; no signer authorization is produced."""

    def __init__(self, plan: ReviewPlan, *, audit: Callable[[], bool]):
        _validate_plan(plan)
        self.plan = plan
        self.audit = audit
        self.page = 0
        self.offset = 0
        self.seen: set[int] = set()
        self.cancelled = False
        self.locked = False
        self.scroll_bottom = 0

    def _audit_ok(self) -> bool:
        try:
            return self.audit() is True
        except Exception:
            return False

    def action(self, key: str) -> bool:
        if self.cancelled or self.locked:
            return False
        if key == "ESC":
            self.cancelled = True
            return False
        if not self._audit_ok():
            self.locked = True
            return False
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
            return len(self.seen) == len(self.plan.pages)
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


def present(surface: Surface, fb_path: str = "/dev/fb0") -> None:
    with open(fb_path, "r+b", buffering=0) as device:
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


def _clear_framebuffer(fb_path: str) -> None:
    with open(fb_path, "r+b", buffering=0) as device:
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


def run_vt(
    plan: ReviewPlan,
    font_path: Path,
    *,
    audit: Callable[[], bool],
    tty_path: str = "/dev/tty1",
    fb_path: str = "/dev/fb0",
    on_ready: Callable[[], None] | None = None,
) -> ReviewIntent:
    """Render a verified plan on the active VT and return non-signing intent."""
    _validate_plan(plan)
    if audit() is not True:
        return ReviewIntent(plan.review_digest, False, "audit_failed")
    font = load_psf2(font_path)
    with open(fb_path, "r+b", buffering=0) as fb:
        width, height, _, _ = _fb_geometry(fb.fileno())
    display = Surface(width, height, font)
    controller = ReviewController(plan, audit=audit)
    tty_number = _tty_number(tty_path)

    with open(tty_path, "rb", buffering=0) as keyboard:
        fd = keyboard.fileno()
        old_termios = termios.tcgetattr(fd)
        old_kd_mode = _get_kd_mode(fd)
        vt_locked = False
        cleanup_error: Exception | None = None
        try:
            if not _vt_is_active(fd, tty_number):
                raise OSError("Requested VT is not active")
            fcntl.ioctl(fd, VT_LOCKSWITCH, 0)
            vt_locked = True
            tty.setraw(fd)
            fcntl.ioctl(fd, KDSETMODE, KD_GRAPHICS)
            ready_reported = False
            while not controller.cancelled and not controller.locked:
                if not _vt_is_active(fd, tty_number):
                    controller.locked = True
                    break
                if not controller._audit_ok():
                    controller.locked = True
                    break
                total = render_review(
                    display,
                    plan,
                    controller.page,
                    controller.offset,
                    acknowledged=controller.page in controller.seen,
                )
                visible = max(1, (height - 160) // (font[1] + 3))
                controller.scroll_bottom = max(0, total - visible)
                controller.offset = min(controller.offset, controller.scroll_bottom)
                present(display, fb_path)
                if not ready_reported and on_ready is not None:
                    on_ready()
                    ready_reported = True
                key = _read_key(fd)
                if controller.action(key):
                    return ReviewIntent(plan.review_digest, True, "reviewed")
            reason = "cancelled" if controller.cancelled else "audit_or_vt_failed"
            return ReviewIntent(plan.review_digest, False, reason)
        finally:
            # A reviewed result is suppressed if secure cleanup cannot complete.
            try:
                _clear_framebuffer(fb_path)
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
                termios.tcsetattr(fd, termios.TCSANOW, old_termios)
            except Exception as exc:
                cleanup_error = cleanup_error or exc
            if cleanup_error is not None:
                raise RuntimeError("Framebuffer/VT cleanup failed; review intent discarded") from cleanup_error

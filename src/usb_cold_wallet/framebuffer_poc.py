"""Dependency-free Linux fbdev review display POC (no X11/AF_UNIX/network).

No signer or secret handling lives here. The caller must build a verified
ReviewPlan and enforce SignerSession / policy checks before any real signature.
Requires a locally provisioned PSF2 bitmap font and an RGB565 or XRGB8888
framebuffer. Keyboard events are read from a dedicated Linux VT.
"""
from __future__ import annotations

import array
import fcntl
import mmap
import os
from pathlib import Path
import select
import struct
import termios
import tty

# Linux fb.h: FBIOGET_VSCREENINFO, FBIOGET_FSCREENINFO
FBIOGET_VSCREENINFO = 0x4600
FBIOGET_FSCREENINFO = 0x4602
PSF2_MAGIC = 0x864AB572


def load_psf2(path: Path) -> tuple[int, int, bytes]:
    """Accept only 256/512 glyph PSF2 fixed-size bitmap fonts with ASCII slots."""
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("PSF2 header missing")
    magic, version, header_size, flags, length, charsize, height, width = struct.unpack_from("<8I", data)
    if (magic != PSF2_MAGIC or version != 0 or not 32 <= header_size <= 4096
            or not 1 <= width <= 16 or not 8 <= height <= 32
            or length not in (256, 512) or charsize != ((width + 7) // 8) * height
            or len(data) < header_size + length * charsize or flags & ~1):
        raise ValueError("Unsupported PSF2 bitmap font")
    # For this POC glyph index must equal ASCII code point. Unicode-mapped
    # fonts with arbitrary glyph ordering are deliberately not accepted.
    if flags:
        raise ValueError("POC requires a direct ASCII indexed PSF2 font")
    return width, height, data[header_size:header_size + length * charsize]


class Surface:
    def __init__(self, width: int, height: int, font: tuple[int, int, bytes]):
        if not 320 <= width <= 4096 or not 240 <= height <= 2160:
            raise ValueError("Unsupported framebuffer geometry")
        self.width, self.height, self.font = width, height, font
        self.pixels = bytearray(width * height * 4)

    def rect(self, x: int, y: int, w: int, h: int, rgb: tuple[int, int, int]):
        r, g, b = rgb
        for yy in range(max(0, y), min(self.height, y + h)):
            for xx in range(max(0, x), min(self.width, x + w)):
                i = (yy * self.width + xx) * 4
                self.pixels[i:i + 4] = bytes((b, g, r, 0))

    def text(self, x: int, y: int, value: str, rgb=(240, 242, 246)):
        fw, fh, glyphs = self.font
        stride = (fw + 7) // 8
        for ch in value:
            code = ord(ch)
            if code > 127 or code < 32:
                code = ord("?")
            glyph = glyphs[code * stride * fh:(code + 1) * stride * fh]
            for gy in range(fh):
                for gx in range(fw):
                    if glyph[gy * stride + gx // 8] & (0x80 >> (gx % 8)):
                        self.rect(x + gx, y + gy, 1, 1, rgb)
            x += fw

    def lines(self, x: int, y: int, content: str, max_columns: int, rgb=(240, 242, 246)):
        # No security-critical text is elided: wrap even very long digest/address fields.
        if max_columns < 8:
            raise ValueError("Insufficient display width")
        for line in content.split("\n"):
            if not line:
                y += self.font[1] + 3
            while line:
                self.text(x, y, line[:max_columns], rgb)
                line = line[max_columns:]
                y += self.font[1] + 3
        return y

    def ppm(self) -> bytes:
        # Offscreen debugging evidence only; not proof that a guest displayed it.
        out = bytearray(f"P6\n{self.width} {self.height}\n255\n".encode())
        for i in range(0, len(self.pixels), 4):
            b, g, r, _ = self.pixels[i:i + 4]
            out.extend((r, g, b))
        return bytes(out)


def render_review(surface: Surface, plan, page_index: int, line_offset: int = 0,
                  *, acknowledged: bool = False, locked: bool = False) -> int:
    """Render a review page. Return total body line count for scrolling."""
    surface.rect(0, 0, surface.width, surface.height, (17, 25, 39))
    fw, fh, _ = surface.font
    pad = 18
    cols = (surface.width - pad * 2) // fw
    surface.rect(0, 0, surface.width, 57, (28, 49, 76))
    surface.text(pad, 12, "OFFLINE / TESTNET / VERIFY ON THIS SCREEN", (255, 222, 147))
    if locked:
        surface.text(pad, 85, "LOCKED - SIGNING DISABLED", (255, 130, 130))
        return 0
    if not 0 <= page_index < len(plan.pages) or line_offset < 0:
        raise ValueError("Invalid review page/scroll position")
    page = plan.pages[page_index]
    content = [f"PAGE {page_index + 1}/{len(plan.pages)}: {page.key}", ""]
    for field in page.fields:
        content.append(field.key + " [" + field.source + "]")
        content.append(field.value)
        content.append("")
    wrapped: list[str] = []
    for line in content:
        if not line:
            wrapped.append("")
        else:
            wrapped.extend(line[i:i + cols] for i in range(0, len(line), cols))
    visible = max(1, (surface.height - 160) // (fh + 3))
    for index, line in enumerate(wrapped[line_offset:line_offset + visible]):
        surface.text(pad, 70 + index * (fh + 3), line)
    surface.rect(0, surface.height - 66, surface.width, 66, (28, 49, 76))
    surface.text(pad, surface.height - 56, "UP/DOWN scroll  LEFT/RIGHT pages  ESC cancel", (255, 222, 147))
    state = "ACKNOWLEDGED" if acknowledged else "REVIEW REQUIRED"
    surface.text(pad, surface.height - 32, "ENTER: acknowledge page  " + state, (255, 222, 147))
    return len(wrapped)


class ReviewController:
    """Approval signal only: never signs. Requires each page to be viewed."""
    def __init__(self, plan, *, audit):
        self.plan = plan
        self.audit = audit
        self.page = 0
        self.offset = 0
        self.seen: set[int] = set()
        self.cancelled = False
        self.locked = False

    def action(self, key: str):
        if self.cancelled or self.locked:
            return False
        if key == "ESC":
            self.cancelled = True
            return False
        if not self.audit():
            self.locked = True
            return False
        if key == "LEFT":
            self.page = max(0, self.page - 1)
            self.offset = 0
        elif key == "RIGHT":
            self.page = min(len(self.plan.pages) - 1, self.page + 1)
            self.offset = 0
        elif key == "DOWN":
            self.offset += 1
        elif key == "UP":
            self.offset = max(0, self.offset - 1)
        elif key == "ENTER":
            self.seen.add(self.page)
            return len(self.seen) == len(self.plan.pages)
        return False


def _fb_geometry(fd: int):
    vi = bytearray(160)
    fi = bytearray(80)
    fcntl.ioctl(fd, FBIOGET_VSCREENINFO, vi, True)
    fcntl.ioctl(fd, FBIOGET_FSCREENINFO, fi, True)
    xres, yres, xv, yv, xoff, yoff, bpp = struct.unpack_from("<7I", vi, 0)
    line_length = struct.unpack_from("<I", fi, 48 if struct.calcsize("P") == 8 else 36)[0]
    if (xoff or yoff or xres != xv or yres != yv or bpp not in (16, 32)
            or line_length < xres * (bpp // 8)):
        raise ValueError("Unsupported framebuffer pixel layout")
    # Vscreen bitfield offsets: red at +32, green +44, blue +56.
    rgb = tuple(struct.unpack_from("<II", vi, offset)[:2] for offset in (32, 44, 56))
    if (bpp == 32 and rgb != ((16, 8), (8, 8), (0, 8))) or (
        bpp == 16 and rgb != ((11, 5), (5, 6), (0, 5))
    ):
        raise ValueError("Unexpected framebuffer color bitfields")
    return xres, yres, bpp, line_length


def present(surface: Surface, fb_path="/dev/fb0"):
    """Write checked framebuffer bytes; keep all rendering memory private."""
    with open(fb_path, "r+b", buffering=0) as device:
        width, height, bpp, stride = _fb_geometry(device.fileno())
        if (width, height) != (surface.width, surface.height):
            raise ValueError("Framebuffer dimensions changed")
        data = surface.pixels
        with mmap.mmap(device.fileno(), stride * height, access=mmap.ACCESS_WRITE) as memory:
            for y in range(height):
                off = y * stride
                if bpp == 32:
                    memory[off:off + width * 4] = data[y * width * 4:(y + 1) * width * 4]
                else:
                    row = bytearray()
                    for x in range(width):
                        i = (y * width + x) * 4
                        b, g, r = data[i:i + 3]
                        row.extend(struct.pack("<H", ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)))
                    memory[off:off + len(row)] = row


def run_vt(plan, font_path: Path, *, audit, tty_path="/dev/tty1", fb_path="/dev/fb0"):
    """POC only: returns authorization intent, NEVER a signed transaction.

    The actual signer integration must reconstruct a fresh ReviewPlan, check
    its digest and policy, then call SignerSession.approve()/signing().
    """
    font = load_psf2(font_path)
    with open(fb_path, "r+b", buffering=0) as fb:
        width, height, _, _ = _fb_geometry(fb.fileno())
    display = Surface(width, height, font)
    controller = ReviewController(plan, audit=audit)
    with open(tty_path, "rb", buffering=0) as keyboard:
        fd = keyboard.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while not controller.cancelled and not controller.locked:
                total = render_review(display, plan, controller.page, controller.offset,
                                      acknowledged=controller.page in controller.seen)
                controller.offset = min(controller.offset, max(0, total - 1))
                present(display, fb_path)
                ready, _, _ = select.select([fd], [], [], 1.0)
                if not audit():
                    controller.locked = True
                    break
                if not ready:
                    continue
                raw = os.read(fd, 8)
                mapping = {b"\x1b": "ESC", b"\r": "ENTER", b"\n": "ENTER",
                           b"\x1b[A": "UP", b"\x1b[B": "DOWN",
                           b"\x1b[C": "RIGHT", b"\x1b[D": "LEFT"}
                if controller.action(mapping.get(raw, "")):
                    return True
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return False

"""Host-only tests for the framebuffer POC; not QEMU display evidence."""
from pathlib import Path
from types import SimpleNamespace
import struct

import pytest

from usb_cold_wallet.framebuffer_poc import (
    ReviewController, Surface, load_psf2, render_review,
)


def _font():
    # Zero bitmaps are sufficient for layout/control tests; no real PSF asset.
    return (8, 16, bytes(256 * 16))


def _plan():
    pages = tuple(SimpleNamespace(
        key=name,
        fields=(SimpleNamespace(key="recipient", source="raw transaction",
                                value="0x" + "ab" * 20),),
    ) for name in ("network", "recipient", "amount", "fee"))
    return SimpleNamespace(pages=pages)


def test_render_pages_and_long_critical_values_are_scrollable():
    display = Surface(640, 480, _font())
    plan = _plan()
    plan.pages[0].fields[0].value = "X" * 5000
    count = render_review(display, plan, 0)
    assert count > (display.height - 160) // 19
    assert display.ppm().startswith(b"P6\n640 480\n255\n")
    assert render_review(display, plan, 0, line_offset=100) == count


def test_all_pages_must_be_acknowledged_explicitly():
    ctrl = ReviewController(_plan(), audit=lambda: True)
    assert ctrl.action("ENTER") is False
    for i in range(4):
        if i:
            ctrl.action("RIGHT")
        assert ctrl.action("ENTER") is (i == 3)
    assert ctrl.seen == {0, 1, 2, 3}


def test_cannot_acknowledge_before_scrolling_to_end():
    ctrl = ReviewController(_plan(), audit=lambda: True)
    ctrl.scroll_bottom = 4
    assert ctrl.action("ENTER") is False
    for _ in range(4):
        ctrl.action("DOWN")
    assert ctrl.action("ENTER") is False
    assert ctrl.seen == {0}


def test_cancel_and_audit_failure_fail_closed():
    ctrl = ReviewController(_plan(), audit=lambda: True)
    assert ctrl.action("ESC") is False
    assert ctrl.cancelled
    assert ctrl.action("ENTER") is False
    ctrl = ReviewController(_plan(), audit=lambda: False)
    assert ctrl.action("ENTER") is False
    assert ctrl.locked
    assert not ctrl.seen


def test_invalid_page_and_geometry_rejected():
    surface = Surface(320, 240, _font())
    with pytest.raises(ValueError):
        render_review(surface, _plan(), 99)
    with pytest.raises(ValueError):
        Surface(100, 100, _font())


def test_psf2_font_rejects_truncated_or_unicode_remapped(tmp_path: Path):
    font = tmp_path / "font.psf"
    font.write_bytes(b"no")
    with pytest.raises(ValueError):
        load_psf2(font)
    header = struct.pack("<8I", 0x864AB572, 0, 32, 1, 256, 16, 16, 8)
    font.write_bytes(header + bytes(256 * 16))
    with pytest.raises(ValueError):
        load_psf2(font)
    font.write_bytes(struct.pack("<8I", 0x864AB572, 0, 32, 0, 256, 16, 16, 8) + bytes(256 * 16))
    assert load_psf2(font)[:2] == (8, 16)

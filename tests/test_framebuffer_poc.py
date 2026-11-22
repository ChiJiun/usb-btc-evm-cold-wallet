"""Host security tests for the framebuffer POC; never substitute for QEMU pixels."""
from dataclasses import replace
from pathlib import Path
import ast
import hashlib
import struct

import pytest

import usb_cold_wallet.framebuffer_poc as fb
from usb_cold_wallet.exchange import package
from usb_cold_wallet.keys import root_from_mnemonic
from usb_cold_wallet.review import (ReviewField, ReviewPage, build_review_plan,
                                    _canonical, _review_document)


PUBLIC_TEST_MNEMONIC = "abandon " * 11 + "about"
EVM_RECIPIENT = "0x000000000000000000000000000000000000dEaD"


def _font():
    return (8, 16, bytes(256 * 16))


def _plan():
    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    tx = {
        "type": 2,
        "chainId": 11155111,
        "nonce": 7,
        "to": EVM_RECIPIENT,
        "value": 1_000_000_000_000,
        "gas": 21_000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
        "data": "0x",
        "accessList": [],
    }
    return build_review_plan(package("evm-request", tx), root, "evm-request")


def _rebind_pages(plan, pages):
    pages = tuple(pages)
    reviewed = (pages[0], *pages[2:])
    digest = hashlib.sha256(
        _canonical(_review_document(plan.kind, plan.request_digest, reviewed))
    ).hexdigest()
    integrity = ReviewPage(
        "integrity",
        (
            ReviewField("request_digest", plan.request_digest, "verified exchange envelope.sha256"),
            ReviewField("review_digest", digest, "SHA-256(canonical offline reviewed fields)"),
        ),
    )
    return replace(
        plan,
        review_digest=digest,
        pages=(pages[0], integrity, *pages[2:]),
        challenge=f"SIGN {plan.kind.upper()} {plan.recipient[-8:]} {digest[:8]}",
    )


def test_renderer_accepts_real_backend_review_plan_and_never_elides_long_fields():
    display = fb.Surface(640, 480, _font())
    plan = _plan()
    long_field = ReviewField("calldata", "X" * 5000, "payload.data")
    pages = list(plan.pages)
    pages[-1] = ReviewPage(pages[-1].key, pages[-1].fields + (long_field,))
    plan = _rebind_pages(plan, pages)

    count = fb.render_review(display, plan, len(plan.pages) - 1)
    assert count > (display.height - 160) // 19
    assert display.ppm().startswith(b"P6\n640 480\n255\n")
    assert fb.render_review(display, plan, len(plan.pages) - 1, line_offset=100) == count


def test_all_real_review_pages_require_explicit_acknowledgement():
    plan = _plan()
    ctrl = fb.ReviewController(plan, audit=lambda: True)
    for index in range(len(plan.pages)):
        if index:
            ctrl.action("RIGHT")
        assert ctrl.action("ENTER") is (index == len(plan.pages) - 1)
    assert ctrl.seen == set(range(len(plan.pages)))


def test_long_page_cannot_acknowledge_before_scrolling_to_end():
    ctrl = fb.ReviewController(_plan(), audit=lambda: True)
    ctrl.scroll_bottom = 4
    assert ctrl.action("ENTER") is False
    for _ in range(4):
        ctrl.action("DOWN")
    assert ctrl.action("ENTER") is False
    assert ctrl.seen == {0}


def test_cancel_and_audit_failure_fail_closed():
    ctrl = fb.ReviewController(_plan(), audit=lambda: True)
    assert ctrl.action("ESC") is False
    assert ctrl.cancelled
    assert ctrl.action("ENTER") is False

    ctrl = fb.ReviewController(_plan(), audit=lambda: False)
    assert ctrl.action("ENTER") is False
    assert ctrl.locked
    assert not ctrl.seen

    ctrl = fb.ReviewController(_plan(), audit=lambda: (_ for _ in ()).throw(OSError("audit")))
    assert ctrl.action("ENTER") is False
    assert ctrl.locked


def test_only_existing_review_plan_type_is_accepted():
    with pytest.raises(TypeError):
        fb.ReviewController(object(), audit=lambda: True)


def test_secret_bearing_review_fields_are_rejected():
    plan = _plan()
    pages = list(plan.pages)
    pages[0] = ReviewPage(
        pages[0].key,
        pages[0].fields + (ReviewField("wallet_passphrase", "do-not-display", "vault passphrase"),),
    )
    plan = _rebind_pages(plan, pages)
    with pytest.raises(ValueError, match="Secret-bearing"):
        fb.render_review(fb.Surface(640, 480, _font()), plan, 0)


def test_invalid_page_and_geometry_rejected():
    surface = fb.Surface(320, 240, _font())
    with pytest.raises(ValueError):
        fb.render_review(surface, _plan(), 99)
    with pytest.raises(ValueError):
        fb.Surface(100, 100, _font())


def test_unrepresentable_review_text_fails_closed():
    plan = _plan()
    pages = list(plan.pages)
    pages[0] = ReviewPage(
        pages[0].key,
        pages[0].fields + (ReviewField("memo", "pay\nnow", "payload.memo"),),
    )
    plan = _rebind_pages(plan, pages)
    with pytest.raises(ValueError, match="cannot represent exactly"):
        fb.render_review(fb.Surface(640, 480, _font()), plan, 0)


def test_tampered_review_pages_are_rejected_before_render():
    plan = _plan()
    pages = list(plan.pages)
    original = pages[-1]
    pages[-1] = ReviewPage(
        original.key,
        original.fields + (ReviewField("recipient", EVM_RECIPIENT[:-1] + "0", "tampered"),),
    )
    tampered = replace(plan, pages=tuple(pages))
    with pytest.raises(ValueError, match="do not match review digest"):
        fb.render_review(fb.Surface(640, 480, _font()), tampered, len(pages) - 1)


def test_tampered_integrity_page_is_rejected():
    plan = _plan()
    pages = list(plan.pages)
    pages[1] = ReviewPage(
        "integrity",
        (
            ReviewField("request_digest", plan.request_digest, "verified exchange envelope.sha256"),
            ReviewField("review_digest", "0" * 64, "SHA-256(canonical offline reviewed fields)"),
        ),
    )
    with pytest.raises(ValueError, match="integrity page is inconsistent"):
        fb.render_review(fb.Surface(640, 480, _font()), replace(plan, pages=tuple(pages)), 1)


def test_psf2_font_is_exact_bounded_direct_index_format(tmp_path: Path):
    font = tmp_path / "font.psf"
    font.write_bytes(b"no")
    with pytest.raises(ValueError):
        fb.load_psf2(font)

    header = struct.pack("<8I", fb.PSF2_MAGIC, 0, 32, 0, 256, 16, 16, 8)
    font.write_bytes(header + bytes(256 * 16))
    assert fb.load_psf2(font)[:2] == (8, 16)

    font.write_bytes(struct.pack("<8I", fb.PSF2_MAGIC, 0, 32, 1, 256, 16, 16, 8) + bytes(256 * 16))
    with pytest.raises(ValueError):
        fb.load_psf2(font)

    font.write_bytes(header + bytes(256 * 16) + b"trailing")
    with pytest.raises(ValueError):
        fb.load_psf2(font)


def test_split_arrow_sequence_is_parsed_and_malformed_escape_cancels(monkeypatch):
    reads = iter((b"\x1b", b"[", b"B"))
    monkeypatch.setattr(fb.select, "select", lambda *args: ([3], [], []))
    monkeypatch.setattr(fb.os, "read", lambda fd, size: next(reads))
    assert fb._read_key(3) == "DOWN"

    calls = iter((([3], [], []), ([], [], [])))
    monkeypatch.setattr(fb.select, "select", lambda *args: next(calls))
    monkeypatch.setattr(fb.os, "read", lambda fd, size: b"\x1b")
    assert fb._read_key(3) == "ESC"


def test_runtime_imports_have_no_socket_x11_or_subprocess_dependency():
    source = Path(fb.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported |= {
        node.module.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not ({"socket", "subprocess", "tkinter", "Xlib"} & imported)
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "AF_UNIX"
        for node in ast.walk(tree)
    )
    assert "SignerSession(" not in source
    assert "sign_review_plan(" not in source


def test_vt_graphics_and_switch_lock_controls_remain_required():
    assert fb.KD_GRAPHICS == 1
    assert fb.KD_TEXT == 0
    assert fb.VT_LOCKSWITCH != fb.VT_UNLOCKSWITCH

"""Adversarial, network-free regression tests for the independent release verifier."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.verify_release_assets import (
    REPOSITORY, ReleaseVerificationError, parse_sha256sums, verify_release,
)

TAG = "v0.1.0-beta.1"
COMMIT = "a" * 40
ASSET = f"usb-cold-wallet-{TAG}.img.xz"
BINARY = b"fake image bytes, not a real wallet image"
DIGEST = hashlib.sha256(BINARY).hexdigest()


class FakeGitHub:
    def __init__(self):
        self.calls: list[list[str]] = []
        self.tag_verified = True
        self.object_commit = COMMIT
        self.manifest_digest = DIGEST
        self.binary = BINARY
        self.fail_command: tuple[str, ...] | None = None
        self.lightweight = False
        self.draft = False

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        if self.fail_command and args[:len(self.fail_command)] == list(self.fail_command):
            raise ReleaseVerificationError("simulated verification command failure")
        if args[:2] == ["api", f"repos/{REPOSITORY}/git/ref/tags/{TAG}"]:
            kind = "commit" if self.lightweight else "tag"
            return json.dumps({"object": {"type": kind, "sha": "b" * 40}})
        if args[:2] == ["api", f"repos/{REPOSITORY}/git/tags/{'b' * 40}"]:
            return json.dumps({
                "tag": TAG,
                "verification": {"verified": self.tag_verified},
                "object": {"type": "commit", "sha": self.object_commit},
            })
        if args[:2] == ["release", "view"]:
            return json.dumps({"tagName": TAG, "isDraft": self.draft})
        if args[:2] == ["release", "download"]:
            target_dir = Path(args[args.index("--dir") + 1])
            name = args[args.index("--pattern") + 1]
            if name == "SHA256SUMS":
                (target_dir / name).write_text(
                    f"{self.manifest_digest}  {ASSET}\n", encoding="ascii"
                )
            elif name == ASSET:
                (target_dir / name).write_bytes(self.binary)
            return ""
        if args[:2] in (
            ["release", "verify"], ["release", "verify-asset"],
            ["attestation", "verify"],
        ):
            return ""
        raise AssertionError(f"Unexpected GitHub CLI call: {args}")


def test_good_release_verifies_pinned_tag_and_build_provenance():
    fake = FakeGitHub()
    assert verify_release(TAG, COMMIT, ASSET, run=fake) == DIGEST
    assert ["release", "verify", TAG, "-R", REPOSITORY] in fake.calls
    attest = next(a for a in fake.calls if a[:2] == ["attestation", "verify"])
    assert attest[attest.index("--source-ref") + 1] == f"refs/tags/{TAG}"
    assert attest[attest.index("--source-digest") + 1] == COMMIT
    assert attest[attest.index("--signer-workflow") + 1] == (
        f"{REPOSITORY}/.github/workflows/release.yml"
    )
    assert sum(a[:2] == ["release", "verify-asset"] for a in fake.calls) == 2


@pytest.mark.parametrize("invalid", [
    "", "main", "v1.0", "v1.2.3/../../steal", "--help", "v1.0.0\nsomething",
])
def test_untrusted_tag_cannot_select_arbitrary_ref(invalid):
    fake = FakeGitHub()
    with pytest.raises(ReleaseVerificationError):
        verify_release(invalid, COMMIT, ASSET, run=fake)
    assert fake.calls == []


@pytest.mark.parametrize("invalid", ["main", "deadbeef", "-a" * 20, "x" * 40])
def test_commit_must_be_exact_sha(invalid):
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, invalid, ASSET, run=FakeGitHub())


@pytest.mark.parametrize("invalid", [
    "SHA256SUMS", "../example.img", f"{ASSET};sh", f"{ASSET}.exe",
    "usb-cold-wallet-v9.9.9.img.xz", f"{ASSET}*",
])
def test_asset_basename_and_tag_must_match(invalid):
    fake = FakeGitHub()
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, COMMIT, invalid, run=fake)
    assert fake.calls == []


@pytest.mark.parametrize("contents", [
    f"{DIGEST}  ../../{ASSET}\n",
    f"{DIGEST}  {ASSET}\n{DIGEST}  {ASSET}\n",
    f"{DIGEST}  {ASSET}\n{'0'*64}  ../secret\n",
    f"{DIGEST}  {ASSET}\n<script>alert(1)</script>\n",
    f"{DIGEST}  other.img\n",
    "\u2603",
])
def test_hostile_manifest_rejected(contents):
    with pytest.raises(ReleaseVerificationError):
        parse_sha256sums(contents.encode("utf-8"), ASSET)


def test_sha256_manifest_limit():
    with pytest.raises(ReleaseVerificationError):
        parse_sha256sums(b"x" * (128 * 1024 + 1), ASSET)


@pytest.mark.parametrize("failure", ["lightweight", "unsigned", "wrong_commit", "draft"])
def test_untrusted_release_ref_is_rejected_before_download(failure):
    fake = FakeGitHub()
    if failure == "lightweight":
        fake.lightweight = True
    elif failure == "unsigned":
        fake.tag_verified = False
    elif failure == "wrong_commit":
        fake.object_commit = "0" * 40
    else:
        fake.draft = True
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, COMMIT, ASSET, run=fake)
    assert not any(a[:2] == ["release", "download"] for a in fake.calls)


def test_binary_substitution_is_rejected_before_attestation():
    fake = FakeGitHub()
    fake.binary = b"tampered release asset"
    with pytest.raises(ReleaseVerificationError, match="SHA256SUMS"):
        verify_release(TAG, COMMIT, ASSET, run=fake)
    assert not any(a[:2] == ["attestation", "verify"] for a in fake.calls)


@pytest.mark.parametrize("command", [
    ("release", "verify"), ("release", "verify-asset"), ("attestation", "verify"),
])
def test_missing_or_invalid_immutable_release_or_build_attestation_blocks(command):
    fake = FakeGitHub()
    fake.fail_command = command
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, COMMIT, ASSET, run=fake)


def test_checksums_are_not_themselves_claimed_to_authenticate_release():
    fake = FakeGitHub()
    fake.manifest_digest = hashlib.sha256(fake.binary).hexdigest()
    fake.fail_command = ("release", "verify-asset")
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, COMMIT, ASSET, run=fake)

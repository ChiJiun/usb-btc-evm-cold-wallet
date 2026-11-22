"""Adversarial, network-free regression tests for release verification and gating."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from scripts.verify_release_assets import (
    RELEASE_WORKFLOW,
    REPOSITORY,
    ReleaseVerificationError,
    parse_sha256sums,
    require_successful_jobs,
    verify_local_artifacts,
    verify_release,
    verify_repository_release_controls,
    verify_source,
)

TAG = "v0.1.0-beta.1"
COMMIT = "a" * 40
WORKFLOW_SHA = "c" * 40
TAG_OBJECT_SHA = "b" * 40
ASSET = f"usb-cold-wallet-{TAG}.img.xz"
BINARY = b"fake image bytes, not a real wallet image"
DIGEST = hashlib.sha256(BINARY).hexdigest()
SBOM = (json.dumps(
    {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0"},
    sort_keys=True,
) + "\n").encode()
HOST_PACKAGES = b"gcc=1.0\nmake=1.0\n"


def _metadata_bytes(*, tag: str = TAG, commit: str = COMMIT, asset: str = ASSET) -> bytes:
    return (json.dumps(
        {
            "repository": REPOSITORY,
            "tag": tag,
            "source_sha": commit,
            "workflow_sha": WORKFLOW_SHA,
            "workflow": ".github/workflows/release.yml",
            "asset": asset,
            "buildroot_version": "2026.08.2",
            "buildroot_sha256": "1" * 64,
            "node_version": "24.22.3",
            "xz_version": "5.8.1",
            "compression": "xz -6 --threads=1 --check=crc64 --no-sparse",
            "raw_image_sha256": "2" * 64,
            "reproducibility_runs": 2,
            "tag_object_sha": TAG_OBJECT_SHA,
            "apt_snapshot": "20261121T000000Z",
            "runner_image_os": "ubuntu24",
            "runner_image_version": "20261116.1",
            "workflow_run_id": "12345",
            "workflow_run_attempt": "1",
        },
        sort_keys=True,
    ) + "\n").encode()


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
        self.tagger_email = "0311gino@gmail.com"
        self.tag_object_sha = TAG_OBJECT_SHA

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        if self.fail_command and args[: len(self.fail_command)] == list(self.fail_command):
            raise ReleaseVerificationError("simulated verification command failure")
        if args[:2] == ["api", f"repos/{REPOSITORY}/git/ref/tags/{TAG}"]:
            kind = "commit" if self.lightweight else "tag"
            return json.dumps({"object": {"type": kind, "sha": self.tag_object_sha}})
        if args[:2] == ["api", f"repos/{REPOSITORY}/git/tags/{self.tag_object_sha}"]:
            return json.dumps(
                {
                    "tag": TAG,
                    "verification": {
                        "verified": self.tag_verified,
                        "reason": "valid" if self.tag_verified else "invalid",
                        "signature": "-----BEGIN PGP SIGNATURE-----\nfake",
                    },
                    "tagger": {"name": "Release Maintainer", "email": self.tagger_email},
                    "object": {"type": "commit", "sha": self.object_commit},
                }
            )
        if args[:2] == ["release", "view"]:
            return json.dumps({"tagName": TAG, "isDraft": self.draft})
        if args[:2] == ["release", "download"]:
            target_dir = Path(args[args.index("--dir") + 1])
            name = args[args.index("--pattern") + 1]
            metadata = _metadata_bytes()
            payloads = {
                ASSET: self.binary,
                "SBOM.spdx.json": SBOM,
                "release-metadata.json": metadata,
                "build-host-packages.txt": HOST_PACKAGES,
            }
            if name == "SHA256SUMS":
                lines = []
                for filename in sorted(payloads):
                    digest = (
                        self.manifest_digest
                        if filename == ASSET
                        else hashlib.sha256(payloads[filename]).hexdigest()
                    )
                    lines.append(f"{digest}  {filename}")
                (target_dir / name).write_text("\n".join(lines) + "\n", encoding="ascii")
            elif name in payloads:
                (target_dir / name).write_bytes(payloads[name])
            return ""
        if args[:2] in (
            ["release", "verify"],
            ["release", "verify-asset"],
            ["attestation", "verify"],
        ):
            return ""
        raise AssertionError(f"Unexpected GitHub CLI call: {args}")


def _write_local_release(
    directory: Path,
    *,
    tag: str = TAG,
    commit: str = COMMIT,
    asset: str = ASSET,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / asset).write_bytes(BINARY)
    (directory / "SBOM.spdx.json").write_bytes(SBOM)
    (directory / "release-metadata.json").write_bytes(
        _metadata_bytes(tag=tag, commit=commit, asset=asset)
    )
    (directory / "build-host-packages.txt").write_bytes(HOST_PACKAGES)
    files = [asset, "SBOM.spdx.json", "release-metadata.json", "build-host-packages.txt"]
    lines = [
        f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}"
        for name in sorted(files)
    ]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")


def test_good_release_verifies_pinned_tag_and_build_provenance():
    fake = FakeGitHub()
    assert verify_release(TAG, COMMIT, ASSET, workflow_sha=WORKFLOW_SHA, run=fake) == DIGEST
    assert ["release", "verify", TAG, "-R", REPOSITORY] in fake.calls
    attest = next(a for a in fake.calls if a[:2] == ["attestation", "verify"])
    assert attest[attest.index("--source-ref") + 1] == "refs/heads/main"
    assert attest[attest.index("--source-digest") + 1] == WORKFLOW_SHA
    assert attest[attest.index("--signer-workflow") + 1] == RELEASE_WORKFLOW
    assert attest[attest.index("--signer-digest") + 1] == WORKFLOW_SHA
    assert attest[attest.index("--predicate-type") + 1] == "https://slsa.dev/provenance/v1"
    assert sum(a[:2] == ["release", "verify-asset"] for a in fake.calls) == 5
    assert sum(a[:2] == ["attestation", "verify"] for a in fake.calls) == 5


def test_source_only_accepts_signed_annotated_tag_bound_to_exact_commit():
    fake = FakeGitHub()
    assert verify_source(TAG, COMMIT, run=fake) == TAG_OBJECT_SHA
    assert len(fake.calls) == 2
    assert not any(a and a[0] == "release" for a in fake.calls)


def test_valid_signature_from_unauthorized_release_signer_is_rejected():
    fake = FakeGitHub()
    fake.tagger_email = "mallory@example.com"
    with pytest.raises(ReleaseVerificationError, match="authorized release identity"):
        verify_source(TAG, COMMIT, run=fake)


def test_tag_object_replacement_after_validation_is_rejected():
    fake = FakeGitHub()
    with pytest.raises(ReleaseVerificationError, match="changed after validation"):
        verify_source(TAG, COMMIT, run=fake, expected_tag_object_sha="d" * 40)


def _ruleset_run(*, main_approvals=1, last_push=True, checks=("CI / Required",), include_tag=True, tag_rules=("creation", "update", "deletion")):
    summaries = [
        {"id": 1, "enforcement": "active"},
        *([{"id": 2, "enforcement": "active"}] if include_tag else []),
    ]
    main = {
        "id": 1,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": main_approvals,
                    "require_last_push_approval": last_push,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{"context": name} for name in checks],
                },
            },
        ],
    }
    tag = {
        "id": 2,
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
        "rules": [{"type": name} for name in tag_rules],
    }

    def run(args):
        if args == ["api", f"repos/{REPOSITORY}/rulesets"]:
            return json.dumps(summaries)
        if args == ["api", f"repos/{REPOSITORY}/rulesets/1"]:
            return json.dumps(main)
        if args == ["api", f"repos/{REPOSITORY}/rulesets/2"] and include_tag:
            return json.dumps(tag)
        raise AssertionError(args)

    return run


def test_repository_release_controls_require_protected_main_and_release_tags():
    verify_repository_release_controls(run=_ruleset_run())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"main_approvals": 0},
        {"last_push": False},
        {"checks": ()},
        {"include_tag": False},
        {"tag_rules": ("creation", "deletion")},
        {"tag_rules": ("update", "deletion")},
        {"tag_rules": ("creation", "update")},
    ],
)
def test_missing_repository_release_control_blocks_release(kwargs):
    with pytest.raises(ReleaseVerificationError, match="not enforced"):
        verify_repository_release_controls(run=_ruleset_run(**kwargs))


def test_staged_final_bytes_verify_before_publish(tmp_path):
    fake = FakeGitHub()
    _write_local_release(tmp_path)
    assert verify_local_artifacts(TAG, COMMIT, ASSET, tmp_path, workflow_sha=WORKFLOW_SHA, run=fake) == DIGEST
    assert not any(a[:2] == ["release", "view"] for a in fake.calls)
    attest = next(
        a for a in fake.calls
        if a[:2] == ["attestation", "verify"] and Path(a[2]).name == ASSET
    )
    assert Path(attest[2]).read_bytes() == BINARY
    assert attest[attest.index("--source-digest") + 1] == WORKFLOW_SHA


@pytest.mark.parametrize(
    "invalid",
    ["", "main", "v1.0", "v1.2.3/../../steal", "--help", "v1.0.0\nsomething"],
)
def test_untrusted_tag_cannot_select_arbitrary_ref(invalid):
    fake = FakeGitHub()
    with pytest.raises(ReleaseVerificationError):
        verify_release(invalid, COMMIT, ASSET, workflow_sha=WORKFLOW_SHA, run=fake)
    assert fake.calls == []


@pytest.mark.parametrize("invalid", ["main", "deadbeef", "-a" * 20, "x" * 40])
def test_commit_must_be_exact_sha(invalid):
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, invalid, ASSET, workflow_sha=WORKFLOW_SHA, run=FakeGitHub())


@pytest.mark.parametrize(
    "invalid",
    [
        "SHA256SUMS",
        "../example.img",
        f"{ASSET};sh",
        f"{ASSET}.exe",
        "usb-cold-wallet-v9.9.9.img.xz",
        f"{ASSET}*",
        "https://evil.invalid/usb-cold-wallet-v0.1.0-beta.1.img.xz",
    ],
)
def test_asset_basename_and_tag_must_match_and_urls_are_rejected(invalid):
    fake = FakeGitHub()
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, COMMIT, invalid, workflow_sha=WORKFLOW_SHA, run=fake)
    assert fake.calls == []


@pytest.mark.parametrize(
    "contents",
    [
        f"{DIGEST}  ../../{ASSET}\n",
        f"{DIGEST}  {ASSET}\n{DIGEST}  {ASSET}\n",
        f"{DIGEST}  {ASSET}\n{'0' * 64}  ../secret\n",
        f"{DIGEST}  {ASSET}\n<script>alert(1)</script>\n",
        f"{DIGEST}  other.img\n",
        "\u2603",
    ],
)
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
        verify_release(TAG, COMMIT, ASSET, workflow_sha=WORKFLOW_SHA, run=fake)
    assert not any(a[:2] == ["release", "download"] for a in fake.calls)


def test_binary_substitution_is_rejected_before_attestation():
    fake = FakeGitHub()
    fake.binary = b"tampered release asset"
    with pytest.raises(ReleaseVerificationError, match="digest mismatch"):
        verify_release(TAG, COMMIT, ASSET, workflow_sha=WORKFLOW_SHA, run=fake)
    assert not any(a[:2] == ["attestation", "verify"] for a in fake.calls)


@pytest.mark.parametrize(
    "command",
    [
        ("release", "verify"),
        ("release", "verify-asset"),
        ("attestation", "verify"),
    ],
)
def test_missing_or_invalid_immutable_release_or_build_attestation_blocks(command):
    fake = FakeGitHub()
    fake.fail_command = command
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, COMMIT, ASSET, workflow_sha=WORKFLOW_SHA, run=fake)


def test_checksums_are_not_themselves_claimed_to_authenticate_release():
    fake = FakeGitHub()
    fake.manifest_digest = hashlib.sha256(fake.binary).hexdigest()
    fake.fail_command = ("release", "verify-asset")
    with pytest.raises(ReleaseVerificationError):
        verify_release(TAG, COMMIT, ASSET, workflow_sha=WORKFLOW_SHA, run=fake)


@pytest.mark.parametrize("mutation", ["asset", "sha", "metadata_commit", "metadata_workflow", "sbom", "extra_file"])
def test_staged_asset_substitution_wrong_sha_source_or_manifest_fails_closed(
    tmp_path, mutation
):
    fake = FakeGitHub()
    _write_local_release(tmp_path)

    if mutation == "asset":
        (tmp_path / ASSET).write_bytes(b"substituted")
    elif mutation == "sha":
        manifest = (tmp_path / "SHA256SUMS").read_text(encoding="ascii")
        (tmp_path / "SHA256SUMS").write_text(
            manifest.replace(DIGEST, "0" * 64), encoding="ascii"
        )
    elif mutation == "metadata_commit":
        metadata = json.loads(
            (tmp_path / "release-metadata.json").read_text(encoding="utf-8")
        )
        metadata["source_sha"] = "0" * 40
        (tmp_path / "release-metadata.json").write_text(
            json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
        )
        names = [ASSET, "SBOM.spdx.json", "release-metadata.json", "build-host-packages.txt"]
        lines = []
        for name in sorted(names):
            digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (tmp_path / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")
    elif mutation == "metadata_workflow":
        metadata = json.loads(
            (tmp_path / "release-metadata.json").read_text(encoding="utf-8")
        )
        metadata["workflow_sha"] = "d" * 40
        (tmp_path / "release-metadata.json").write_text(
            json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
        )
        names = [ASSET, "SBOM.spdx.json", "release-metadata.json", "build-host-packages.txt"]
        lines = []
        for name in sorted(names):
            digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (tmp_path / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")
    elif mutation == "sbom":
        (tmp_path / "SBOM.spdx.json").write_text("{}", encoding="utf-8")
        names = [ASSET, "SBOM.spdx.json", "release-metadata.json", "build-host-packages.txt"]
        lines = []
        for name in sorted(names):
            digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}")
        (tmp_path / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")
    else:
        with (tmp_path / "SHA256SUMS").open("a", encoding="ascii") as handle:
            handle.write(f"{'0' * 64}  unexpected.bin\n")

    with pytest.raises(ReleaseVerificationError):
        verify_local_artifacts(TAG, COMMIT, ASSET, tmp_path, workflow_sha=WORKFLOW_SHA, run=fake)


def test_wrong_or_missing_attestation_subject_fails_staged_verification(tmp_path):
    fake = FakeGitHub()
    fake.fail_command = ("attestation", "verify")
    _write_local_release(tmp_path)
    with pytest.raises(ReleaseVerificationError):
        verify_local_artifacts(TAG, COMMIT, ASSET, tmp_path, workflow_sha=WORKFLOW_SHA, run=fake)


@pytest.mark.parametrize("state", ["skipped", "failure", "cancelled", "neutral"])
def test_required_release_job_not_success_blocks_publish(state):
    results = {"build": "success", "attest": "success", "verify": "success"}
    results["verify"] = state
    with pytest.raises(ReleaseVerificationError):
        require_successful_jobs(results)


def test_missing_required_release_job_blocks_publish():
    with pytest.raises(ReleaseVerificationError):
        require_successful_jobs({"build": "success", "attest": "success"})


def test_all_required_release_jobs_must_succeed():
    require_successful_jobs(
        {"build": "success", "attest": "success", "verify": "success"}
    )


def test_release_workflow_has_pinned_actions_and_separated_permissions():
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "pull_request:" not in workflow
    assert "permissions: {}" in workflow
    assert 'default: false' in workflow
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in workflow
    assert 'test "$GITHUB_SHA" = "$SOURCE_SHA"' not in workflow
    assert workflow.count('ref: ${{ github.sha }}') >= 3
    assert "expected_tag_object_sha" in workflow
    assert "verify_source" in workflow
    assert "--snapshot" in workflow

    use_lines = [line.strip() for line in workflow.splitlines() if "uses:" in line]
    assert use_lines
    for line in use_lines:
        assert re.search(r"uses:\s+[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$", line), line

    build = workflow.split("\n  build:\n", 1)[1].split("\n  attest:\n", 1)[0]
    attest = workflow.split("\n  attest:\n", 1)[1].split("\n  verify:\n", 1)[0]
    verify = workflow.split("\n  verify:\n", 1)[1].split("\n  gate:\n", 1)[0]
    publish = workflow.split("\n  publish:\n", 1)[1]

    assert "contents: read" in build
    assert "id-token: write" not in build
    assert "attestations: write" not in build
    assert "contents: write" not in build

    assert "id-token: write" in attest
    assert "attestations: write" in attest
    assert "contents: write" not in attest

    assert "attestations: read" in verify
    assert "attestations: write" not in verify
    assert "id-token: write" not in verify
    assert "contents: write" not in verify

    assert "contents: write" in publish
    assert "needs: gate" in publish
    assert "github.ref == 'refs/heads/main'" in publish
    assert "needs.gate.result == 'success'" in publish
    assert "--clobber" not in publish
    assert 'test "$RUN1" = "$RUN2"' in build
    assert 'RAW_IMAGE_SHA256' in build
    assert 'build-host-packages.txt' in build
    assert 'release/build-host-packages.txt' in publish
    assert 'for issue in 24 43' in publish
    assert 'gh issue view 48' in publish
    assert "expected_tag_object_sha" in publish
    assert "verify_source" in publish
    assert "verify_repository_release_controls" in workflow

#!/usr/bin/env python3
"""Fail-closed verification for release source, staged artifacts, and published assets.

Requires a recent GitHub CLI (gh) with release integrity and artifact
attestation commands. Never downloads arbitrary URLs or executes release assets.
The expected commit must come from a separately trusted source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping

REPOSITORY = "ChiJiun/usb-btc-evm-cold-wallet"
RELEASE_CANDIDATE_WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"
RELEASE_FINALIZE_WORKFLOW = f"{REPOSITORY}/.github/workflows/release-finalize.yml"
# Build provenance is minted only by the trusted default-branch finalizer.
RELEASE_WORKFLOW = RELEASE_FINALIZE_WORKFLOW
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?")
SHA_RE = re.compile(r"[a-fA-F0-9]{40}")
ASSET_RE = re.compile(
    r"usb-cold-wallet-v[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?\.img(?:\.xz)?"
)
CHECKSUM_RE = re.compile(r"([a-fA-F0-9]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)")
MAX_MANIFEST_BYTES = 128 * 1024
MAX_RAW_IMAGE_BYTES = 16 * 1024 * 1024 * 1024
# The download bound is independent of the decompressed-image safety bound.
MAX_COMPRESSED_IMAGE_BYTES = 16 * 1024 * 1024 * 1024
REQUIRED_STAGED_FILES = ("SBOM.spdx.json", "release-metadata.json", "build-host-packages.txt")
DEFAULT_AUTHORIZED_RELEASE_TAGGER_EMAILS = frozenset({"0311gino@gmail.com"})
DEFAULT_AUTHORIZED_RELEASE_ACTORS = frozenset({"ChiJiun"})
# GitHub Actions App ID; a check from any other integration must not satisfy the release gate.
GITHUB_ACTIONS_APP_ID = 15368
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SLSA_BUILD_TYPE_PREFIX = f"https://github.com/{REPOSITORY}/blob/"
SLSA_BUILDER_ID = f"https://github.com/{REPOSITORY}/actions/workflows/release-finalize.yml"
Run = Callable[[list[str]], str]


class ReleaseVerificationError(ValueError):
    """Unsafe or unverifiable release input."""


def _gh(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["gh", *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        # Never echo stderr: CLI errors can include credentials or remote data.
        raise ReleaseVerificationError(
            "GitHub CLI verification failed: " + " ".join(args[:2])
        ) from exc


def _json(run: Run, args: list[str]) -> dict:
    try:
        value = json.loads(run(args))
    except (ValueError, TypeError) as exc:
        raise ReleaseVerificationError("Invalid GitHub API JSON response") from exc
    if not isinstance(value, dict):
        raise ReleaseVerificationError("Expected a GitHub JSON object")
    return value


def _sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _raw_image_sha256(image: Path) -> str:
    """Verify the compressed delivery bytes bind the claimed raw disk image."""
    digest = hashlib.sha256()
    size = 0
    try:
        opener = lzma.open if image.name.endswith(".xz") else open
        with opener(image, "rb") as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > MAX_RAW_IMAGE_BYTES:
                    raise ReleaseVerificationError("Raw image exceeds safety size limit")
                digest.update(block)
    except (lzma.LZMAError, EOFError, OSError) as exc:
        raise ReleaseVerificationError("Release image is not a complete valid xz/raw image") from exc
    if size == 0:
        raise ReleaseVerificationError("Raw image is empty")
    return digest.hexdigest()


def _safe_file(directory: Path, name: str) -> Path:
    path = directory / name
    if path.parent.resolve() != directory.resolve():
        raise ReleaseVerificationError("Release asset escaped the verification directory")
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise ReleaseVerificationError(
            "Release asset is missing, empty, symlinked, or not a regular file"
        )
    return path


def parse_sha256sums_entries(raw: bytes) -> dict[str, str]:
    """Parse a strict GNU sha256sum manifest into safe basename entries."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ReleaseVerificationError("SHA256SUMS is too large")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise ReleaseVerificationError("SHA256SUMS must be ASCII") from exc

    entries: dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        match = CHECKSUM_RE.fullmatch(line)
        if not match:
            raise ReleaseVerificationError("Invalid or unsafe SHA256SUMS line")
        digest, name = match.groups()
        if name in entries:
            raise ReleaseVerificationError("Duplicate SHA256SUMS entry")
        entries[name] = digest.lower()
    if not entries:
        raise ReleaseVerificationError("SHA256SUMS is empty")
    return entries


def parse_sha256sums(raw: bytes, filename: str) -> str:
    """Require an unambiguous GNU sha256sum manifest with safe basenames."""
    entries = parse_sha256sums_entries(raw)
    if filename not in entries:
        raise ReleaseVerificationError("Requested asset is absent from SHA256SUMS")
    return entries[filename]


def _validate_identity(tag: str, commit: str, asset: str | None = None) -> tuple[str, str]:
    if not TAG_RE.fullmatch(tag):
        raise ReleaseVerificationError("Tag must be a full vMAJOR.MINOR.PATCH release tag")
    if not SHA_RE.fullmatch(commit):
        raise ReleaseVerificationError("Expected commit must be a full 40-character SHA")
    commit = commit.lower()
    if asset is not None:
        if (
            not ASSET_RE.fullmatch(asset)
            or not asset.startswith(f"usb-cold-wallet-{tag}.img")
        ):
            raise ReleaseVerificationError("Asset name does not match the pinned release tag")
    return tag, commit


def _verify_authorized_tag_signer(
    annotated: dict,
    authorized_tagger_emails: frozenset[str],
) -> None:
    """Bind a GitHub-verified GPG tag signature to an explicit release identity."""
    if not authorized_tagger_emails:
        raise ReleaseVerificationError("No authorized release tagger email is configured")

    verification = annotated.get("verification")
    tagger = annotated.get("tagger")
    signature = verification.get("signature") if isinstance(verification, dict) else None
    email = tagger.get("email") if isinstance(tagger, dict) else None
    if (
        not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
        or not isinstance(signature, str)
        or not signature.startswith("-----BEGIN PGP SIGNATURE-----")
        or not isinstance(email, str)
        or email not in authorized_tagger_emails
    ):
        raise ReleaseVerificationError("Tag signature is not from an authorized release identity")


def _verify_signed_tag(
    run: Run,
    tag: str,
    commit: str,
    authorized_tagger_emails: frozenset[str],
    *,
    expected_tag_object_sha: str | None = None,
) -> str:
    ref = _json(run, ["api", f"repos/{REPOSITORY}/git/ref/tags/{tag}"])
    obj = ref.get("object")
    if not isinstance(obj, dict) or obj.get("type") != "tag":
        raise ReleaseVerificationError("Lightweight or missing signed annotated tag")
    tag_sha = obj.get("sha")
    if not isinstance(tag_sha, str) or not SHA_RE.fullmatch(tag_sha):
        raise ReleaseVerificationError("Malformed annotated tag object")
    tag_sha = tag_sha.lower()
    if expected_tag_object_sha is not None and tag_sha != expected_tag_object_sha.lower():
        raise ReleaseVerificationError("Release tag object changed after validation")

    annotated = _json(run, ["api", f"repos/{REPOSITORY}/git/tags/{tag_sha}"])
    target = annotated.get("object")
    verification = annotated.get("verification")
    if (
        annotated.get("tag") != tag
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha", "").lower() != commit
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
    ):
        raise ReleaseVerificationError("Tag signature, tag name, or pinned commit mismatch")
    _verify_authorized_tag_signer(annotated, authorized_tagger_emails)
    return tag_sha


def verify_source(
    tag: str,
    commit: str,
    *,
    run: Run = _gh,
    authorized_tagger_emails: frozenset[str] = DEFAULT_AUTHORIZED_RELEASE_TAGGER_EMAILS,
    expected_tag_object_sha: str | None = None,
    trusted_workflow_sha: str | None = None,
) -> str:
    """Verify signed source and, when supplied, its ancestry in trusted main."""
    tag, commit = _validate_identity(tag, commit)
    tag_object_sha = _verify_signed_tag(
        run,
        tag,
        commit,
        authorized_tagger_emails,
        expected_tag_object_sha=expected_tag_object_sha,
    )
    if trusted_workflow_sha is not None:
        if not re.fullmatch(r"[a-f0-9]{40}", trusted_workflow_sha):
            raise ReleaseVerificationError("Trusted main workflow SHA is malformed")
        compare = _json(
            run,
            ["api", f"repos/{REPOSITORY}/compare/{commit}...{trusted_workflow_sha}"],
        )
        if (
            compare.get("status") not in ("ahead", "identical")
            or type(compare.get("behind_by")) is not int
            or compare["behind_by"] != 0
            or type(compare.get("ahead_by")) is not int
            or compare["ahead_by"] < 0
        ):
            raise ReleaseVerificationError("Signed release source is not in trusted main history")
    return tag_object_sha


def verify_protected_main_commit(expected_sha: str, *, run: Run = _gh) -> None:
    """Recheck the live protected main ref before privileged attest/publish work."""
    if not re.fullmatch(r"[a-f0-9]{40}", expected_sha):
        raise ReleaseVerificationError("Trusted main commit SHA is malformed")
    ref = _json(run, ["api", f"repos/{REPOSITORY}/git/ref/heads/main"])
    obj = ref.get("object")
    if (
        ref.get("ref") != "refs/heads/main"
        or not isinstance(obj, dict)
        or obj.get("type") != "commit"
        or obj.get("sha") != expected_sha
    ):
        raise ReleaseVerificationError("Protected main moved or returned an invalid ref")


def _active_ruleset_details(run: Run) -> list[dict]:
    try:
        summaries = json.loads(run(["api", f"repos/{REPOSITORY}/rulesets"]))
    except (ValueError, TypeError) as exc:
        raise ReleaseVerificationError("Invalid repository ruleset list") from exc
    if not isinstance(summaries, list):
        raise ReleaseVerificationError("Repository ruleset list must be an array")

    details: list[dict] = []
    for summary in summaries:
        if not isinstance(summary, dict) or summary.get("enforcement") != "active":
            continue
        ruleset_id = summary.get("id")
        if not isinstance(ruleset_id, int):
            raise ReleaseVerificationError("Active repository ruleset has no numeric id")
        detail = _json(run, ["api", f"repos/{REPOSITORY}/rulesets/{ruleset_id}"])
        if detail.get("enforcement") == "active":
            details.append(detail)
    return details


def _ruleset_includes(detail: dict, ref_pattern: str) -> bool:
    """Require an exact include with no exclusions or explicit bypass identities."""
    conditions = detail.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    bypass_actors = detail.get("bypass_actors")
    return (
        isinstance(includes, list)
        and ref_pattern in includes
        and isinstance(excludes, list)
        and not excludes
        and isinstance(bypass_actors, list)
        and not bypass_actors
    )


def verify_repository_release_controls(*, run: Run = _gh) -> None:
    """Require active main/release-tag rulesets before privileged release work."""
    details = _active_ruleset_details(run)

    main_ok = False
    tag_ok = False
    for detail in details:
        rules = detail.get("rules")
        if not isinstance(rules, list):
            continue
        by_type = {
            rule.get("type"): rule
            for rule in rules
            if isinstance(rule, dict) and isinstance(rule.get("type"), str)
        }

        if (
            detail.get("target") == "branch"
            and _ruleset_includes(detail, "refs/heads/main")
        ):
            pull_request = by_type.get("pull_request")
            required_checks = by_type.get("required_status_checks")
            pr_params = (
                pull_request.get("parameters")
                if isinstance(pull_request, dict)
                else None
            )
            check_params = (
                required_checks.get("parameters")
                if isinstance(required_checks, dict)
                else None
            )
            checks = (
                check_params.get("required_status_checks")
                if isinstance(check_params, dict)
                else None
            )
            check_by_name = {
                item.get("context"): item
                for item in checks
                if isinstance(item, dict) and isinstance(item.get("context"), str)
            } if isinstance(checks, list) else {}
            required_ci = check_by_name.get("CI / Required")
            main_ok = (
                isinstance(pr_params, dict)
                and isinstance(pr_params.get("required_approving_review_count"), int)
                and pr_params["required_approving_review_count"] >= 1
                and pr_params.get("dismiss_stale_reviews_on_push") is True
                and pr_params.get("required_review_thread_resolution") is True
                and pr_params.get("require_last_push_approval") is True
                and isinstance(check_params, dict)
                and check_params.get("strict_required_status_checks_policy") is True
                and isinstance(required_ci, dict)
                and required_ci.get("integration_id") == GITHUB_ACTIONS_APP_ID
                and {"deletion", "non_fast_forward"}.issubset(by_type)
            ) or main_ok

        if (
            detail.get("target") == "tag"
            and _ruleset_includes(detail, "refs/tags/v*")
        ):
            tag_ok = (
                {"update", "deletion"}.issubset(by_type)
                and "creation" not in by_type
            ) or tag_ok

    missing = []
    if not main_ok:
        missing.append(
            "active main ruleset with no excludes/bypass actors, >=1 approval, "
            "dismiss stale approvals, resolve review threads, last-push approval, "
            "strict GitHub-Actions-bound CI / Required, deletion protection, "
            "and non-fast-forward protection"
        )
    if not tag_ok:
        missing.append(
            "active refs/tags/v* ruleset with no excludes/bypass actors, "
            "update/deletion restrictions, and no creation restriction"
        )
    if missing:
        raise ReleaseVerificationError(
            "Repository release controls are not enforced: " + "; ".join(missing)
        )



def select_candidate_artifact(
    run_id: int | str,
    run_attempt: int | str,
    expected_head_sha: str,
    *,
    run: Run = _gh,
) -> dict:
    """Select one immutable, run-bound artifact across every API page."""
    run_id, run_attempt = str(run_id), str(run_attempt)
    if not run_id.isdigit() or not run_attempt.isdigit():
        raise ReleaseVerificationError("Candidate artifact run identity must be numeric")
    if not re.fullmatch(r"[a-f0-9]{40}", expected_head_sha):
        raise ReleaseVerificationError("Candidate artifact head SHA is malformed")

    all_artifacts: list[dict] = []
    total_count: int | None = None
    for page in range(1, 101):
        data = _json(
            run,
            [
                "api",
                f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts"
                f"?per_page=100&page={page}",
            ],
        )
        count = data.get("total_count")
        batch = data.get("artifacts")
        if (
            type(count) is not int
            or count < 0
            or count > 10000
            or not isinstance(batch, list)
            or len(batch) > 100
            or any(not isinstance(item, dict) for item in batch)
        ):
            raise ReleaseVerificationError("Candidate artifact pagination is malformed")
        if total_count is None:
            total_count = count
        elif count != total_count:
            raise ReleaseVerificationError("Candidate artifact list changed during pagination")
        all_artifacts.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ReleaseVerificationError("Candidate artifact pagination limit exceeded")
    if len(all_artifacts) != total_count:
        raise ReleaseVerificationError("Candidate artifact listing is incomplete")

    pattern = re.compile(
        r"release-candidate-v[0-9]+\.[0-9]+\.[0-9]+"
        r"(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?-[a-f0-9]{40}"
        rf"-run{re.escape(run_id)}-attempt{re.escape(run_attempt)}"
    )
    matches = [
        item for item in all_artifacts
        if item.get("expired") is False
        and isinstance(item.get("name"), str)
        and pattern.fullmatch(item["name"])
    ]
    if len(matches) != 1:
        raise ReleaseVerificationError(
            f"Expected exactly one current-attempt candidate artifact, got {len(matches)}"
        )
    item = matches[0]
    workflow_run = item.get("workflow_run")
    artifact_id = item.get("id")
    digest = item.get("digest")
    if (
        type(artifact_id) is not int
        or artifact_id <= 0
        or not isinstance(digest, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
        or not isinstance(workflow_run, dict)
        or workflow_run.get("id") != int(run_id)
        or workflow_run.get("head_sha") != expected_head_sha
    ):
        raise ReleaseVerificationError("Candidate artifact id, digest, or source is untrusted")
    return {"name": item["name"], "id": artifact_id, "digest": digest}


def verify_workflow_run_identity(
    run_id: int | str,
    expected_head_sha: str,
    *,
    expected_run_attempt: int | str | None = None,
    authorized_actor_logins: frozenset[str] = DEFAULT_AUTHORIZED_RELEASE_ACTORS,
    run: Run = _gh,
) -> dict:
    """Require a successful manual candidate run from the exact protected-main commit."""
    run_id_text = str(run_id)
    if not run_id_text.isdigit():
        raise ReleaseVerificationError("Workflow run id must be numeric")
    if not SHA_RE.fullmatch(expected_head_sha):
        raise ReleaseVerificationError("Workflow head SHA must be a full 40-character SHA")
    expected_head_sha = expected_head_sha.lower()

    data = _json(run, ["api", f"repos/{REPOSITORY}/actions/runs/{run_id_text}"])
    repository = data.get("repository")
    head_repository = data.get("head_repository")
    actor = data.get("actor")
    triggering_actor = data.get("triggering_actor")
    path = data.get("path")
    path_parts = path.split("@", 1) if isinstance(path, str) else []
    valid_path = (
        bool(path_parts)
        and path_parts[0] == ".github/workflows/release.yml"
        and (len(path_parts) == 1 or path_parts[1] == "refs/heads/main")
    )

    if (
        data.get("id") != int(run_id_text)
        or data.get("event") != "workflow_dispatch"
        or data.get("status") != "completed"
        or data.get("conclusion") != "success"
        or data.get("head_branch") != "main"
        or str(data.get("head_sha", "")).lower() != expected_head_sha
        or not valid_path
        or not isinstance(repository, dict)
        or repository.get("full_name") != REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != REPOSITORY
        or not authorized_actor_logins
        or not isinstance(actor, dict)
        or actor.get("login") not in authorized_actor_logins
        or not isinstance(triggering_actor, dict)
        or triggering_actor.get("login") not in authorized_actor_logins
    ):
        raise ReleaseVerificationError("Untrusted or mismatched candidate workflow run")

    if expected_run_attempt is not None:
        attempt = str(expected_run_attempt)
        if not attempt.isdigit() or data.get("run_attempt") != int(attempt):
            raise ReleaseVerificationError("Candidate workflow run attempt mismatch")
    return data


def build_slsa_predicate(metadata: Mapping[str, object], workflow_sha: str) -> dict:
    """Build the exact SLSA v1 predicate signed by the trusted finalizer."""
    if not SHA_RE.fullmatch(workflow_sha):
        raise ReleaseVerificationError("Trusted workflow SHA must be a full 40-character SHA")
    workflow_sha = workflow_sha.lower()

    required = {
        "repository",
        "tag",
        "source_sha",
        "tag_object_sha",
        "workflow_sha",
        "asset",
        "buildroot_version",
        "buildroot_sha256",
        "raw_image_sha256",
        "efi_partition_sha256",
        "kernel_sha256",
        "sbom_scope",
        "node_version",
        "xz_version",
        "apt_snapshot",
        "runner_image_os",
        "runner_image_version",
        "compression",
        "workflow_run_id",
        "workflow_run_attempt",
        "publish_requested",
    }
    if not isinstance(metadata, Mapping) or not required.issubset(metadata):
        raise ReleaseVerificationError("Release metadata cannot produce SLSA provenance")
    if metadata.get("repository") != REPOSITORY or metadata.get("workflow_sha") != workflow_sha:
        raise ReleaseVerificationError("Release metadata does not match trusted provenance identity")

    tag = metadata.get("tag")
    source_sha = metadata.get("source_sha")
    tag_object_sha = metadata.get("tag_object_sha")
    asset = metadata.get("asset")
    if (
        not isinstance(tag, str)
        or TAG_RE.fullmatch(tag) is None
        or not isinstance(source_sha, str)
        or SHA_RE.fullmatch(source_sha) is None
        or not isinstance(tag_object_sha, str)
        or SHA_RE.fullmatch(tag_object_sha) is None
        or not isinstance(asset, str)
        or ASSET_RE.fullmatch(asset) is None
    ):
        raise ReleaseVerificationError("Release metadata has invalid provenance identity")

    external = {
        "repository": REPOSITORY,
        "tag": tag,
        "sourceSha": source_sha.lower(),
        "tagObjectSha": tag_object_sha.lower(),
        "workflowSha": workflow_sha,
        "candidateWorkflow": ".github/workflows/release.yml",
        "candidateRunId": metadata["workflow_run_id"],
        "candidateRunAttempt": metadata["workflow_run_attempt"],
        "asset": asset,
        "publishRequested": metadata["publish_requested"],
        "aptSnapshot": metadata["apt_snapshot"],
        "nodeVersion": metadata["node_version"],
        "xzVersion": metadata["xz_version"],
        "compression": metadata["compression"],
        "sbomScope": metadata["sbom_scope"],
    }
    internal = {
        "trustedFinalizerWorkflowSha": workflow_sha,
        "rawImageSha256": metadata["raw_image_sha256"],
        "runnerImageOS": metadata["runner_image_os"],
        "runnerImageVersion": metadata["runner_image_version"],
        "bootComponentDigests": {
            "efiPartitionSha256": metadata["efi_partition_sha256"],
            "kernelSha256": metadata["kernel_sha256"],
        },
    }
    dependencies = [
        {
            "uri": f"git+https://github.com/{REPOSITORY}.git@refs/tags/{tag}",
            "digest": {"gitCommit": source_sha.lower()},
        },
        {
            "uri": f"git+https://github.com/{REPOSITORY}.git@refs/heads/main",
            "digest": {"gitCommit": workflow_sha},
        },
        {
            "uri": (
                "https://buildroot.org/downloads/"
                f"buildroot-{metadata['buildroot_version']}.tar.xz"
            ),
            "digest": {"sha256": metadata["buildroot_sha256"]},
        },
    ]
    return {
        "buildDefinition": {
            "buildType": (
                f"{SLSA_BUILD_TYPE_PREFIX}{workflow_sha}/docs/RELEASE_VERIFICATION.md"
                "#release-build-attestation"
            ),
            "externalParameters": external,
            "internalParameters": internal,
            "resolvedDependencies": dependencies,
        },
        "runDetails": {
            "builder": {
                "id": SLSA_BUILDER_ID,
            }
        },
    }


def _attest_args(image: Path, workflow_sha: str) -> list[str]:
    if not SHA_RE.fullmatch(workflow_sha):
        raise ReleaseVerificationError("Trusted workflow SHA must be a full 40-character SHA")
    workflow_sha = workflow_sha.lower()
    return [
        "attestation",
        "verify",
        str(image),
        "-R",
        REPOSITORY,
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        workflow_sha,
        "--signer-workflow",
        RELEASE_WORKFLOW,
        "--signer-digest",
        workflow_sha,
        "--predicate-type",
        SLSA_PREDICATE_TYPE,
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]


def _verify_metadata(
    path: Path,
    tag: str,
    commit: str,
    workflow_sha: str,
    tag_object_sha: str,
    asset: str,
) -> None:
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseVerificationError("Invalid release-metadata.json") from exc
    if not isinstance(metadata, dict):
        raise ReleaseVerificationError("release-metadata.json must contain an object")

    expected = {
        "repository": REPOSITORY,
        "tag": tag,
        "source_sha": commit,
        "workflow_sha": workflow_sha,
        "tag_object_sha": tag_object_sha,
        "workflow": ".github/workflows/release.yml",
        "attestation_workflow": ".github/workflows/release-finalize.yml",
        "asset": asset,
        "compression": "xz -6 --threads=1 --check=crc64 --no-sparse",
        "reproducibility_runs": 2,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ReleaseVerificationError(f"Release metadata mismatch: {key}")

    for key in ("raw_image_sha256", "efi_partition_sha256", "kernel_sha256"):
        digest = metadata.get(key)
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")
    if metadata.get("sbom_scope") != "buildroot-target-rootfs":
        raise ReleaseVerificationError("Release metadata has invalid SBOM scope")
    for key in ("buildroot_sha256",):
        value = metadata.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")
    for key in ("buildroot_version", "node_version", "xz_version"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value or len(value) > 80:
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")
    apt_snapshot = metadata.get("apt_snapshot")
    if not isinstance(apt_snapshot, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", apt_snapshot):
        raise ReleaseVerificationError("Release metadata has invalid apt snapshot")
    for key in ("runner_image_os", "runner_image_version"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value or len(value) > 120:
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")
    if not isinstance(metadata.get("publish_requested"), bool):
        raise ReleaseVerificationError("Release metadata has invalid publish_requested flag")
    for key in ("workflow_run_id", "workflow_run_attempt"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value.isdigit():
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")


def _verify_spdx(path: Path) -> None:
    try:
        sbom = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseVerificationError("Invalid SPDX SBOM") from exc
    if (
        not isinstance(sbom, dict)
        or sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("SPDXID") != "SPDXRef-DOCUMENT"
        or sbom.get("dataLicense") != "CC0-1.0"
    ):
        raise ReleaseVerificationError("SPDX SBOM identity is invalid")


def _verify_build_provenance(
    run: Run,
    directory: Path,
    names: list[str],
    workflow_sha: str,
    metadata: Mapping[str, object],
) -> None:
    expected_predicate = build_slsa_predicate(metadata, workflow_sha)
    for name in names:
        raw = run(_attest_args(_safe_file(directory, name), workflow_sha))
        try:
            results = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ReleaseVerificationError("Invalid attestation verification JSON") from exc
        if not isinstance(results, list) or not results:
            raise ReleaseVerificationError("No verified SLSA provenance returned")
        matched = False
        for result in results:
            if not isinstance(result, dict):
                continue
            verification = result.get("verificationResult")
            statement = verification.get("statement") if isinstance(verification, dict) else None
            if (
                isinstance(statement, dict)
                and statement.get("predicateType") == SLSA_PREDICATE_TYPE
                and statement.get("predicate") == expected_predicate
            ):
                matched = True
                break
        if not matched:
            raise ReleaseVerificationError(
                f"SLSA provenance does not bind the expected release source: {name}"
            )


def verify_candidate_artifacts(
    tag: str,
    commit: str,
    asset: str,
    directory: str | Path,
    *,
    workflow_sha: str,
    run: Run = _gh,
    authorized_tagger_emails: frozenset[str] = DEFAULT_AUTHORIZED_RELEASE_TAGGER_EMAILS,
    expected_tag_object_sha: str | None = None,
    expected_run_id: int | str | None = None,
    expected_run_attempt: int | str | None = None,
) -> str:
    """Verify staged candidate bytes before any privileged attestation or publish step."""
    tag, commit = _validate_identity(tag, commit, asset)
    tag_object_sha = verify_source(
        tag,
        commit,
        run=run,
        authorized_tagger_emails=authorized_tagger_emails,
        expected_tag_object_sha=expected_tag_object_sha,
        trusted_workflow_sha=workflow_sha,
    )

    root = Path(directory)
    if not root.is_dir() or root.is_symlink():
        raise ReleaseVerificationError("Local release directory is missing or unsafe")

    manifest = _safe_file(root, "SHA256SUMS")
    entries = parse_sha256sums_entries(manifest.read_bytes())
    expected_names = {asset, *REQUIRED_STAGED_FILES}
    if {entry.name for entry in root.iterdir()} != expected_names | {"SHA256SUMS"}:
        raise ReleaseVerificationError("Unexpected file or directory in candidate artifact")
    limits = {
        asset: MAX_COMPRESSED_IMAGE_BYTES,
        "SBOM.spdx.json": 256 * 1024 * 1024,
        "release-metadata.json": MAX_MANIFEST_BYTES,
        "build-host-packages.txt": 8 * 1024 * 1024,
    }
    for name, max_bytes in limits.items():
        if _safe_file(root, name).stat().st_size > max_bytes:
            raise ReleaseVerificationError(f"Candidate artifact exceeds limit: {name}")
    if set(entries) != expected_names:
        raise ReleaseVerificationError(
            "SHA256SUMS must cover exactly the final image, SBOM, and release metadata"
        )

    for name, expected_digest in entries.items():
        actual_digest = _sha256(_safe_file(root, name))
        if actual_digest != expected_digest:
            raise ReleaseVerificationError(f"Staged release digest mismatch: {name}")

    metadata_path = _safe_file(root, "release-metadata.json")
    _verify_metadata(
        metadata_path,
        tag,
        commit,
        workflow_sha,
        tag_object_sha,
        asset,
    )
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseVerificationError("Invalid release-metadata.json") from exc

    if expected_run_id is not None and metadata.get("workflow_run_id") != str(expected_run_id):
        raise ReleaseVerificationError("Release metadata workflow run id mismatch")
    if (
        expected_run_attempt is not None
        and metadata.get("workflow_run_attempt") != str(expected_run_attempt)
    ):
        raise ReleaseVerificationError("Release metadata workflow run attempt mismatch")

    if _raw_image_sha256(_safe_file(root, asset)) != metadata["raw_image_sha256"]:
        raise ReleaseVerificationError("Delivered compressed image does not match claimed raw SHA-256")
    _verify_spdx(_safe_file(root, "SBOM.spdx.json"))
    return _sha256(_safe_file(root, asset))


def verify_local_artifacts(
    tag: str,
    commit: str,
    asset: str,
    directory: str | Path,
    *,
    workflow_sha: str,
    run: Run = _gh,
    authorized_tagger_emails: frozenset[str] = DEFAULT_AUTHORIZED_RELEASE_TAGGER_EMAILS,
    expected_tag_object_sha: str | None = None,
    expected_run_id: int | str | None = None,
    expected_run_attempt: int | str | None = None,
) -> str:
    """Verify the exact staged bytes after attestation and before publish."""
    digest = verify_candidate_artifacts(
        tag,
        commit,
        asset,
        directory,
        workflow_sha=workflow_sha,
        run=run,
        authorized_tagger_emails=authorized_tagger_emails,
        expected_tag_object_sha=expected_tag_object_sha,
        expected_run_id=expected_run_id,
        expected_run_attempt=expected_run_attempt,
    )
    root = Path(directory)
    metadata_path = _safe_file(root, "release-metadata.json")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseVerificationError("Invalid release-metadata.json") from exc
    _verify_build_provenance(
        run,
        root,
        ["SHA256SUMS", asset, *REQUIRED_STAGED_FILES],
        workflow_sha,
        metadata,
    )
    return digest

def require_successful_jobs(job_results: Mapping[str, str]) -> None:
    """Fail closed unless every required release job completed successfully."""
    required = {"build", "attest", "verify"}
    if set(job_results) != required:
        raise ReleaseVerificationError("Release gate is missing a required job result")
    failed = [name for name in sorted(required) if job_results.get(name) != "success"]
    if failed:
        raise ReleaseVerificationError(
            "Required release jobs did not succeed: " + ", ".join(failed)
        )


def verify_release(
    tag: str,
    commit: str,
    asset: str,
    *,
    workflow_sha: str,
    run: Run = _gh,
    authorized_tagger_emails: frozenset[str] = DEFAULT_AUTHORIZED_RELEASE_TAGGER_EMAILS,
    expected_tag_object_sha: str | None = None,
) -> str:
    """Independently download and verify an already-published immutable release."""
    tag, commit = _validate_identity(tag, commit, asset)
    tag_object_sha = verify_source(
        tag,
        commit,
        run=run,
        authorized_tagger_emails=authorized_tagger_emails,
        expected_tag_object_sha=expected_tag_object_sha,
        trusted_workflow_sha=workflow_sha,
    )

    release = _json(
        run,
        ["release", "view", tag, "-R", REPOSITORY, "--json", "tagName,isDraft"],
    )
    if release.get("tagName") != tag or release.get("isDraft") is not False:
        raise ReleaseVerificationError("Release is draft or points to a different tag")

    # This checks GitHub's immutable-release integrity attestation, not the
    # separate build provenance attestation verified below.
    run(["release", "verify", tag, "-R", REPOSITORY])

    with tempfile.TemporaryDirectory(prefix="wallet-release-verify-") as temp:
        directory = Path(temp)
        release_files = ["SHA256SUMS", asset, *REQUIRED_STAGED_FILES]
        for name in release_files:
            run(
                [
                    "release",
                    "download",
                    tag,
                    "-R",
                    REPOSITORY,
                    "--pattern",
                    name,
                    "--dir",
                    str(directory),
                ]
            )
            _safe_file(directory, name)

        manifest = _safe_file(directory, "SHA256SUMS")
        entries = parse_sha256sums_entries(manifest.read_bytes())
        expected_names = {asset, *REQUIRED_STAGED_FILES}
        if set(entries) != expected_names:
            raise ReleaseVerificationError(
                "SHA256SUMS must cover exactly every published payload file"
            )
        for name, expected_digest in entries.items():
            if _sha256(_safe_file(directory, name)) != expected_digest:
                raise ReleaseVerificationError(f"Downloaded release digest mismatch: {name}")

        image = _safe_file(directory, asset)
        actual = _sha256(image)
        _verify_metadata(
            _safe_file(directory, "release-metadata.json"),
            tag,
            commit,
            workflow_sha,
            tag_object_sha,
            asset,
        )
        _verify_spdx(_safe_file(directory, "SBOM.spdx.json"))
        try:
            metadata = json.loads(
                _safe_file(directory, "release-metadata.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ReleaseVerificationError("Invalid release-metadata.json") from exc
        if _raw_image_sha256(image) != metadata["raw_image_sha256"]:
            raise ReleaseVerificationError("Published raw image SHA-256 does not match metadata")

        # Authenticate every published file with immutable-release integrity
        # and the same SLSA source/workflow identity.
        for name in release_files:
            run(
                [
                    "release",
                    "verify-asset",
                    tag,
                    str(directory / name),
                    "-R",
                    REPOSITORY,
                ]
            )
        _verify_build_provenance(
            run,
            directory,
            release_files,
            workflow_sha,
            metadata,
        )
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Signed annotated release tag")
    parser.add_argument(
        "--commit",
        required=True,
        help="Independently pinned source commit SHA",
    )
    parser.add_argument("--asset", help="Exact .img or .img.xz asset name")
    parser.add_argument(
        "--workflow-sha",
        help="Exact trusted main commit containing the release workflow definition",
    )
    parser.add_argument(
        "--expected-tag-object-sha",
        help="Optional annotated tag object SHA pinned by the validate job",
    )
    parser.add_argument(
        "--local-dir",
        help="Verify already-built final bytes in this directory; never downloads assets",
    )
    parser.add_argument("--expected-run-id", help="Expected candidate workflow run ID")
    parser.add_argument("--expected-run-attempt", help="Expected candidate run attempt")
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="Verify only signed tag -> exact source commit binding",
    )
    parser.add_argument(
        "--candidate-only",
        action="store_true",
        help="Verify staged candidate bytes before privileged attestation",
    )
    args = parser.parse_args()

    try:
        if args.source_only:
            if args.asset or args.local_dir or args.candidate_only or args.expected_run_id or args.expected_run_attempt:
                raise ReleaseVerificationError(
                    "--source-only cannot be combined with artifact verification options"
                )
            tag_object_sha = verify_source(
                args.tag,
                args.commit,
                expected_tag_object_sha=args.expected_tag_object_sha,
            )
            print(
                f"VERIFIED SOURCE: {args.tag} -> {args.commit.lower()} "
                f"tag-object:{tag_object_sha}"
            )
            return 0

        if not args.asset:
            raise ReleaseVerificationError("--asset is required for artifact verification")
        if not args.workflow_sha:
            raise ReleaseVerificationError("--workflow-sha is required for artifact verification")

        if args.candidate_only:
            if not args.local_dir:
                raise ReleaseVerificationError("--candidate-only requires --local-dir")
            digest = verify_candidate_artifacts(
                args.tag,
                args.commit,
                args.asset,
                args.local_dir,
                workflow_sha=args.workflow_sha,
                expected_tag_object_sha=args.expected_tag_object_sha,
                expected_run_id=args.expected_run_id,
                expected_run_attempt=args.expected_run_attempt,
            )
        elif args.local_dir:
            digest = verify_local_artifacts(
                args.tag,
                args.commit,
                args.asset,
                args.local_dir,
                workflow_sha=args.workflow_sha,
                expected_tag_object_sha=args.expected_tag_object_sha,
                expected_run_id=args.expected_run_id,
                expected_run_attempt=args.expected_run_attempt,
            )
        else:
            if args.expected_run_id or args.expected_run_attempt:
                raise ReleaseVerificationError("Run identity pin requires --local-dir")
            digest = verify_release(
                args.tag,
                args.commit,
                args.asset,
                workflow_sha=args.workflow_sha,
                expected_tag_object_sha=args.expected_tag_object_sha,
            )
    except ReleaseVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"VERIFIED: {args.asset} sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

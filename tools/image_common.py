from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class ImageBuildError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ImageBuildError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ImageBuildError(f"expected JSON object in {path}")
    return value


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256sums(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise ImageBuildError(f"malformed SHA256SUMS line: {line!r}")
        digest, filename = parts
        filename = filename.lstrip("*")
        if "/" in filename or filename in {".", ".."}:
            raise ImageBuildError(f"unsafe checksum filename: {filename!r}")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise ImageBuildError(f"invalid SHA-256 digest: {digest!r}") from exc
        if filename in result:
            raise ImageBuildError(f"duplicate checksum entry: {filename}")
        result[filename] = digest.lower()
    return result


def normalized_fingerprint(value: str) -> str:
    compact = "".join(value.split()).upper()
    if len(compact) != 40:
        raise ImageBuildError("OpenPGP fingerprint must be 40 hexadecimal characters")
    try:
        int(compact, 16)
    except ValueError as exc:
        raise ImageBuildError("OpenPGP fingerprint is not hexadecimal") from exc
    return compact


def validate_lock_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if manifest.get("schema") != 1:
        raise ImageBuildError("unsupported Python artifact lock schema")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ImageBuildError("Python artifact lock has no artifacts")
    names: set[str] = set()
    files: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ImageBuildError("artifact entry must be an object")
        for key in ("package", "version", "filename", "sha256", "kind"):
            if not isinstance(artifact.get(key), str) or not artifact[key]:
                raise ImageBuildError(f"artifact missing {key}")
        filename = artifact["filename"]
        if Path(filename).name != filename:
            raise ImageBuildError(f"unsafe artifact filename: {filename}")
        digest = artifact["sha256"].lower()
        if len(digest) != 64:
            raise ImageBuildError(f"invalid SHA-256 for {filename}")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise ImageBuildError(f"invalid SHA-256 for {filename}") from exc
        key = f"{artifact['package'].lower()}=={artifact['version']}"
        if key in names:
            raise ImageBuildError(f"duplicate package/version: {key}")
        if filename in files:
            raise ImageBuildError(f"duplicate artifact filename: {filename}")
        if artifact["kind"] not in {"wheel", "sdist"}:
            raise ImageBuildError(f"unsupported artifact kind for {filename}")
        names.add(key)
        files.add(filename)
    return artifacts

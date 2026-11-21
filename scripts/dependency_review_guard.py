"""Fail closed unless the current asynchronous GitHub Dependency Graph API works.

GitHub retired the synchronous GET /dependency-graph/sbom on 2026-11-13.
Requesting the new asynchronous export proves that the Graph service can
start an SBOM job; the separate dependency-review-action must *also* pass.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


def dependency_graph_status_error(
    status: str, response: str, repo: str, api_url: str
) -> str | None:
    if status != "201":
        if status in {"401", "403", "404"}:
            return (
                "GitHub asynchronous Dependency Graph SBOM request is unavailable "
                f"(HTTP {status}); check repository Dependency Graph access/permissions"
            )
        return f"GitHub asynchronous Dependency Graph SBOM request failed (HTTP {status})"
    try:
        obj = json.loads(response)
        if not isinstance(obj, dict) or type(obj.get("sbom_url")) is not str:
            raise ValueError("Missing sbom_url")
        url = urlsplit(obj["sbom_url"])
        base = urlsplit(api_url)
        prefix = base.path.rstrip("/") + f"/repos/{repo}/dependency-graph/sbom/fetch-report/"
        report_id = url.path.removeprefix(prefix)
        if (
            url.scheme != base.scheme or url.netloc != base.netloc
            or not url.path.startswith(prefix) or url.query or url.fragment
            or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", report_id)
        ):
            raise ValueError("Unexpected SBOM report URL")
    except (ValueError, TypeError) as exc:
        return f"GitHub asynchronous SBOM response was invalid: {exc}"
    return None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 4:
        print(
            "::error::usage: dependency_review_guard.py HTTP_STATUS RESPONSE_PATH REPO API_URL",
            file=sys.stderr,
        )
        return 2
    try:
        response = Path(args[1]).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"::error::Cannot read SBOM API response: {exc}", file=sys.stderr)
        return 1
    error = dependency_graph_status_error(args[0], response, args[2], args[3])
    if error is not None:
        print("::error::" + error, file=sys.stderr)
        return 1
    print("Async Dependency Graph request accepted; proceeding to required Dependency Review action")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Fail closed when GitHub's Dependency Graph cannot run real dependency review.

A successful job with a skipped dependency-review step is not an acceptable
supply-chain security gate.
"""
from __future__ import annotations

import sys


def dependency_graph_status_error(status: str) -> str | None:
    if status == "200":
        return None
    if status in {"403", "404"}:
        return (
            "GitHub Dependency Graph is disabled or unavailable to this token "
            f"(HTTP {status}); enable Dependency Graph / grant access before "
            "merging dependency or workflow changes"
        )
    return f"Cannot verify GitHub Dependency Graph availability (HTTP {status})"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("::error::usage: dependency_review_guard.py HTTP_STATUS", file=sys.stderr)
        return 2
    error = dependency_graph_status_error(args[0])
    if error is not None:
        print("::error::" + error, file=sys.stderr)
        return 1
    print("Dependency Graph API available; dependency-review action must run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

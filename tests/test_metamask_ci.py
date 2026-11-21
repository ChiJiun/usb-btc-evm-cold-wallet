"""Check that the native QR CI cannot silently lose required security jobs.

This test runs in the pinned Python test matrix; a later merge with the
path-aware CI (#38) must retain the Native QR Node/Chromium integration gate.
"""
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


def test_native_qr_compatibility_is_required_in_ci():
    content = WORKFLOW.read_text(encoding="utf-8")
    assert "  metamask_native_qr:" in content
    assert "    name: MetaMask native QR / Node 24" in content
    assert "npm run test:browser" in content
    assert "npm run test:python" in content
    assert "npm run build --prefix qr-metamask" in content
    assert "    name: CI / Required" in content
    required = content.split("\n  required:", 1)[1]
    assert "      - metamask_native_qr" in required
    assert "NATIVE_QR: ${{ needs.metamask_native_qr.result }}" in required
    assert 'test "$NATIVE_QR" = "success"' in required or (
        'require("NATIVE_QR"' in (
            Path(__file__).resolve().parents[1] / "scripts/ci_checks.py"
        ).read_text(encoding="utf-8")
    )


def test_dependency_review_never_skips_on_pr_when_graph_is_unavailable():
    content = WORKFLOW.read_text(encoding="utf-8")
    review = content.split("\n  dependency_review:", 1)[1].split(
        "\n  reproducible_build:", 1
    )[0]
    assert "uses: actions/dependency-review-action@" in review
    assert "Review dependency changes (required)" in review
    assert "if: steps.dependency-graph.outputs.available" not in review
    assert "dependency-graph/sbom" not in review
    assert "Detect Dependency Graph availability" not in review
    required = content.split("\n  required:", 1)[1]
    assert "      - dependency_review" in required
    required_gate = (
        Path(__file__).resolve().parents[1] / "scripts/ci_checks.py"
    ).read_text(encoding="utf-8")
    assert ('test "$DEPENDENCY_REVIEW" = "success"' in required or
            '"DEPENDENCY_REVIEW",' in required_gate)
    assert 'env.get("EVENT_NAME") == "pull_request" and deps == "true"' in required_gate


def test_qr_transport_must_fail_when_manifest_is_missing():
    content = WORKFLOW.read_text(encoding="utf-8")
    job = content.split("\n  qr_transport:", 1)[1].split(
        "\n  metamask_native_qr:", 1
    )[0]
    assert "test -f qr-transport/package.json" in job
    assert "test -f qr-transport/package-lock.json" in job
    assert "steps.qr.outputs.present" not in job

#!/usr/bin/python3
from __future__ import annotations

import argparse
import json
import os
import resource
import subprocess
import sys
from pathlib import Path
from typing import Callable

POLICY_PATH = Path("/opt/usb-cold-wallet/runtime-policy.json")
STATE_DIR = Path("/run/usb-cold-wallet")
PASS_MARKER = STATE_DIR / "airgap-ok"
APPLIED_MARKER = STATE_DIR / "airgap-applied"


def _result(name: str, ok: bool, detail: str) -> dict[str, object]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def load_policy(path: Path = POLICY_PATH) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != 1:
        raise ValueError("unsupported runtime policy schema")
    return value


def check_boot_cmdline(cmdline: str, policy: dict) -> dict[str, object]:
    tokens = cmdline.split()
    token_set = set(tokens)
    missing = [token for token in policy["required_boot_tokens"] if token not in token_set]
    forbidden = [token for token in policy["forbidden_boot_tokens"] if token in token_set]
    for prefix in policy["forbidden_boot_prefixes"]:
        forbidden.extend(token for token in tokens if token.startswith(prefix))
    ok = not missing and not forbidden
    detail = f"missing={missing or 'none'} forbidden={sorted(set(forbidden)) or 'none'}"
    return _result("boot_parameters", ok, detail)


def check_swaps(swaps_text: str) -> dict[str, object]:
    active = [line for line in swaps_text.splitlines()[1:] if line.strip()]
    return _result("swap", not active, "no active swap" if not active else "; ".join(active))


def check_core_limit() -> dict[str, object]:
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    ok = soft == 0 and hard == 0
    return _result("core_dump_limit", ok, f"RLIMIT_CORE soft={soft} hard={hard}")


def check_masked_units(root: Path, policy: dict) -> dict[str, object]:
    failures: list[str] = []
    unit_dir = root / "etc/systemd/system"
    for unit in policy["masked_units"]:
        path = unit_dir / unit
        if not path.is_symlink() or os.readlink(path) != "/dev/null":
            failures.append(unit)
    return _result(
        "masked_units",
        not failures,
        "all policy units masked" if not failures else "not masked: " + ", ".join(failures),
    )


def check_network_interfaces(root: Path) -> dict[str, object]:
    path = root / "etc/network/interfaces"
    try:
        effective = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError as exc:
        return _result("interfaces_config", False, str(exc))
    expected = ["auto lo", "iface lo inet loopback"]
    return _result(
        "interfaces_config",
        effective == expected,
        "loopback only" if effective == expected else f"unexpected configuration: {effective}",
    )


def check_resolver(root: Path) -> dict[str, object]:
    path = root / "etc/resolv.conf"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return _result("resolver_config", False, str(exc))
    nameservers = [
        line for line in text.splitlines() if line.strip().lower().startswith("nameserver ")
    ]
    return _result(
        "resolver_config",
        not nameservers,
        "no DNS nameservers configured" if not nameservers else f"nameservers present: {nameservers}",
    )


def check_static_files(root: Path, policy: dict) -> list[dict[str, object]]:
    checks = [
        check_masked_units(root, policy),
        check_network_interfaces(root),
        check_resolver(root),
    ]
    required = {
        "wallet_wrapper": root / "usr/local/bin/usb-cold-wallet",
        "airgap_script": root / "usr/local/sbin/usb-cold-wallet-airgap",
        "audit_script": root / "usr/local/sbin/usb-cold-wallet-offline-audit",
        "runtime_policy": root / "opt/usb-cold-wallet/runtime-policy.json",
        "artifact_manifest": root / "opt/usb-cold-wallet/site-packages/USB_COLD_WALLET_ARTIFACTS.json",
    }
    for name, path in required.items():
        checks.append(_result(name, path.is_file(), str(path)))
    return checks


def _run(command: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
    completed = subprocess.run(command, text=True, capture_output=True, check=False, env=env)
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def check_interface_flags(sys_class_net: Path = Path("/sys/class/net")) -> dict[str, object]:
    up: list[str] = []
    try:
        entries = list(sys_class_net.iterdir())
    except OSError as exc:
        return _result("interfaces_down", False, str(exc))
    for interface in entries:
        if interface.name == "lo":
            continue
        try:
            flags = int((interface / "flags").read_text(encoding="ascii").strip(), 16)
        except (OSError, ValueError) as exc:
            return _result("interfaces_down", False, f"{interface.name}: {exc}")
        if flags & 0x1:
            up.append(interface.name)
    return _result(
        "interfaces_down",
        not up,
        "all non-loopback interfaces DOWN" if not up else "UP: " + ", ".join(sorted(up)),
    )


def check_no_global_addresses() -> dict[str, object]:
    rc, out, err = _run(["ip", "-o", "addr", "show", "scope", "global"])
    if rc != 0:
        return _result("global_addresses", False, err or f"ip exited {rc}")
    return _result(
        "global_addresses",
        not out,
        "no global addresses" if not out else out.replace("\n", "; "),
    )


def check_nft_chain(family: str, table: str, chain: str) -> dict[str, object]:
    rc, out, err = _run(["nft", "list", "chain", family, table, chain])
    ok = rc == 0 and "hook " in out and "policy drop;" in out
    return _result(
        f"nft_{family}_{chain}",
        ok,
        "base chain policy DROP" if ok else (err or out or f"nft exited {rc}"),
    )


def check_mounts(policy: dict) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    rc, fstype, err = _run(["findmnt", "-n", "-o", "FSTYPE", "/"])
    allowed = set(policy["allowed_root_filesystems"])
    checks.append(
        _result(
            "live_root",
            rc == 0 and fstype in allowed,
            f"root fstype={fstype or err or 'unknown'} allowed={sorted(allowed)}",
        )
    )
    mountpoint = policy["live_medium_mount"]
    rc, options, err = _run(["findmnt", "-n", "-o", "OPTIONS", mountpoint])
    opts = set(options.split(",")) if rc == 0 else set()
    checks.append(
        _result(
            "live_medium_read_only",
            rc == 0 and "ro" in opts and "rw" not in opts,
            f"{mountpoint} options={options or err or 'unknown'}",
        )
    )
    return checks


def check_python_runtime() -> dict[str, object]:
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    code = (
        "import sys;"
        "sys.path.insert(0,'/opt/usb-cold-wallet/site-packages');"
        "import embit,eth_account,cryptography,usb_cold_wallet;"
        "print('imports-ok')"
    )
    rc, out, err = _run(["/usr/bin/python3", "-I", "-B", "-c", code], env=env)
    return _result("python_runtime", rc == 0 and out == "imports-ok", err or out)


def audit_runtime(policy: dict) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    checks.append(_result("airgap_applied", APPLIED_MARKER.is_file(), str(APPLIED_MARKER)))
    try:
        checks.append(check_boot_cmdline(Path("/proc/cmdline").read_text(encoding="utf-8"), policy))
    except OSError as exc:
        checks.append(_result("boot_parameters", False, str(exc)))
    try:
        checks.append(check_swaps(Path("/proc/swaps").read_text(encoding="utf-8")))
    except OSError as exc:
        checks.append(_result("swap", False, str(exc)))
    checks.append(check_core_limit())
    checks.append(check_interface_flags())
    checks.append(check_no_global_addresses())
    checks.append(check_nft_chain("inet", "usb_cold_wallet", "output"))
    checks.append(check_nft_chain("inet", "usb_cold_wallet", "input"))
    checks.append(check_nft_chain("arp", "usb_cold_wallet_arp", "output"))
    checks.extend(check_mounts(policy))
    checks.append(check_python_runtime())
    return checks


def summarize(checks: list[dict[str, object]]) -> dict[str, object]:
    failed = [str(check["name"]) for check in checks if not check["ok"]]
    return {"ok": not failed, "failed": failed, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the cold-wallet Live system before unlocking secrets")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--static-root",
        type=Path,
        help="audit an extracted root filesystem instead of the currently booted live system",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help="override policy path (mainly for image-build tests)",
    )
    args = parser.parse_args()

    policy_path = args.policy or (
        args.static_root / "opt/usb-cold-wallet/runtime-policy.json"
        if args.static_root
        else POLICY_PATH
    )
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"OFFLINE AUDIT ERROR: cannot load policy: {exc}", file=sys.stderr)
        return 2

    if args.static_root:
        checks = check_static_files(args.static_root, policy)
    else:
        PASS_MARKER.unlink(missing_ok=True)
        checks = check_static_files(Path("/"), policy)
        checks.extend(audit_runtime(policy))

    report = summarize(checks)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for check in checks:
            state = "PASS" if check["ok"] else "FAIL"
            print(f"[{state}] {check['name']}: {check['detail']}")
        print("OFFLINE AUDIT: " + ("PASS" if report["ok"] else "FAIL"))

    if report["ok"] and not args.static_root:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        PASS_MARKER.write_text("offline audit passed\n", encoding="utf-8")
        PASS_MARKER.chmod(0o600)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

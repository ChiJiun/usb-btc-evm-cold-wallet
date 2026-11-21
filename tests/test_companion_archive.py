"""Prevent archive guard from accepting arbitrary bundled cold modules."""
import pytest

from scripts.check_windows_companion_archive import examine_listing

PUBLIC = "\n".join([
    "'usb_cold_wallet'",
    "'usb_cold_wallet.companion_core'",
    "'usb_cold_wallet.companion_btc'",
    "'usb_cold_wallet.companion_web'",
    "'usb_cold_wallet.companion_portable'",
    "'usb_cold_wallet.companion_envelope'",
    "'usb_cold_wallet.companion_static.index.html'",
    "'usb_cold_wallet.companion_static.companion.css'",
    "'usb_cold_wallet.companion_static.companion.js'",
])


def test_only_online_modules_are_allowed():
    assert "usb_cold_wallet.companion_core" in examine_listing(PUBLIC)


@pytest.mark.parametrize("forbidden", [
    "vault", "keys", "btc", "evm", "recovery", "cli", "gui", "policy",
    "review", "signer_session", "exchange", "qr_workflow", "keystone_public",
])
def test_offline_module_exposure_fails_closed(forbidden):
    with pytest.raises(AssertionError, match="Offline or unknown"):
        examine_listing(PUBLIC + "\n" + repr("usb_cold_wallet." + forbidden))


def test_unknown_local_package_module_is_forbidden():
    with pytest.raises(AssertionError, match="Offline or unknown"):
        examine_listing(PUBLIC + "\n'usb_cold_wallet.unreviewed_feature'")


def test_missing_required_public_module_is_error():
    with pytest.raises(AssertionError, match="Missing watch-only"):
        examine_listing(PUBLIC.replace("'usb_cold_wallet.companion_btc'", ""))


@pytest.mark.parametrize("unapproved", [
    "companion_static.extra.js", "companion_static.secret.py",
    "companion_static.recovery.json", "companion_static.index.hta",
])
def test_frontend_asset_allowlist_is_exact(unapproved):
    with pytest.raises(AssertionError, match="Offline or unknown"):
        examine_listing(PUBLIC + "\n" + repr("usb_cold_wallet." + unapproved))

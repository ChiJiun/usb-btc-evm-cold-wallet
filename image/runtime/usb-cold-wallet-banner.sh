if [ -t 1 ]; then
    echo
    echo "USB Cold Wallet — TESTNET RESEARCH IMAGE"
    echo "Network is software-blocked, persistence is disabled, and swap is off."
    echo "Still physically disconnect Ethernet and disable/remove radios."
    if [ -f /run/usb-cold-wallet/airgap-ok ]; then
        echo "Boot audit: PASS"
    else
        echo "Boot audit: NOT PASSED — do not unlock a wallet."
    fi
    echo
fi

from __future__ import annotations

import sys

SITE_PACKAGES = "/opt/usb-cold-wallet/site-packages"
if SITE_PACKAGES not in sys.path:
    sys.path.insert(0, SITE_PACKAGES)

from usb_cold_wallet.cli import main

raise SystemExit(main())

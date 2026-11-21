# Replayed PSBT crash regressions

Keep only public synthetic PSBT payloads named by SHA-256, e.g. `<sha256>.psbt`. Never add actual wallet PSBTs or private keys. A saved sample must fail closed or pass the approved policy on replay; any uncaught exception or timeout fails CI. Pair triaged samples with a targeted pytest assertion. This directory may be empty until a reproducible crash is discovered.

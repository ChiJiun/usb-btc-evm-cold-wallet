# ERC-20 / EIP-712 runtime staging (#3, #21)

The reviewed parsers from PR #65 are now installed under `src/usb_cold_wallet/evm_erc20.py` and `evm_eip712.py`. They are included in the regular Python wheel, with no added online dependencies.

## Current permitted boundary

- Only Sepolia (chainId 11155111). ERC-20 `transfer(address,uint256)` / `approve(address,uint256)` and two exact, custom EIP-712 `Wallet*Intent` schemas may be **decoded for offline human review**.
- An empty `contract_rules` allowlist is the default. An allowlisted ERC-20 review requires a rule in the encrypted, wallet-bound offline policy: checksummed contract, method, checksummed counterparty, uint256 maximum amount and exact expected nonce. The rule must be configured using authenticated offline policy operations; no online-supplied ABI, token name/symbol, decimals or RPC label authorizes a contract.
- `decide_erc20` returns existing `PolicyDecision` values, and `build_erc20_review_pages` / `build_eip712_review_pages` return the existing transport-neutral `ReviewPage` fields. **ALLOW_FOR_REVIEW is not a signature authorization.** Current contract approvals require explicit extra review, and contract signing is still disabled.
- `approve(spender,0)` is identified as a distinct revoke case. Unlimited approvals, dirty ABI, unknown calldata, wrong chain, unexpected nonce, wrong contract, wrong spender, and excessive gas/fees are rejected.
- EIP-712 currently has no deploy-verified contract identity, trusted nonce consumption, hardware-backed clock or replay-safe state; `build_eip712_review_pages` only accepts explicit trusted-approval arguments and never exposes signing.
- The original `evm.py::sign_evm` and native ETH signing remain unchanged. No Ethereum mainnet, blind signing, Permit/Permit2, arbitrary contracts or automatic approval.
- No changes to Buildroot/Tk packaging or #19 GUI wiring. GUI integrators may consume new `ReviewPage` fields once a separate authenticated offline policy flow and manual confirmation are implemented.

## Remaining gates before contract signing

1. Offline authenticated rule enrollment/edit/delete UI, full-address confirmation and sealed profile persistence/rollback/restore tests.
2. Source-verifiable, network-specific deployed token contract registry and actual code/semantics verification, instead of trusting names, symbols or online ABIs.
3. Request-vs-intent binding with fresh nonce source and signed-byte E2E with independent Ethereum libraries, transaction-account recovery, fee cap and explicit on-device approval.
4. EIP-712 deployed verifier + nonce consumption/replay analysis; only then consider scoped typed-data signing.
5. Physical USB/Tk GUI manual-review verification (including adversarial cases).

Run the existing independent PR #65 tests and new runtime-policy tests in CI before declaring completion. Neither issue #3 nor #21 may be closed solely on this staging work.

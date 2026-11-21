# EVM transaction decoding and independent test vectors

This project signs **Sepolia-only EIP-1559 native ETH transfers**. The runtime signer remains deliberately narrow: type 2, chain ID `11155111`, exactly 21,000 gas, empty calldata, and an empty access list. Mainnet and blind contract signing remain disabled.

## Why decode the signed bytes again?

Reviewing only the input JSON is insufficient. The bytes that leave the offline signer are the artifact that will eventually be broadcast. After signing, `sign_evm()` therefore decodes the raw transaction from scratch, re-applies the same wallet policy, recovers the sender, and verifies that the decoded unsigned fields exactly match the transaction that was approved before signing.

The EIP-1559 wire format is defined as:

```
0x02 || rlp([
  chain_id,
  nonce,
  max_priority_fee_per_gas,
  max_fee_per_gas,
  gas_limit,
  destination,
  amount,
  data,
  access_list,
  signature_y_parity,
  signature_r,
  signature_s,
])
```

Reference: https://eips.ethereum.org/EIPS/eip-1559

## External signed Sepolia vector

The regression suite contains the following signed type-2 transaction:

```
0x02f87583aa36a714847735940085174876e8008303000094b0920c523d582040f2bcb1bd7fb1c7c1ecebdb34865af3107a400080c001a03f8ed18cb03ee0fe3fbc3f0a7477a2f68db6ec84450e77e702b82a3f2c873aa4a0205c4f6a16ea8ad13a148cc3105814cd4a6860cd26a771651199c85ccb7c7f0f
```

It is an external Sepolia example that was decoded with Foundry `cast from-rlp` in the source material below. It is useful because it was not produced by this repository's Python signer.

Source: https://blog.gitcode.com/b7b3887572446866e6295e23309a2b25.html

Expected decoded values:

| Field | Value |
|---|---:|
| chainId | 11155111 |
| nonce | 20 |
| maxPriorityFeePerGas | 2,000,000,000 wei |
| maxFeePerGas | 100,000,000,000 wei |
| gas | 196,608 |
| to | `0xb0920c523d582040f2bcb1bd7fb1c7c1ecebdb34` |
| value | 100,000,000,000,000 wei |
| data | empty |
| access list | empty |
| yParity | 1 |
| transaction hash | `0x07bfbeb337e19763a1f74d989dae2953807dcb06822354cfefb16405a11beb93` |
| recovered sender | `0x7e41354AfE84800680ceB104c5Fc99eCB98A25f0` |

The hash and sender above were independently cross-checked during development with **viem 2.58.0** by parsing the serialized transaction, re-serializing the unsigned fields for the signing hash, and recovering the address from `r`, `s`, and `yParity`. viem was installed only in a temporary connected-development directory; it is not a runtime dependency of the offline wallet.

Viem parser reference: https://viem.sh/docs/utilities/parseTransaction

This external transaction intentionally has a gas limit of 196,608. The low-level decoder must parse it correctly, while the wallet policy must **reject** it because this prototype only signs simple 21,000-gas native ETH transfers. That separation is deliberate: parsing a transaction does not mean approving it.

## Regression coverage

`tests/test_wallet.py` now checks that:

- a locally signed transaction decodes back to the exact reviewed fields;
- the recovered sender is the derived test account;
- the external Sepolia vector decodes to the independently known fields, hash, and sender;
- the external vector is rejected by the stricter 21,000-gas wallet policy;
- wrong transaction types, truncated RLP, and non-canonical integer encodings are rejected.

All test keys and mnemonics in this repository are public, compromised test vectors. Never use them for real funds.

## Independent ERC-20 and EIP-712 review-only modules (Issue #3)

`review_only/evm_erc20.py` and `review_only/evm_eip712.py` add strict, **review-only**
Sepolia token calldata and two explicit custom EIP-712 intent schema decoders.
Cross-library negative and positive test vectors are in
`tests/test_evm_erc20_review.py` and `tests/test_evm_eip712_review.py`;
see [ERC20_EIP712_SECURITY.md](ERC20_EIP712_SECURITY.md) for security
assumptions, trusted inputs, unsigned/signed review boundaries, replay limits
and intentionally unsupported Permit/Permit2 operations.

The existing native ETH signer remains unchanged and **still rejects ERC-20
calldata and all typed-data**; GUI/Live USB integration, signing and mainnet
are deliberately out of scope. No current token-contract allowlist is
provisioned, and no custom EIP-712 verifier contract is asserted deployed.

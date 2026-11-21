# ERC-20／EIP-712 獨立安全解析（Issue #3）

**狀態：僅實作解析、交易語意驗證、簽章位元組回驗及測試。程式置於儲存庫根目錄的 `review_only/`，依現有 `pyproject.toml` 僅打包 `src/` 的規則，不會收錄進線上／離線 wheel；未接入 Signer、CLI、GUI、Live USB 或發行流程。正式冷端仍只允許 Sepolia 原生 ETH 21,000 gas 交易；主網與任意合約簽章維持拒絕。**

## 信任邊界

- `review_only/evm_erc20.py`：
  - `parse_erc20_calldata(data)` 只允許 ERC-20 `transfer(address,uint256)` (`0xa9059cbb`) 與 `approve(address,uint256)` (`0x095ea7b3`)；精確長度 68 bytes（4-byte selector + 2 × 32-byte ABI words）。拒絕尾隨資料、動態 ABI、位址欄位非零的前置 12 bytes、非 hex、未知 selector、零地址、零額 transfer 及 unlimited approval（但允許明確核准的 `approve(spender, 0)` 撤銷授權） (`2**256-1`)。
  - `review_erc20_transaction(...)` 要求 **獨立提供** `expected_method`（transfer/approve）、`expected_nonce`、contract、recipient/spender、amount/allowance、已核准的 token contract allowlist 和最大 Gas 費。只接受 Sepolia `chainId=11155111`、EIP-1559 type 2、`value=0`、空 access list、正整數及上限內的 Gas；從原始 calldata 解碼後逐欄比對，以 `gas * maxFeePerGas` 計算最壞 ETH 手續費。
  - `review_signed_erc20_transaction(...)` 另針對**已取得的** signed type-2 raw tx 做大小限制、獨立 RLP 解碼、同一政策回驗和簽署者地址還原；不會建立或核准簽章。
- `review_only/evm_eip712.py`：
  - `review_eip712_intent(...)` 強制獨立提供 `expected_primary_type` 防止 transfer/approval 意圖置換，只核對本專案明確定義的 **`WalletTransferIntent`**、**`WalletApprovalIntent`** 兩種 flat schema。兩者皆有 `owner`、`token`、`nonce`、`deadline`，前者有 `recipient/amount`，後者有 `spender/allowance`。
  - 只接受 domain `EIP712Domain(name,version,chainId,verifyingContract)`，其中 name=`USB Cold Wallet Intent`、version=`1`、chainId=`11155111`；verifyingContract 必須與 independently approved contract/allowlist 相符，且 token 地址需與它一致。
  - 所有欄位及 ABI 類型的**集合與順序**都要與 schema 完全一致。拒絕 `Permit`、`PermitSingle`、`PermitBatch`、Permit2、未知 domain/typed fields、嵌套型別、額外欄位、跨鏈與錯帳戶。
  - 使用外部可信的 `expected_nonce`、`expected_deadline` 和 `now_timestamp`，拒絕 stale nonce、逾期或超過 7 日期限；回傳 EIP-712 domain separator、struct hash 及 digest 作為**檢查結果**，不提供簽章 API。

呼叫端必須從可信離線政策取得 allowlist、預期地址與數值，**不可直接把 Online 交易中的 `to`／`spender`／`amount` 回填為 expected values**。未核實的 token symbol/decimals/ABI、RPC 回報與鏈上 simulation 不構成信任來源，**本模組只顯示 token raw uint256 最小單位，不將其解釋成可信的使用者金額**。

**EIP-712 replay 限制**：此解析器會比對已提供的可信 nonce，但沒有可信的 nonce 持久化／消耗機制、硬體時間來源或部署合約。重複提交相同訊息且可信 nonce 尚未變更，仍會得到相同 digest；不能宣稱提供端到端 anti-replay。自訂 `Wallet*Intent` schema 也沒有已審核的上鏈執行者，不能當作 ERC-2612/Permit2 或 dApp 已可使用的授權。任何 schema 擴充須另做合約身份、nonce 執行與 E2E 安全驗收。

**重要限制**：目前既有 `evm.py::sign_evm()` 會拒絕所有非空 calldata，`review_evm_transaction()` 不接受合約交易；新的 `signature_allowed=False` 只是防誤解的回傳欄位，不是全域強制政策或交易授權。實際代幣小數位、合約實際功能、費用市場狀態與 `approve` allowance race condition 均不能由純離線 ABI 解析確認。要在 GUI 或主網啟用之前，需另外完成 #21 政策、#19 離線顯示、正式可核實的合約 allowlist 與 #24 安全 E2E。

## 測試證據與重現

- `tests/test_evm_erc20_review.py` 用**獨立** `eth-abi` 產生兩種 selector 的 Solidity ABI calldata，使用 `eth-account` 產生 signed EIP-1559 bytes，測試解析、recover sender、原始交易逐欄比對，及惡意 selector/長度/dirty high bits/spender 替換/跨鏈/額外 metadata/整數與 Gas 上下界。
- `tests/test_evm_eip712_review.py` 以獨立 `eth-account.messages.encode_typed_data` 核對 EIP-712 `domainSeparator`、`structHash`、`0x1901` digest；另測簽名 recover、domain/schema/nonce/deadline/allowance 竄改與 Permit/Permit2 拒絕。
- 所有測試私鑰與 seed 均為**公開、已失去保密性的測試向量**，絕對不可存入任何真實資產。

```sh
PYTHONPATH=src python -m pytest -q tests/test_evm_erc20_review.py tests/test_evm_eip712_review.py
```

規格來源：
- <https://eips.ethereum.org/EIPS/eip-20>
- <https://eips.ethereum.org/EIPS/eip-712>
- <https://eips.ethereum.org/EIPS/eip-1559>
- <https://eips.ethereum.org/EIPS/eip-2612>

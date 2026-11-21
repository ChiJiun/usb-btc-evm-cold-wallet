/** Verify the full account address selected in MetaMask before any request.
 * QR account screens commonly encode plain 0x addresses or EIP-681 URIs.
 * Reject transactions, foreign chain IDs and arbitrary QR instructions.
 */
import { getAddress } from 'ethers';

export function verifySelectedAddress(input, expectedAddress) {
  if(typeof input!=='string' || input.length>160) throw Error('無效的 MetaMask 地址 QR');
  const text=input.trim();
  const match=/^(?:ethereum:)?(0x[0-9a-fA-F]{40})(?:@11155111)?$/i.exec(text);
  if(!match || (!text.toLowerCase().startsWith('ethereum:') && text.includes('@'))) {
    throw Error('只接受單純 EVM 地址或 Sepolia 帳戶 QR');
  }
  const actual=getAddress(match[1]);
  if(actual!==getAddress(expectedAddress)) {
    throw Error('MetaMask 選取地址與離線可簽地址不同，禁止繼續');
  }
  return actual;
}

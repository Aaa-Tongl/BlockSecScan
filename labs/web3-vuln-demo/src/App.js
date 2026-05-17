// ⚠️ CRITICAL: Mnemonic phrase hardcoded in frontend
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ⚠️ CRITICAL: Private key exposed
const privateKey = "0x8f2a55949038a9610f50daa30e2f4c3e8c68d8e2b1c4e6c5a7d9f0b3e4a5c6d7";

// ⚠️ HIGH: Alchemy API key leaked in client code
const ALCHEMY_KEY = "https://eth-mainnet.g.alchemy.com/v2/demo-api-key-12345";

// ⚠️ HIGH: Unlimited token approval
await token.approve(spenderAddress, ethers.MaxUint256);

// ⚠️ MEDIUM: Unprotected signMessage
const sig = await signer.signMessage("Login to DApp");

// ⚠️ MEDIUM: Hardcoded contract address
const EXCHANGE_CONTRACT = "0xdef1c0ded9bec7f1a1670819833240f027b25eff";

// ⚠️ LOW: Direct window.ethereum usage
if (window.ethereum !== undefined) {
  const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
}

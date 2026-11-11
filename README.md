# evm-token-inspector

A Hermes plugin that inspects an EVM token contract **before you interact
with it**. One tool, `evm_token_check`, reads the contract over a public
JSON-RPC endpoint and reports:

- name, symbol, decimals, total supply
- `owner()` status — the owner address, `renounced` when it is the zero
  address, or `n/a` when the contract has no `owner()` at all
- whether it is an **EIP-1967 proxy** (and the implementation address)
- the **DEX V2 pair** vs the chain's wrapped native token, plus both
  reserves, so you can see whether real liquidity exists (or the pair is
  empty / missing)

Chains: **BSC, Ethereum, Base, Arbitrum**.

## Why this exists

Before a swap, a mint or an approval, the two questions that matter are
"what is this contract?" and "is there real liquidity behind it?". This
plugin answers both with on-chain reads, in one tool call, without an API
key and without signing anything.

## How it works

All reads are plain `eth_call` / `eth_getCode` / `eth_getStorageAt` against
public RPCs:

| Chain | RPC | DEX |
|---|---|---|
| BSC | bsc-dataseed, publicnode, 48.club, ninicoin (fallback order) | PancakeSwap V2 |
| Ethereum | publicnode, drpc.org, blastapi.io | Uniswap V2 |
| Base | mainnet.base.org, publicnode | Uniswap V2 |
| Arbitrum | arb1.arbitrum.io, publicnode | Uniswap V2 |

Transport: the plugin POSTs through the `curl` binary when it is present
(its TLS handshake is accepted by public RPCs that silently drop Python's
stdlib TLS fingerprint), falling back to stdlib `urllib`. The `curl` call
uses an argument list with no shell, and the URL/body are built from fixed
config plus a validated `0x` address, so there is no injection surface.

No writes, no signing, no API keys, no credentials. The plugin never reads
any file or secret — the only input is the contract address (and the chain).

## Install

```sh
hermes plugins install evm-token-inspector
```

Or from source:

```sh
git clone https://github.com/sawi57003-ops/evm-token-inspector
hermes plugins validate ./evm-token-inspector --install-deps
```

## Example

Ask Hermes:

> Check token 0x... on BSC — is it safe to look at?

The agent calls `evm_token_check` and gets back a JSON report like:

```json
{
  "success": true,
  "token": {
    "chain": "bsc",
    "address": "0x...",
    "name": "Example Token",
    "symbol": "EXM",
    "decimals": 18,
    "total_supply": "1000000000",
    "owner": "0x0000000000000000000000000000000000000000",
    "owner_renounced": true,
    "is_proxy": false,
    "pair": "0x...",
    "has_liquidity_pair": true,
    "reserves": { "token": "500000000000000000000000", "wrapped_native": "1200000000000000000" },
    "liquidity_empty": false
  }
}
```

## Disclosure

- Read-only. It makes HTTPS calls to the public RPCs listed above and to
  nothing else.
- It does **not** detect honeypots, hidden taxes or malicious logic — it
  reports the facts (owner, proxy, pair, reserves) so the agent and the user
  can judge. It is not financial advice.
- No telemetry, no background processes, no stored credentials.

## License

MIT. See `LICENSE`.

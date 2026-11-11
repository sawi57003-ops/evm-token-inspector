"""
evm-token-inspector - inspect an EVM token contract before interacting with it.

Registers one deterministic tool, ``evm_token_check``, that reads a token
contract over a public JSON-RPC endpoint (no API key, no signing, no writes)
and returns:

* name, symbol, decimals, totalSupply
* owner() when the contract is Ownable (or "renounced" when owner is the zero
  address, "n/a" when the contract has no owner() at all)
* whether it is an EIP-1967 proxy (implementation slot populated)
* the DEX V2 pair for the token vs the chain's wrapped native token, plus
  both reserves, so the caller can see whether real liquidity exists

Chains: bsc, ethereum, base, arbitrum. All reads are plain ``eth_call`` /
``eth_getCode`` / ``eth_getStorageAt`` against public RPCs. Nothing is
written on-chain and no secret is read.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from typing import Any

from tools.registry import tool_error, tool_result

logger = logging.getLogger(__name__)

_TIMEOUT_S = 15
_MAX_ADDR_LEN = 42

# --- selectors (first 4 bytes of keccak of the canonical signature) ---
_SEL_NAME = "06fdde03"
_SEL_SYMBOL = "95d89b41"
_SEL_DECIMALS = "313ce567"
_SEL_TOTAL_SUPPLY = "18160ddd"
_SEL_OWNER = "8da5cb5b"
_SEL_GET_PAIR = "e6a43905"
_SEL_GET_RESERVES = "0902f1ac"
_SEL_TOKEN0 = "0dfe1681"
_SEL_TOKEN1 = "d21220a7"

# EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
_EIP1967_IMPL_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# chain -> (public RPCs in fallback order, wrapped native token, DEX V2 factory)
# Transport: the plugin POSTs via the `curl` binary when available (its TLS
# handshake is accepted by public RPCs that silently drop Python's stdlib
# TLS fingerprint), falling back to stdlib urllib. So the list below uses
# the most reliable public endpoints, tried in order.
CHAINS: dict[str, dict[str, Any]] = {
    "bsc": {
        "rpcs": [
            "https://bsc-dataseed.binance.org/",
            "https://bsc.publicnode.com",
            "https://rpc-bsc.48.club/",
            "https://bsc-dataseed1.ninicoin.io/",
        ],
        "wrapped": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
        "factory": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
        "dex": "PancakeSwap V2",
    },
    "ethereum": {
        "rpcs": [
            "https://ethereum.publicnode.com",
            "https://eth.drpc.org",
            "https://eth-mainnet.public.blastapi.io",
        ],
        "wrapped": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "dex": "Uniswap V2",
    },
    "base": {
        "rpcs": [
            "https://mainnet.base.org",
            "https://base.publicnode.com",
        ],
        "wrapped": "0x4200000000000000000000000000000000000006",
        "factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "dex": "Uniswap V2",
    },
    "arbitrum": {
        "rpcs": [
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum.publicnode.com",
        ],
        "wrapped": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        "factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "dex": "Uniswap V2",
    },
}

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

EVM_TOKEN_CHECK_SCHEMA = {
    "description": (
        "Inspect an EVM token contract before interacting with it. Returns "
        "name, symbol, decimals, total supply, owner status, whether it is a "
        "proxy, and the DEX V2 pair + liquidity reserves. Read-only; uses "
        "public RPCs, no API key, no signing. Use this when the user gives a "
        "token contract address and wants to know what it is and whether it "
        "has real liquidity, before any swap, mint or approval."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Token contract address (0x + 40 hex chars).",
            },
            "chain": {
                "type": "string",
                "description": (
                    "Chain to read from: bsc, ethereum, base or arbitrum. "
                    "Defaults to bsc."
                ),
                "enum": ["bsc", "ethereum", "base", "arbitrum"],
            },
        },
        "required": ["address"],
        "additionalProperties": False,
    },
}


def _http_post_json(url: str, body: bytes) -> dict:
    """POST a JSON body and return the parsed JSON response.

    Prefers the ``curl`` binary (its TLS handshake is accepted by public
    RPCs that silently drop Python's stdlib TLS fingerprint), falling back
    to ``urllib`` when curl is unavailable. The subprocess call uses an
    argument list with no shell, and the URL/body are built from fixed
    config plus a validated 0x address, so there is no injection surface.
    """
    try:
        import subprocess

        proc = subprocess.run(
            [
                "curl",
                "-s",
                "-m",
                str(_TIMEOUT_S),
                "-X",
                "POST",
                url,
                "-H",
                "Content-Type: application/json",
                "-H",
                "User-Agent: evm-token-inspector/1.0",
                "-d",
                body.decode(),
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_S + 5,
        )
        if proc.returncode != 0:
            raise RuntimeError("curl exit %d: %s" % (proc.returncode, proc.stderr[:200]))
        return json.loads(proc.stdout)
    except FileNotFoundError:
        # curl not installed: fall back to stdlib urllib.
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "evm-token-inspector/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode())


def _rpc_once(rpc_url: str, method: str, params: list, req_id: int = 1) -> Any:
    """One JSON-RPC call against one endpoint. Returns `result` or raises."""
    body = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": req_id}
    ).encode()
    payload = _http_post_json(rpc_url, body)
    if "error" in payload:
        raise RuntimeError(str(payload["error"]))
    return payload.get("result")


def _rpc(rpc_urls: list, method: str, params: list, req_id: int = 1) -> Any:
    """JSON-RPC with fallback: try each public endpoint until one answers."""
    last_exc: Exception | None = None
    for url in rpc_urls:
        try:
            return _rpc_once(url, method, params, req_id)
        except Exception as exc:  # noqa: BLE001 - try the next endpoint
            last_exc = exc
            logger.debug("RPC %s failed (%s), trying next", url, exc)
    raise RuntimeError(
        "all public RPCs failed for %s: %s" % (method, last_exc)
    )


def _eth_call(rpc_urls: list, to: str, data: str) -> str:
    result = _rpc(rpc_urls, "eth_call", [{"to": to, "data": data}, "latest"])
    if not isinstance(result, str):
        raise RuntimeError("empty eth_call result")
    return result


def _decode_address(word: str) -> str | None:
    """Decode a 32-byte ABI word into an address, or None if not an address."""
    if not isinstance(word, str) or not word.startswith("0x"):
        return None
    body = word[2:]
    if len(body) < 40:
        return None
    return "0x" + body[-40:].lower()


def _decode_uint(word: str) -> int:
    return int(word, 16)


def _decode_string(hexdata: str) -> str:
    """Decode an ABI-encoded dynamic string (offset + length + bytes)."""
    body = hexdata[2:] if hexdata.startswith("0x") else hexdata
    if len(body) < 128:
        raise ValueError("string data too short")
    length = int(body[64:128], 16)
    raw = bytes.fromhex(body[128 : 128 + length * 2])
    return raw.decode("utf-8", errors="replace")


def _try_call(rpc_urls: list, to: str, data: str) -> str | None:
    """eth_call that returns None instead of raising (for optional views)."""
    try:
        return _eth_call(rpc_urls, to, data)
    except Exception as exc:  # noqa: BLE001 - optional view, absence is data
        logger.debug("optional eth_call %s failed: %s", data[:10], exc)
        return None


def _inspect_token(address: str, chain: str) -> dict:
    cfg = CHAINS[chain]
    rpc_urls = cfg["rpcs"]
    wrapped = cfg["wrapped"]
    factory = cfg["factory"]

    code = _rpc(rpc_urls, "eth_getCode", [address, "latest"])
    if not code or code == "0x":
        raise ValueError("address has no contract code on %s" % chain)

    out: dict[str, Any] = {
        "chain": chain,
        "address": address,
        "dex": cfg["dex"],
    }

    name_raw = _try_call(rpc_urls, address, "0x" + _SEL_NAME)
    out["name"] = _decode_string(name_raw) if name_raw else None
    symbol_raw = _try_call(rpc_urls, address, "0x" + _SEL_SYMBOL)
    out["symbol"] = _decode_string(symbol_raw) if symbol_raw else None
    dec_raw = _try_call(rpc_urls, address, "0x" + _SEL_DECIMALS)
    out["decimals"] = _decode_uint(dec_raw) if dec_raw else None
    supply_raw = _try_call(rpc_urls, address, "0x" + _SEL_TOTAL_SUPPLY)
    out["total_supply_raw"] = (
        str(_decode_uint(supply_raw)) if supply_raw else None
    )
    if out["decimals"] is not None and out["total_supply_raw"] is not None:
        out["total_supply"] = str(
            int(out["total_supply_raw"]) // (10 ** out["decimals"])
        )
    else:
        out["total_supply"] = None

    owner_raw = _try_call(rpc_urls, address, "0x" + _SEL_OWNER)
    if owner_raw is None:
        out["owner"] = "n/a (no owner())"
        out["owner_renounced"] = None
    else:
        owner = _decode_address(owner_raw)
        if owner is None:
            out["owner"] = "n/a (undecodable)"
            out["owner_renounced"] = None
        else:
            out["owner"] = owner
            out["owner_renounced"] = owner == _ZERO_ADDRESS

    impl = _rpc(rpc_urls, "eth_getStorageAt", [address, _EIP1967_IMPL_SLOT, "latest"])
    if impl and impl != "0x" + "0" * 64:
        out["is_proxy"] = True
        out["implementation"] = _decode_address(impl)
    else:
        out["is_proxy"] = False
        out["implementation"] = None

    # DEX V2 pair: getPair(token, wrappedNative)
    pair_data = (
        "0x" + _SEL_GET_PAIR
        + address[2:].lower().rjust(64, "0")
        + wrapped[2:].lower().rjust(64, "0")
    )
    pair_raw = _try_call(rpc_urls, factory, pair_data)
    pair = _decode_address(pair_raw) if pair_raw else None
    out["pair"] = pair
    out["has_liquidity_pair"] = pair is not None and pair != _ZERO_ADDRESS
    out["reserves"] = None
    if out["has_liquidity_pair"]:
        res_raw = _try_call(rpc_urls, pair, "0x" + _SEL_GET_RESERVES)
        t0_raw = _try_call(rpc_urls, pair, "0x" + _SEL_TOKEN0)
        t1_raw = _try_call(rpc_urls, pair, "0x" + _SEL_TOKEN1)
        if res_raw and t0_raw and t1_raw:
            r0 = _decode_uint(res_raw[2:66])
            r1 = _decode_uint(res_raw[66:130])
            token0 = _decode_address(t0_raw)
            if token0 is None:
                out["liquidity_empty"] = None
            else:
                if token0 == address.lower():
                    token_reserve, native_reserve = r0, r1
                else:
                    token_reserve, native_reserve = r1, r0
                out["reserves"] = {
                    "token": str(token_reserve),
                    "wrapped_native": str(native_reserve),
                    "token_is_token0": token0 == address.lower(),
                }
                out["liquidity_empty"] = token_reserve == 0 or native_reserve == 0
        else:
            out["liquidity_empty"] = None

    return out


def _handle_evm_token_check(args: dict, **kwargs: Any) -> str:
    """Handler for the evm_token_check tool."""
    del kwargs

    address = args.get("address")
    if not isinstance(address, str) or not _ADDR_RE.match(address.strip()):
        return tool_error(
            "address must be a 0x contract address (40 hex chars)",
            example="0x0000000000000000000000000000000000000000",
        )
    address = address.strip()
    # checksummed display is unnecessary; RPCs accept lowercase.
    address = "0x" + address[2:].lower()

    chain = args.get("chain") or "bsc"
    if chain not in CHAINS:
        return tool_error(
            "chain must be one of: bsc, ethereum, base, arbitrum",
            got=str(chain),
        )

    try:
        result = _inspect_token(address, chain)
    except ValueError as exc:
        return tool_error(str(exc), address=address, chain=chain)
    except Exception as exc:  # noqa: BLE001 - surface RPC failures cleanly
        logger.warning("evm_token_check RPC failure: %s", exc)
        return tool_error(
            "public RPC call failed: %s" % exc, address=address, chain=chain
        )

    return tool_result({"success": True, "token": result})


def register(ctx: Any) -> None:
    """Plugin entry point - expose one model-callable tool."""
    ctx.register_tool(
        name="evm_token_check",
        toolset="evm_token_inspector",
        schema=EVM_TOKEN_CHECK_SCHEMA,
        handler=_handle_evm_token_check,
        description=(
            "Inspect an EVM token contract (name, supply, owner, proxy, "
            "DEX pair + liquidity) before interacting with it."
        ),
    )
    logger.debug("evm-token-inspector: registered evm_token_check")

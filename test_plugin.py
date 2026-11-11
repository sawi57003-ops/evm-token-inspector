"""Standalone test for evm-token-inspector (no hermes install needed).

Mocks `tools.registry` (tool_error/tool_result) and a minimal `ctx`,
imports the plugin, registers the tool, then calls the handler against
real public RPCs. Usage: python3 test_plugin.py
"""
import json
import sys
import types

# --- mock tools.registry BEFORE importing the plugin ---
registry = types.ModuleType("tools.registry")


def tool_result(data):
    return json.dumps(data)


def tool_error(message, **kwargs):
    out = {"error": message}
    out.update(kwargs)
    return json.dumps(out)


registry.tool_result = tool_result
registry.tool_error = tool_error
tools_mod = types.ModuleType("tools")
tools_mod.registry = registry
sys.modules["tools"] = tools_mod
sys.modules["tools.registry"] = registry

sys.path.insert(0, "/home/hatch/workspace/hermes-plugin/evm-token-inspector")

import __init__ as plugin  # noqa: E402


class FakeCtx:
    def __init__(self):
        self.tools = {}

    def register_tool(self, name, toolset, schema, handler, description):
        self.tools[name] = {
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
            "description": description,
        }


def main():
    ctx = FakeCtx()
    plugin.register(ctx)
    assert "evm_token_check" in ctx.tools, "tool did not register"
    print("register: OK — evm_token_check registered")
    handler = ctx.tools["evm_token_check"]["handler"]

    # 1. BUSD on BSC (well-known, has a PancakeSwap pair)
    print("\n--- BUSD on BSC ---")
    out = handler({"address": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", "chain": "bsc"})
    d = json.loads(out)
    print(json.dumps(d, indent=1)[:1500])
    assert d.get("success") is True, "BUSD check failed"
    assert d["token"]["symbol"] == "BUSD", d["token"].get("symbol")
    assert d["token"]["has_liquidity_pair"] is True
    print("BUSD: OK")

    # 2. CAKE on BSC
    print("\n--- CAKE on BSC ---")
    out = handler({"address": "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", "chain": "bsc"})
    d = json.loads(out)
    print("symbol:", d["token"].get("symbol"), "| owner:", d["token"].get("owner"),
          "| proxy:", d["token"].get("is_proxy"), "| pair:", d["token"].get("pair"))
    assert d.get("success") is True
    print("CAKE: OK")

    # 3. USDC on Base (correct address ends ...bdA02913)
    print("\n--- USDC on Base ---")
    out = handler({"address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "chain": "base"})
    d = json.loads(out)
    print("symbol:", d["token"].get("symbol"), "| decimals:", d["token"].get("decimals"),
          "| pair:", d["token"].get("pair"))
    assert d.get("success") is True
    print("USDC/base: OK")

    # 3b. WETH on Arbitrum
    print("\n--- WETH on Arbitrum ---")
    out = handler({"address": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "chain": "arbitrum"})
    d = json.loads(out)
    print("symbol:", d["token"].get("symbol"), "| proxy:", d["token"].get("is_proxy"),
          "| pair:", d["token"].get("pair"), "| reserves:", d["token"].get("reserves"))
    assert d.get("success") is True
    assert d["token"].get("pair") and d["token"]["pair"].startswith("0x") and len(d["token"]["pair"]) == 42
    print("WETH/arb: OK")

    # 4. Bad address -> clean error, not a crash
    print("\n--- bad address ---")
    out = handler({"address": "not-an-address", "chain": "bsc"})
    d = json.loads(out)
    print("error:", d.get("error"))
    assert "error" in d
    print("bad address: OK (clean error)")

    # 5. EOA (no code) -> clean error
    print("\n--- EOA (no contract code) ---")
    out = handler({"address": "0x0000000000000000000000000000000000000001", "chain": "bsc"})
    d = json.loads(out)
    print("error:", d.get("error"))
    assert "error" in d
    print("EOA: OK (clean error)")

    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()

"""Local blockchain harness — deploy a contract and execute transaction sequences.

The brief requires a "local blockchain testing environment". This wraps a local
EVM node (Anvil from Foundry by default; configurable) so contracts can be
deployed and driven with multi-step transaction sequences — the substrate the
fuzzer and PoC exploits run on.

Status: scaffold (Milestone M2). Interfaces are defined; implementation lands
when the fuzzing loop is wired up.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import settings


@dataclass
class Deployment:
    address: str
    abi: list[dict]


class LocalChain:
    """A local EVM node the analyzer deploys to and drives transactions against."""

    def __init__(self, rpc_url: str | None = None) -> None:
        # No hardcoded chain: read from config/env, default to local Anvil.
        self.rpc_url = rpc_url or settings.rpc_url

    def __enter__(self) -> "LocalChain":
        # TODO(M2): start/connect Anvil (or attach to a running node).
        return self

    def __exit__(self, *exc: object) -> None:
        # TODO(M2): tear down the node if we started it.
        return None

    def deploy(self, contract_path: str) -> Deployment:
        raise NotImplementedError("TODO(M2): compile + deploy contract to local chain")

    def send_sequence(self, deployment: Deployment, calls: list[dict]) -> list[dict]:
        """Execute an ordered multi-step transaction sequence; return receipts."""
        raise NotImplementedError("TODO(M2): execute transaction sequence")

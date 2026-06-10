"""Central configuration — everything env-driven, nothing hardcoded.

Solidity version, tool limits, chain RPC, and AI model are all read from the
environment (see .env.example), honoring the project's flexibility principle:
no hardcoded Solidity versions, tool versions, or chain names in source.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Local chain (default: Anvil from Foundry).
    rpc_url: str = os.getenv("RPC_URL", "http://127.0.0.1:8545")
    # Solidity compiler version is resolved at runtime via solc-select, not pinned.
    solc_version: str | None = os.getenv("SOLC_VERSION") or None
    # Echidna campaign length (configurable, not hardcoded).
    echidna_test_limit: int = int(os.getenv("ECHIDNA_TEST_LIMIT", "50000"))
    # Local AI stack.
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3")
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    chroma_collection: str = os.getenv("CHROMA_COLLECTION", "aifuzz-knowledge")


settings = Settings()

"""AI guidance — generate fuzzing properties and seed inputs from contract source.

This is the project's novelty: instead of purely random transaction generation,
a local LLM (Ollama) — informed by a RAG knowledge base of vulnerability
patterns and best practices (ChromaDB) — proposes (a) Echidna invariants/
properties to check and (b) seed transaction sequences likely to reach
vulnerable states. Goal: beat random fuzzing on coverage and bugs found.

Everything runs locally / air-gapped (no hosted API): reproducible, no API cost,
no contract source leaves the machine.

Status: scaffold (Milestone M3).
"""

from __future__ import annotations

from .config import settings


class KnowledgeBase:
    """RAG store (ChromaDB) over vulnerability patterns + best-practice corpus."""

    def __init__(self) -> None:
        self.collection = settings.chroma_collection

    def retrieve(self, contract_source: str, k: int = 5) -> list[str]:
        """Return the k most relevant vulnerability/best-practice snippets."""
        raise NotImplementedError("TODO(M3): embed query + ChromaDB similarity search")


class PropertyGenerator:
    """Uses a local LLM (Ollama) + retrieved context to draft fuzzing guidance."""

    def __init__(self, kb: KnowledgeBase | None = None) -> None:
        self.kb = kb or KnowledgeBase()
        self.model = settings.ollama_model

    def generate_properties(self, contract_source: str) -> list[str]:
        """Draft Echidna invariants/properties tailored to this contract."""
        raise NotImplementedError("TODO(M3): RAG-augmented property generation via Ollama")

    def seed_sequences(self, contract_source: str) -> list[list[str]]:
        """Propose seed transaction sequences likely to reach vulnerable states."""
        raise NotImplementedError("TODO(M3): AI-guided seed sequence generation")

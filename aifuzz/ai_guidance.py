"""AI guidance — generate fuzzing properties and seed inputs from contract source.

This is the project's novelty: instead of purely random transaction generation,
a local LLM (Ollama) — informed by a RAG knowledge base of vulnerability
patterns and best practices (ChromaDB) — proposes (a) Echidna invariants/
properties to check and (b) seed transaction sequences likely to reach
vulnerable states. Goal: beat random fuzzing on coverage and bugs found.

Everything runs locally / air-gapped (no hosted API): reproducible, no API cost,
no contract source leaves the machine. ChromaDB is an EMBEDDED on-disk store
(no server, no cloud) that lives next to the aifuzz process; embeddings come
from a local Ollama model. Retrieval (this file's KnowledgeBase) is wired;
generation (PropertyGenerator) is the remaining M3 slice.
"""

from __future__ import annotations

from pathlib import Path

from .config import settings

# Chroma / Ollama are optional (the `ai` extra). Import lazily so the tool and
# tests still run without them installed; retrieval degrades to empty.
try:
    import chromadb
    import ollama

    _AI_DEPS = True
except ImportError:  # pragma: no cover - exercised only without the ai extra
    _AI_DEPS = False

_MAX_CHARS = 8000  # keep each doc within the embedder's context window


class KnowledgeBase:
    """RAG store (embedded ChromaDB) over the labelled contract corpus.

    On first use it builds an on-disk vector index from `rag_corpus_dir` (the
    reference split / offline sample) by embedding each contract with a local
    Ollama model. Subsequent runs reuse the persisted index.
    """

    def __init__(self) -> None:
        self.collection_name = settings.chroma_collection
        self.embed_model = settings.embed_model
        self.corpus_dir = Path(settings.rag_corpus_dir)
        self.chroma_path = settings.chroma_path
        self._collection = None

    def available(self) -> bool:
        return _AI_DEPS

    def _client(self):
        return ollama.Client(host=settings.ollama_host)

    def _embed(self, texts: list[str]) -> list[list[float]]:
        """Embed texts with the local Ollama embedding model."""
        payload = [t[:_MAX_CHARS] for t in texts]
        resp = self._client().embed(model=self.embed_model, input=payload)
        return resp["embeddings"]

    def _ensure_index(self):
        """Open the persistent collection, building it from the corpus if empty."""
        if self._collection is not None:
            return self._collection
        client = chromadb.PersistentClient(path=self.chroma_path)
        col = client.get_or_create_collection(self.collection_name)
        if col.count() == 0:
            self._build(col)
        self._collection = col
        return col

    def _build(self, col) -> None:
        sols = sorted(self.corpus_dir.rglob("*.sol"))
        if not sols:
            return
        docs, ids, metas = [], [], []
        for sol in sols:
            docs.append(sol.read_text(encoding="utf-8", errors="replace"))
            ids.append(sol.relative_to(self.corpus_dir).as_posix())
            # folder under the corpus (e.g. vulnerable/reentrancy) is the label hint
            parts = sol.relative_to(self.corpus_dir).parts
            metas.append({"path": ids[-1], "type": parts[-2] if len(parts) > 1 else "unknown"})
        # embed in batches so a single Ollama call stays small
        embs: list[list[float]] = []
        for i in range(0, len(docs), 16):
            embs.extend(self._embed(docs[i:i + 16]))
        col.add(ids=ids, documents=docs, embeddings=embs, metadatas=metas)

    def retrieve(self, contract_source: str, k: int = 5) -> list[str]:
        """Return the k most relevant contracts from the corpus for this query."""
        if not _AI_DEPS:
            return []
        col = self._ensure_index()
        if col.count() == 0:
            return []
        q = self._embed([contract_source])
        res = col.query(query_embeddings=q, n_results=min(k, col.count()))
        return res.get("documents", [[]])[0]


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

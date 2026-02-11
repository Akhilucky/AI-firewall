"""
AI Firewall - Vector Database Module
FAISS-based vector store for semantic similarity search against known attack patterns.
"""

from __future__ import annotations

import logging
import numpy as np
from typing import Optional

from sentence_transformers import SentenceTransformer
import faiss

from src.config import config
from src.models import AttackType, RetrievedEvidence
from src.data.attack_patterns import ATTACK_PATTERNS, SAFE_PROMPTS, SECURITY_POLICIES

logger = logging.getLogger("ai_firewall.vector_db")


class VectorStore:
    """
    FAISS-backed vector store for the AI Firewall.
    
    Stores embeddings of:
    - Known attack patterns (prompt injection, jailbreak, etc.)
    - Safe prompt examples (for calibration)
    - Security policies (for policy agent grounding)
    """

    def __init__(self, model_name: str = config.embedding_model):
        self.model_name = model_name
        self.dimension = config.embedding_dimension
        self._model: Optional[SentenceTransformer] = None

        # FAISS index (Inner Product for cosine similarity on normalized vectors)
        self.index = faiss.IndexFlatIP(self.dimension)

        # Metadata store (parallel to FAISS index)
        self.metadata: list[dict] = []

        # Track initialization state
        self._initialized = False

    @property
    def model(self) -> SentenceTransformer:
        """Lazy-load the embedding model."""
        if self._model is None:
            logger.info(f"Loading embedding model: {self.model_name}")
            self._model = SentenceTransformer(self.model_name)
            logger.info("Embedding model loaded successfully")
        return self._model

    def embed(self, texts: list[str]) -> np.ndarray:
        """Generate normalized embeddings for a list of texts."""
        embeddings = self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        return embeddings.astype("float32")

    def add_texts(self, texts: list[str], metadata_list: list[dict]) -> None:
        """Add texts with metadata to the vector store."""
        if len(texts) != len(metadata_list):
            raise ValueError("texts and metadata_list must have same length")

        embeddings = self.embed(texts)
        self.index.add(embeddings)
        self.metadata.extend(metadata_list)
        logger.debug(f"Added {len(texts)} entries. Total: {self.index.ntotal}")

    def search(
        self,
        query: str,
        top_k: int = 5,
        min_score: float = 0.0,
        filter_type: Optional[str] = None,
    ) -> list[tuple[dict, float]]:
        """
        Search for similar entries in the vector store.
        
        Returns list of (metadata, similarity_score) tuples, sorted by score descending.
        """
        if self.index.ntotal == 0:
            return []

        query_embedding = self.embed([query])
        scores, indices = self.index.search(query_embedding, min(top_k * 2, self.index.ntotal))

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:
                continue
            if score < min_score:
                continue

            meta = self.metadata[idx]
            if filter_type and meta.get("type") != filter_type:
                continue

            results.append((meta, float(score)))

            if len(results) >= top_k:
                break

        return results

    def search_attacks(self, query: str, top_k: int = 5) -> list[RetrievedEvidence]:
        """Search specifically for attack pattern matches."""
        results = self.search(
            query,
            top_k=top_k,
            min_score=config.similarity_threshold * 0.5,  # lower floor, filter later
            filter_type="attack",
        )

        evidence = []
        for meta, score in results:
            evidence.append(RetrievedEvidence(
                text=meta["text"],
                attack_type=AttackType(meta["attack_type"]),
                similarity_score=round(score, 4),
                source="vector_db",
            ))
        return evidence

    def search_policies(self, query: str, top_k: int = 3) -> list[tuple[str, str, float]]:
        """Search for relevant security policies."""
        results = self.search(query, top_k=top_k, filter_type="policy")
        return [
            (meta["text"], meta["policy_name"], score)
            for meta, score in results
        ]

    def initialize(self) -> None:
        """
        Seed the vector database with all known patterns, safe examples, and policies.
        """
        if self._initialized:
            logger.info("Vector store already initialized, skipping")
            return

        logger.info("Initializing vector store with seed data...")

        # ── Attack Patterns ───────────────────────────────────────────────
        attack_texts = []
        attack_meta = []
        for text, attack_type, description in ATTACK_PATTERNS:
            attack_texts.append(text)
            attack_meta.append({
                "type": "attack",
                "text": text,
                "attack_type": attack_type.value,
                "description": description,
            })

        if attack_texts:
            self.add_texts(attack_texts, attack_meta)
            logger.info(f"Loaded {len(attack_texts)} attack patterns")

        # ── Safe Prompts ──────────────────────────────────────────────────
        safe_texts = []
        safe_meta = []
        for text, description in SAFE_PROMPTS:
            safe_texts.append(text)
            safe_meta.append({
                "type": "safe",
                "text": text,
                "description": description,
            })

        if safe_texts:
            self.add_texts(safe_texts, safe_meta)
            logger.info(f"Loaded {len(safe_texts)} safe prompt examples")

        # ── Security Policies ─────────────────────────────────────────────
        policy_texts = []
        policy_meta = []
        for text, policy_name in SECURITY_POLICIES:
            policy_texts.append(text)
            policy_meta.append({
                "type": "policy",
                "text": text,
                "policy_name": policy_name,
            })

        if policy_texts:
            self.add_texts(policy_texts, policy_meta)
            logger.info(f"Loaded {len(policy_texts)} security policies")

        self._initialized = True
        logger.info(
            f"Vector store initialized: {self.index.ntotal} total entries"
        )

    @property
    def stats(self) -> dict:
        """Return stats about the vector store."""
        type_counts = {}
        for meta in self.metadata:
            t = meta.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_entries": self.index.ntotal,
            "dimension": self.dimension,
            "model": self.model_name,
            "entries_by_type": type_counts,
            "initialized": self._initialized,
        }


# Module-level singleton
_vector_store: Optional[VectorStore] = None


def get_vector_store() -> VectorStore:
    """Get or create the global VectorStore singleton."""
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStore()
        _vector_store.initialize()
    return _vector_store

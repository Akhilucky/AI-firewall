"""
AI Firewall - Retrieval Agent
Performs RAG-based semantic search against the vector database
to find evidence of known attack patterns.
"""

from __future__ import annotations

import logging
import time

from src.models import AttackType, RetrievalResult, RetrievedEvidence
from src.vector_db import VectorStore
from src.config import config

logger = logging.getLogger("ai_firewall.retrieval_agent")


class RetrievalAgent:
    """
    Retrieval Agent — searches the vector database for semantically
    similar known attack patterns and returns grounded evidence.
    
    This agent does NOT make decisions. It only retrieves and ranks evidence.
    Decisions are made by the Guard Agent and Policy Agent downstream.
    """

    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store
        self.top_k = 5

    def analyze(self, prompt: str) -> RetrievalResult:
        """
        Search for similar attack patterns in the vector database.
        
        Returns:
            RetrievalResult with ranked evidence and summary statistics.
        """
        start = time.perf_counter()
        logger.info(f"Retrieval Agent: searching for similar patterns (top_k={self.top_k})")

        # Retrieve evidence from vector DB
        evidence = self.vector_store.search_attacks(prompt, top_k=self.top_k)

        # Filter by similarity threshold
        strong_evidence = [
            e for e in evidence
            if e.similarity_score >= config.similarity_threshold
        ]

        # Compute statistics
        if evidence:
            max_sim = max(e.similarity_score for e in evidence)
            avg_sim = sum(e.similarity_score for e in evidence) / len(evidence)
        else:
            max_sim = 0.0
            avg_sim = 0.0

        # Collect matched attack types (from strong evidence only)
        matched_types = list(set(
            e.attack_type for e in strong_evidence
            if e.attack_type != AttackType.SAFE
        ))

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            f"Retrieval Agent: found {len(evidence)} results, "
            f"{len(strong_evidence)} above threshold ({config.similarity_threshold}), "
            f"max_sim={max_sim:.3f}, took {elapsed:.1f}ms"
        )

        return RetrievalResult(
            evidence=evidence,
            max_similarity=round(max_sim, 4),
            avg_similarity=round(avg_sim, 4),
            matched_attack_types=matched_types,
        )

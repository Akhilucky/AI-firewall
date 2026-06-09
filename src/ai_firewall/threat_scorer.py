"""
AI Firewall - Threat Scorer

Extracts detailed scoring breakdowns from firewall analysis results.
Provides the `get_threat_breakdown` tool output with per-signal scores.
"""

from __future__ import annotations

from src.config import config
from src.models import FirewallReport


class ThreatScorer:
    """Computes detailed scoring breakdowns from firewall analysis results."""

    @staticmethod
    def get_breakdown(report: FirewallReport) -> dict:
        """
        Extract individual signal scores and the final composite score.

        Recomputes signal scores from the report using the same formulas
        as the Guard Agent for full transparency.
        """
        # Vector similarity score (same formula as GuardAgent._compute_vector_score)
        retrieval = report.retrieval
        if retrieval.evidence:
            max_sim = retrieval.max_similarity
            match_count_bonus = min(len(retrieval.matched_attack_types) * 0.15, 0.3)
            strong_matches = sum(
                1 for e in retrieval.evidence
                if e.similarity_score >= config.similarity_threshold
            )
            strength_bonus = min(strong_matches * 0.1, 0.2)
            vector_similarity = round(min(max_sim + match_count_bonus + strength_bonus, 1.0), 4)
        else:
            vector_similarity = 0.0

        # Keyword match score
        keyword_score = round(min(len(report.guard.keyword_matches) * 0.45, 1.0), 4)

        # Heuristic score
        heuristic_signals = report.guard.heuristic_signals
        if heuristic_signals:
            heuristic_score = round(
                sum(s.severity for s in heuristic_signals) / max(len(heuristic_signals), 1),
                4,
            )
        else:
            heuristic_score = 0.0

        # Policy weight from config
        policy_weight = round(config.weight_policy, 4)

        # Final score (directly from guard verdict)
        final_score = report.guard.threat_score

        # Classification
        classification = report.threat_level.value

        return {
            "vector_similarity": vector_similarity,
            "keyword_score": keyword_score,
            "heuristic_score": heuristic_score,
            "policy_weight": policy_weight,
            "final_score": final_score,
            "classification": classification,
        }

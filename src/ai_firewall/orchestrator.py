"""
AI Firewall - Orchestrator
Coordinates all agents in a sequential pipeline to produce a final firewall decision.

Pipeline: Input → Retrieval Agent → Guard Agent → Policy Agent → Output
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from ai_firewall.models import (
    AnalyzeRequest,
    FirewallAction,
    FirewallReport,
    RedTeamResult,
    ThreatLevel,
)
from ai_firewall.agents.retrieval_agent import RetrievalAgent
from ai_firewall.agents.guard_agent import GuardAgent
from ai_firewall.agents.policy_agent import PolicyAgent
from ai_firewall.agents.redteam_agent import RedTeamAgent
from ai_firewall.vector_db import VectorStore, get_vector_store
from ai_firewall.config import config

logger = logging.getLogger("ai_firewall.orchestrator")


class FirewallOrchestrator:
    """
    The main orchestration layer for the AI Firewall.
    
    Coordinates the agent pipeline:
    1. Retrieval Agent — RAG-based evidence search
    2. Guard Agent    — multi-signal threat classification
    3. Policy Agent   — final allow/block/sanitize decision
    
    Optional:
    4. Red-Team Agent — adversarial testing
    """

    def __init__(self, vector_store: Optional[VectorStore] = None):
        self.vector_store = vector_store or get_vector_store()
        self.retrieval_agent = RetrievalAgent(self.vector_store)
        self.guard_agent = GuardAgent()
        self.policy_agent = PolicyAgent(self.vector_store)
        self.redteam_agent = RedTeamAgent()

        logger.info(
            f"Firewall Orchestrator initialized | mode={config.mode} | "
            f"vectors={self.vector_store.index.ntotal}"
        )

    def analyze(self, request: AnalyzeRequest) -> FirewallReport:
        """
        Run the complete firewall analysis pipeline on a prompt.
        
        Args:
            request: AnalyzeRequest containing the prompt and metadata.
            
        Returns:
            FirewallReport with complete analysis and decision.
        """
        start = time.perf_counter()
        prompt = request.prompt

        logger.info(f"─── Analyzing prompt ({len(prompt)} chars) ───")

        # ── Step 1: Retrieval Agent ───────────────────────────────────────
        retrieval_result = self.retrieval_agent.analyze(prompt)

        # ── Step 2: Guard Agent ───────────────────────────────────────────
        guard_verdict = self.guard_agent.analyze(prompt, retrieval_result)

        # ── Step 3: Policy Agent ──────────────────────────────────────────
        policy_decision = self.policy_agent.decide(prompt, guard_verdict, retrieval_result)

        # ── Compute overall confidence ────────────────────────────────────
        overall_confidence = self._compute_overall_confidence(
            guard_verdict.confidence,
            retrieval_result.max_similarity,
            len(guard_verdict.keyword_matches),
        )

        # ── Build final explanation ───────────────────────────────────────
        elapsed_ms = (time.perf_counter() - start) * 1000
        explanation = self._build_final_explanation(
            guard_verdict, policy_decision, retrieval_result, elapsed_ms
        )

        report = FirewallReport(
            original_prompt=prompt,
            retrieval=retrieval_result,
            guard=guard_verdict,
            policy=policy_decision,
            final_action=policy_decision.action,
            threat_level=guard_verdict.threat_level,
            overall_confidence=round(overall_confidence, 4),
            processing_time_ms=round(elapsed_ms, 2),
            explanation=explanation,
        )

        logger.info(
            f"─── Result: {report.final_action.value} | "
            f"{report.threat_level.value} | "
            f"confidence={report.overall_confidence} | "
            f"{elapsed_ms:.1f}ms ───"
        )

        return report

    def analyze_text(self, prompt: str) -> FirewallReport:
        """Convenience method: analyze a raw text string."""
        return self.analyze(AnalyzeRequest(prompt=prompt))

    def run_red_team(self) -> list[RedTeamResult]:
        """
        Execute the full red-team test suite against the firewall.
        
        Returns:
            List of RedTeamResult objects with pass/fail status.
        """
        logger.info("═══ Starting Red-Team Test Suite ═══")
        tests = self.redteam_agent.get_test_suite()
        results = []

        for i, test in enumerate(tests, 1):
            logger.info(f"Red-Team test {i}/{len(tests)}: {test.attack_type.value}")

            # Run the prompt through the firewall
            report = self.analyze_text(test.attack_prompt)
            test.report = report

            # Evaluate the result
            evaluated = self.redteam_agent.evaluate_result(
                test, report.final_action, report.threat_level
            )
            results.append(evaluated)

        # Summary
        passed = sum(1 for r in results if r.passed)
        total = len(results)
        logger.info(f"═══ Red-Team Results: {passed}/{total} passed ═══")

        return results

    def _compute_overall_confidence(
        self,
        guard_confidence: float,
        max_similarity: float,
        keyword_count: int,
    ) -> float:
        """Compute an overall confidence score from multiple signals."""
        # More signals agreeing = higher confidence
        components = [guard_confidence]
        if max_similarity > 0:
            components.append(min(max_similarity * 1.2, 1.0))
        if keyword_count > 0:
            components.append(min(keyword_count * 0.3, 1.0))

        return sum(components) / len(components)

    def _build_final_explanation(self, guard, policy, retrieval, elapsed_ms) -> str:
        """Build the top-level explanation for the firewall report."""
        lines = [
            f"AI Firewall Analysis Complete ({elapsed_ms:.0f}ms)",
            f"Threat Level: {guard.threat_level.value} (score: {guard.threat_score:.3f})",
            f"Action: {policy.action.value}",
            "",
            "Evidence Summary:",
        ]

        if retrieval.evidence:
            top = retrieval.evidence[0]
            lines.append(
                f"  • Top vector match: {top.attack_type.value} "
                f"(similarity: {top.similarity_score:.3f})"
            )

        if guard.keyword_matches:
            kws = ", ".join(f"'{m.keyword}'" for m in guard.keyword_matches[:3])
            lines.append(f"  • Keyword matches: {kws}")

        if guard.heuristic_signals:
            rules = ", ".join(s.rule_name for s in guard.heuristic_signals)
            lines.append(f"  • Heuristic rules: {rules}")

        if not (retrieval.evidence or guard.keyword_matches or guard.heuristic_signals):
            lines.append("  • No threat indicators detected")

        return "\n".join(lines)

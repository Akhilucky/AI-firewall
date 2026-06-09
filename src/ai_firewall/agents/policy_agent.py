"""
AI Firewall - Policy Agent
Makes final allow/block/sanitize decisions based on evidence,
threat classification, and explicit security policies.
"""

from __future__ import annotations

import logging
import re
import time

from ai_firewall.models import (
    FirewallAction,
    GuardVerdict,
    PolicyDecision,
    RetrievalResult,
    ThreatLevel,
)
from ai_firewall.vector_db import VectorStore
from ai_firewall.config import config

logger = logging.getLogger("ai_firewall.policy_agent")


class PolicyAgent:
    """
    Policy Agent — the final arbiter of firewall decisions.

    Consumes outputs from the Guard Agent and Retrieval Agent,
    applies explicit security policies, and produces an action:
    - ALLOW: Prompt passes through to the LLM
    - BLOCK: Prompt is rejected entirely
    - SANITIZE: Prompt is modified to remove dangerous elements
    """

    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    def decide(
        self,
        prompt: str,
        guard: GuardVerdict,
        retrieval: RetrievalResult,
    ) -> PolicyDecision:
        """
        Make the final policy decision for a prompt.

        Args:
            prompt: Original user prompt
            guard: Classification from Guard Agent
            retrieval: Evidence from Retrieval Agent

        Returns:
            PolicyDecision with action, triggered rules, and explanation.
        """
        start = time.perf_counter()
        logger.info("Policy Agent: evaluating against security policies")

        triggered_rules: list[str] = []
        action = FirewallAction.ALLOW
        sanitized = None

        # ── Rule 1: MALICIOUS → always BLOCK ─────────────────────────────
        if guard.threat_level == ThreatLevel.MALICIOUS:
            action = FirewallAction.BLOCK
            triggered_rules.append("R1: MALICIOUS classification → BLOCK")

        # ── Rule 2: High confidence SUSPICIOUS → BLOCK ───────────────────
        elif (
            guard.threat_level == ThreatLevel.SUSPICIOUS
            and guard.confidence >= 0.5
            and guard.threat_score >= 0.30
        ):
            action = FirewallAction.BLOCK
            triggered_rules.append(
                "R2: SUSPICIOUS with confidence (≥0.5) and score (≥0.30) → BLOCK"
            )

        # ── Rule 3: SUSPICIOUS → try SANITIZE ────────────────────────────
        elif guard.threat_level == ThreatLevel.SUSPICIOUS:
            sanitized = self._sanitize_prompt(prompt)
            if sanitized != prompt:
                action = FirewallAction.SANITIZE
                triggered_rules.append(
                    "R3: SUSPICIOUS → SANITIZE (dangerous elements removed)"
                )
            else:
                # Can't sanitize effectively → BLOCK in strict mode
                if config.mode == "strict":
                    action = FirewallAction.BLOCK
                    triggered_rules.append(
                        "R3: SUSPICIOUS + unable to sanitize + strict mode → BLOCK"
                    )
                else:
                    action = FirewallAction.ALLOW
                    triggered_rules.append(
                        "R3: SUSPICIOUS but no sanitizable content found → ALLOW (non-strict mode)"
                    )

        # ── Rule 4: Known attack type matched with strong evidence ────────
        if (
            action == FirewallAction.ALLOW
            and retrieval.matched_attack_types
            and retrieval.max_similarity >= 0.45
        ):
            action = FirewallAction.BLOCK
            types = ", ".join(t.value for t in retrieval.matched_attack_types)
            triggered_rules.append(
                f"R4: Strong vector match ({retrieval.max_similarity:.3f}) "
                f"for attack type(s): {types} → BLOCK"
            )

        # ── Rule 5: Keyword matches alone can escalate ────────────────────
        if action == FirewallAction.ALLOW and len(guard.keyword_matches) >= 2:
            action = FirewallAction.BLOCK
            triggered_rules.append(
                f"R5: Multiple keyword matches ({len(guard.keyword_matches)}) → BLOCK"
            )

        # ── Rule 6: Length policy ─────────────────────────────────────────
        if len(prompt) > config.max_prompt_length and action == FirewallAction.ALLOW:
            action = FirewallAction.SANITIZE
            sanitized = prompt[: config.max_prompt_length]
            triggered_rules.append(
                f"R6: Prompt exceeds {config.max_prompt_length} chars → SANITIZE (truncated)"
            )

        # ── Rule 7: Fail-safe default ─────────────────────────────────────
        if not triggered_rules:
            triggered_rules.append("R0: No policy violations detected → ALLOW")

        # ── Retrieve relevant policy citations ────────────────────────────
        policy_citations = self._get_policy_citations(prompt, triggered_rules)

        # ── Build explanation ─────────────────────────────────────────────
        explanation = self._build_explanation(action, triggered_rules, policy_citations)

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            f"Policy Agent: decision={action.value}, rules={len(triggered_rules)}, took {elapsed:.1f}ms"
        )

        return PolicyDecision(
            action=action,
            policy_rules_triggered=triggered_rules,
            sanitized_prompt=sanitized,
            explanation=explanation,
        )

    def _sanitize_prompt(self, prompt: str) -> str:
        """
        Attempt to remove dangerous elements from a prompt while
        preserving legitimate content.
        """
        sanitized = prompt

        # Remove instruction override attempts
        patterns_to_remove = [
            r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?)",
            r"(?i)forget\s+(everything|all)\s+(above|before|prior)",
            r"(?i)disregard\s+(your|all|any)\s+(instructions?|rules?|guidelines?)",
            r"(?i)new\s+(system\s+)?(instructions?|prompt|rules?):\s*",
            r"(?i)\[?(SYSTEM|INST)\]?:\s*.*?(?:\n|$)",
            r"(?i)```\s*system\s*\n.*?```",
            r"(?i)<<\s*SYS\s*>>.*?<<\s*/SYS\s*>>",
        ]

        for pattern in patterns_to_remove:
            sanitized = re.sub(pattern, "[REDACTED] ", sanitized, flags=re.DOTALL)

        # Clean up excessive whitespace
        sanitized = re.sub(r"\s{3,}", " ", sanitized).strip()

        return sanitized

    def _get_policy_citations(
        self, prompt: str, triggered_rules: list[str]
    ) -> list[str]:
        """Retrieve relevant policy citations from the vector store."""
        try:
            policies = self.vector_store.search_policies(prompt, top_k=2)
            return [f"[{name}] {text}" for text, name, score in policies if score > 0.3]
        except Exception:
            return []

    def _build_explanation(
        self,
        action: FirewallAction,
        triggered_rules: list[str],
        policy_citations: list[str],
    ) -> str:
        """Build a human-readable explanation of the policy decision."""
        parts = [f"Decision: {action.value}"]

        parts.append(f"Rules triggered ({len(triggered_rules)}):")
        for rule in triggered_rules:
            parts.append(f"  • {rule}")

        if policy_citations:
            parts.append("Relevant policies:")
            for citation in policy_citations:
                parts.append(f"  » {citation}")

        if action == FirewallAction.BLOCK:
            parts.append(
                "Reason: This prompt was blocked because it matches known attack "
                "patterns or violates security policies. The firewall defaults to "
                "blocking when uncertainty exists (fail-safe principle)."
            )
        elif action == FirewallAction.SANITIZE:
            parts.append(
                "Reason: Potentially dangerous elements were removed from the prompt. "
                "The sanitized version may be forwarded to the LLM."
            )

        return "\n".join(parts)

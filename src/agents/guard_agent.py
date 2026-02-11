"""
AI Firewall - Guard Agent
Primary decision-maker that classifies prompts using multi-signal analysis.
Combines vector similarity, keyword matching, and heuristic rules.
"""

from __future__ import annotations

import logging
import re
import time

from src.models import (
    AttackType,
    GuardVerdict,
    HeuristicSignal,
    KeywordMatch,
    RetrievalResult,
    ThreatLevel,
)
from src.config import config

logger = logging.getLogger("ai_firewall.guard_agent")


class GuardAgent:
    """
    Guard Agent — the primary threat classifier.
    
    Combines three signal sources:
    1. Vector similarity scores from the Retrieval Agent
    2. Keyword-based pattern matching
    3. Heuristic rules (structural analysis)
    
    Produces a weighted threat score and classification.
    """

    def __init__(self):
        self.blocked_keywords = [kw.lower() for kw in config.blocked_keywords]

    def analyze(self, prompt: str, retrieval: RetrievalResult) -> GuardVerdict:
        """
        Analyze a prompt and produce a threat classification.
        
        Args:
            prompt: The user's input prompt
            retrieval: Evidence from the Retrieval Agent
            
        Returns:
            GuardVerdict with threat level, confidence, and reasoning.
        """
        start = time.perf_counter()
        logger.info("Guard Agent: beginning multi-signal analysis")

        # ── Signal 1: Vector Similarity ───────────────────────────────────
        vector_score = self._compute_vector_score(retrieval)

        # ── Signal 2: Keyword Matching ────────────────────────────────────
        keyword_matches = self._scan_keywords(prompt)
        keyword_score = min(len(keyword_matches) * 0.45, 1.0)

        # ── Signal 3: Heuristic Rules ─────────────────────────────────────
        heuristic_signals = self._run_heuristics(prompt)
        heuristic_score = (
            sum(s.severity for s in heuristic_signals) / max(len(heuristic_signals), 1)
            if heuristic_signals else 0.0
        )

        # ── Weighted Threat Score ─────────────────────────────────────────
        threat_score = (
            config.weight_vector_similarity * vector_score
            + config.weight_keyword_match * keyword_score
            + config.weight_heuristic * heuristic_score
        )
        threat_score = min(max(threat_score, 0.0), 1.0)

        # ── Classification ────────────────────────────────────────────────
        threat_level = self._classify(threat_score)

        # ── Confidence ────────────────────────────────────────────────────
        # Confidence is higher when signals agree
        signals = [vector_score, keyword_score, heuristic_score]
        signal_variance = self._variance(signals)
        confidence = max(0.5, 1.0 - signal_variance)

        # ── Reasoning ─────────────────────────────────────────────────────
        reasoning = self._build_reasoning(
            threat_level, threat_score, vector_score, keyword_matches,
            heuristic_signals, retrieval, confidence
        )

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            f"Guard Agent: threat_score={threat_score:.3f}, "
            f"level={threat_level.value}, confidence={confidence:.3f}, "
            f"took {elapsed:.1f}ms"
        )

        return GuardVerdict(
            threat_level=threat_level,
            confidence=round(confidence, 4),
            threat_score=round(threat_score, 4),
            keyword_matches=keyword_matches,
            heuristic_signals=heuristic_signals,
            reasoning=reasoning,
        )

    # ── Vector Score Computation ──────────────────────────────────────────────

    def _compute_vector_score(self, retrieval: RetrievalResult) -> float:
        """Convert retrieval evidence into a normalized threat score."""
        if not retrieval.evidence:
            return 0.0

        # Weight: max similarity matters most, boosted by number/strength of matches
        max_sim = retrieval.max_similarity
        match_count_bonus = min(len(retrieval.matched_attack_types) * 0.15, 0.3)
        # Boost if multiple strong matches exist
        strong_matches = sum(
            1 for e in retrieval.evidence
            if e.similarity_score >= config.similarity_threshold
        )
        strength_bonus = min(strong_matches * 0.1, 0.2)
        return min(max_sim + match_count_bonus + strength_bonus, 1.0)

    # ── Keyword Scanning ──────────────────────────────────────────────────────

    def _scan_keywords(self, prompt: str) -> list[KeywordMatch]:
        """Scan prompt for known malicious keywords/phrases."""
        matches = []
        prompt_lower = prompt.lower()
        # Normalize whitespace for better matching
        prompt_normalized = " ".join(prompt_lower.split())

        for keyword in self.blocked_keywords:
            # Search both original and normalized
            for search_text in (prompt_lower, prompt_normalized):
                pos = search_text.find(keyword)
                if pos != -1:
                    # Extract context window
                    ctx_start = max(0, pos - 20)
                    ctx_end = min(len(search_text), pos + len(keyword) + 20)
                    context = search_text[ctx_start:ctx_end]

                    matches.append(KeywordMatch(
                        keyword=keyword,
                        position=pos,
                        context=f"...{context}...",
                    ))
                    break  # Found in one form, no need to check the other

        return matches

    # ── Heuristic Rules ───────────────────────────────────────────────────────

    def _run_heuristics(self, prompt: str) -> list[HeuristicSignal]:
        """Run structural heuristic rules on the prompt."""
        signals = []

        # Rule 1: Excessive length
        if len(prompt) > config.max_prompt_length:
            signals.append(HeuristicSignal(
                rule_name="excessive_length",
                description=f"Prompt exceeds {config.max_prompt_length} chars ({len(prompt)} chars)",
                severity=0.4,
            ))

        # Rule 2: Contains role assignment patterns
        role_patterns = [
            r"you are(?: now)?\s+(a|an|the|my)\s+\w+",
            r"act as\s+(a|an|if)\s+",
            r"pretend\s+(you are|to be)",
            r"from now on,?\s+you",
        ]
        for pattern in role_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                signals.append(HeuristicSignal(
                    rule_name="role_assignment",
                    description=f"Detected role assignment pattern: /{pattern}/",
                    severity=0.7,
                ))
                break

        # Rule 3: Contains system/instruction framing
        system_patterns = [
            r"\[?(SYSTEM|INST|SYS)\]?[\s:]+",
            r"```\s*system",
            r"<<\s*SYS\s*>>",
            r"SYSTEM\s*(?:PROMPT|MESSAGE|UPDATE|OVERRIDE)",
        ]
        for pattern in system_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                signals.append(HeuristicSignal(
                    rule_name="system_framing",
                    description=f"Detected fake system message framing: /{pattern}/",
                    severity=0.85,
                ))
                break

        # Rule 4: Contains encoded or obfuscated content
        obfuscation_patterns = [
            r"\\x[0-9a-fA-F]{2}",       # hex escape
            r"\\u[0-9a-fA-F]{4}",       # unicode escape
            r"base64[:=]\s*[A-Za-z0-9+/=]{20,}",
            r"&#\d{2,4};",              # HTML entities
        ]
        for pattern in obfuscation_patterns:
            if re.search(pattern, prompt):
                signals.append(HeuristicSignal(
                    rule_name="obfuscation_detected",
                    description="Prompt contains encoded or obfuscated content",
                    severity=0.6,
                ))
                break

        # Rule 5: Urgency/authority indicators
        urgency_patterns = [
            r"(immediately|urgent|right now|ASAP)",
            r"(authorization|admin|root)\s*(code|access|mode|level)",
            r"(override|bypass|disable)\s*(your|the|all)\s*(safety|filter|restrict|rule|polic)",
        ]
        for pattern in urgency_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                signals.append(HeuristicSignal(
                    rule_name="urgency_authority",
                    description="Prompt uses urgency or authority pressure tactics",
                    severity=0.55,
                ))
                break

        # Rule 6: Multiple instruction-like sentences
        instruction_indicators = prompt.lower().count("you must") + \
            prompt.lower().count("you should") + \
            prompt.lower().count("you will") + \
            prompt.lower().count("you have to")
        if instruction_indicators >= 2:
            signals.append(HeuristicSignal(
                rule_name="multiple_instructions",
                description=f"Prompt contains {instruction_indicators} directive statements",
                severity=0.5,
            ))

        return signals

    # ── Classification ────────────────────────────────────────────────────────

    def _classify(self, threat_score: float) -> ThreatLevel:
        """Map threat score to threat level."""
        if threat_score >= config.malicious_threshold:
            return ThreatLevel.MALICIOUS
        elif threat_score >= config.suspicious_threshold:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.SAFE

    # ── Reasoning ─────────────────────────────────────────────────────────────

    def _build_reasoning(
        self,
        threat_level: ThreatLevel,
        threat_score: float,
        vector_score: float,
        keyword_matches: list[KeywordMatch],
        heuristic_signals: list[HeuristicSignal],
        retrieval: RetrievalResult,
        confidence: float,
    ) -> str:
        """Build a human-readable explanation of the classification decision."""
        parts = [f"Threat classification: {threat_level.value} (score: {threat_score:.3f}, confidence: {confidence:.3f})"]

        # Vector evidence
        if retrieval.evidence:
            top = retrieval.evidence[0]
            parts.append(
                f"Vector DB: Top match is '{top.attack_type.value}' "
                f"with similarity {top.similarity_score:.3f}. "
                f"{len(retrieval.matched_attack_types)} attack type(s) matched above threshold."
            )
        else:
            parts.append("Vector DB: No significant matches found.")

        # Keyword evidence
        if keyword_matches:
            kw_list = ", ".join(f"'{m.keyword}'" for m in keyword_matches[:3])
            parts.append(f"Keywords: Matched {len(keyword_matches)} blocked term(s): {kw_list}.")
        else:
            parts.append("Keywords: No blocked terms detected.")

        # Heuristic evidence
        if heuristic_signals:
            rules = ", ".join(s.rule_name for s in heuristic_signals)
            parts.append(f"Heuristics: {len(heuristic_signals)} rule(s) triggered: {rules}.")
        else:
            parts.append("Heuristics: No structural anomalies detected.")

        return " | ".join(parts)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _variance(values: list[float]) -> float:
        """Compute variance of a list of floats."""
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        return sum((v - mean) ** 2 for v in values) / len(values)

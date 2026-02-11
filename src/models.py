"""
AI Firewall - Data Models
Pydantic models for requests, responses, and internal data flow.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class FirewallAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANITIZE = "SANITIZE"


class AttackType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ROLE_CONFUSION = "role_confusion"
    POLICY_EVASION = "policy_evasion"
    INSTRUCTION_OVERRIDE = "instruction_override"
    INSTRUCTION_LEAKAGE = "instruction_leakage"
    SAFE = "safe"


# ── Evidence & Analysis ───────────────────────────────────────────────────────

class RetrievedEvidence(BaseModel):
    """A single piece of evidence retrieved from the vector database."""
    text: str
    attack_type: AttackType
    similarity_score: float = Field(ge=0.0, le=1.0)
    source: str = "vector_db"


class KeywordMatch(BaseModel):
    """A keyword-based detection match."""
    keyword: str
    position: int
    context: str  # surrounding text


class HeuristicSignal(BaseModel):
    """A signal from heuristic analysis."""
    rule_name: str
    description: str
    severity: float = Field(ge=0.0, le=1.0)


# ── Agent Outputs ─────────────────────────────────────────────────────────────

class RetrievalResult(BaseModel):
    """Output from the Retrieval Agent."""
    evidence: list[RetrievedEvidence] = []
    max_similarity: float = 0.0
    avg_similarity: float = 0.0
    matched_attack_types: list[AttackType] = []


class GuardVerdict(BaseModel):
    """Output from the Guard Agent."""
    threat_level: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0)
    threat_score: float = Field(ge=0.0, le=1.0)
    keyword_matches: list[KeywordMatch] = []
    heuristic_signals: list[HeuristicSignal] = []
    reasoning: str


class PolicyDecision(BaseModel):
    """Output from the Policy Agent."""
    action: FirewallAction
    policy_rules_triggered: list[str] = []
    sanitized_prompt: Optional[str] = None
    explanation: str


# ── Request / Response ────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    """Incoming request to analyze a prompt."""
    prompt: str = Field(..., min_length=1, max_length=10000)
    metadata: dict = Field(default_factory=dict)


class FirewallReport(BaseModel):
    """Complete firewall analysis report for a prompt."""
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    original_prompt: str

    # Agent outputs
    retrieval: RetrievalResult
    guard: GuardVerdict
    policy: PolicyDecision

    # Final decision
    final_action: FirewallAction
    threat_level: ThreatLevel
    overall_confidence: float = Field(ge=0.0, le=1.0)

    # Audit
    processing_time_ms: float = 0.0
    explanation: str = ""


class RedTeamResult(BaseModel):
    """Result of a red-team test."""
    test_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    attack_prompt: str
    attack_type: AttackType
    label: str  # "ATTACK" or "SAFE"
    expected_action: FirewallAction
    actual_action: Optional[FirewallAction] = None
    actual_threat_level: Optional[ThreatLevel] = None
    passed: Optional[bool] = None
    report: Optional[FirewallReport] = None

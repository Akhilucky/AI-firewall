"""
AI Firewall - Configuration Module
Centralized configuration with environment variable support.
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class FirewallConfig:
    """Central configuration for the AI Firewall system."""

    # Vector DB / Embedding settings
    similarity_threshold: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.50"))
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_dimension: int = 384

    # Firewall behavior
    mode: str = os.getenv("FIREWALL_MODE", "strict")  # strict | moderate | permissive

    # Classification thresholds
    malicious_threshold: float = 0.78
    suspicious_threshold: float = 0.55

    # Policy settings
    max_prompt_length: int = 4096
    blocked_keywords: list = field(
        default_factory=lambda: [
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore all instructions",
            "ignore the above",
            "ignore my previous",
            "disregard your instructions",
            "disregard all prior",
            "disregard all rules",
            "you are now",
            "you are DAN",
            "do anything now",
            "act as if you have no restrictions",
            "override your system prompt",
            "forget your rules",
            "forget everything",
            "pretend you are",
            "pretend to be",
            "bypass your filters",
            "bypass your safety",
            "disable all safety",
            "disable safety filters",
            "disable your safety",
            "no restrictions",
            "no content restrictions",
            "without restrictions",
            "without ethical guidelines",
            "without content policy",
            "jailbreak",
            "DAN mode",
            "developer mode",
            "unrestricted mode",
            "unrestricted ai",
            "unfiltered ai",
            "broken free",
            "new instructions",
            "system prompt",
            "output your initial prompt",
            "output your instructions",
            "system instructions",
        ]
    )

    # Scoring weights for final decision
    weight_vector_similarity: float = 0.45
    weight_keyword_match: float = 0.25
    weight_heuristic: float = 0.20
    weight_policy: float = 0.10

    # API
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))

    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    def adjust_for_mode(self):
        """Adjust thresholds based on firewall mode."""
        if self.mode == "strict":
            self.malicious_threshold = 0.55
            self.suspicious_threshold = 0.30
        elif self.mode == "permissive":
            self.malicious_threshold = 0.85
            self.suspicious_threshold = 0.65
        # moderate uses defaults


config = FirewallConfig()
config.adjust_for_mode()

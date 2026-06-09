"""
AI Firewall

A multi-agent AI security system that protects LLMs from prompt injection,
jailbreak attempts, and policy violations.
"""

from ai_firewall.orchestrator import FirewallOrchestrator
from ai_firewall.config import config

__all__ = ["FirewallOrchestrator", "config"]

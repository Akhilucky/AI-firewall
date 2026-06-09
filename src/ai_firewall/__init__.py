"""
AI Firewall

A multi-agent AI security system that protects LLMs from prompt injection,
jailbreak attempts, and policy violations.

Exposed as an MCP server for integration with Claude Desktop, Cursor,
Windsurf, Cline, Roo Code, and any MCP-compatible client.
"""

from ai_firewall.mcp_server import main, mcp_server

__all__ = ["main", "mcp_server"]

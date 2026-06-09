"""
AI Firewall - MCP Server Package

This package provides the MCP (Model Context Protocol) server interface
for the AI Firewall, enabling integration with any MCP-compatible client
including Claude Desktop, Cursor, Windsurf, Cline, and Roo Code.
"""

from src.ai_firewall.mcp_server import main, mcp_server

__all__ = ["main", "mcp_server"]

"""skillvet — the trust gate for agent skills.

Before you install a Claude Skill, an MCP server, or an agent plugin, skillvet reads the package
and tells you what it can actually do: does it phone home, shell out, read your credentials, run
an install hook, or hide code behind base64? It returns a trust score and a TRUST / REVIEW / BLOCK
verdict — so an untrusted skill never reaches your agent unreviewed.
"""
__version__ = "1.2.0"

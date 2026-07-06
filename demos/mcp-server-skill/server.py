"""A minimal, inert MCP-style server stub. It only formats a canned reply; the point of this
demo is that the manifest declares a launch command (a process the host will exec), which
skillvet surfaces from mcp.json alone."""


def get_weather(city: str) -> str:
    return f"Weather for {city}: sunny, 22C (demo stub)."

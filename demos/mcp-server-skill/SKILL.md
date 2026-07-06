# Weather MCP Server

An MCP server that exposes a `get_weather` tool. Its `mcp.json` declares a launch `command`, which
means the host will spawn a process on your machine — a declared exec surface. skillvet surfaces
that from the manifest alone (`manifest_overbroad`), before it even reads the server code.

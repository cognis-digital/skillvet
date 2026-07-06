import json


def run(query: str) -> str:
    """Pretty-print a JSON string. No network, no shell, no secrets — despite what the
    manifest asks for."""
    return json.dumps(json.loads(query), indent=2, sort_keys=True)

def run(query: str) -> str:
    """Return the query in title case."""
    return " ".join(w.capitalize() for w in query.split())

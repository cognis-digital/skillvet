def run(markdown: str) -> str:
    """v1.0.0 — lint heading levels. No network, no shell, no files."""
    levels = [len(line) - len(line.lstrip("#"))
              for line in markdown.splitlines() if line.startswith("#")]
    problems = [i for i in range(1, len(levels)) if levels[i] > levels[i - 1] + 1]
    return "ok" if not problems else f"heading jump at heading #{problems[0] + 1}"

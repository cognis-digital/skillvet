# Contributing to skillvet

The most valuable contributions are **new capability checks** and **new install-hook detectors** —
the patterns that reveal what a skill can do.

## Add a capability check
In `skillvet/analyzer.py`, add to `CHECKS` (or `INSTALL_HOOK_FILES`): a capability name, severity,
weight, MITRE ATLAS id, and a list of `(regex, why)` patterns. Add a demo file + a test proving it
fires on a malicious sample and stays quiet on the benign one.

## Ground rules
- **Never execute the target.** skillvet is static by design.
- **Real capabilities only.** Each check maps to something a skill can actually do.
- **Low false-positive.** The benign demo must stay TRUST (the suite enforces it).
- **Stdlib + offline.** No runtime deps (agentsigs is an optional extra).

```bash
pip install -e ".[dev]"
pytest -q
skillvet vet demos/malicious-skill   # BLOCK
skillvet vet demos/benign-skill      # TRUST
```

Ideas and new attack classes: [Discussions](https://github.com/cognis-digital/skillvet/discussions).

<div align="center">

# skillvet

**The trust gate for agent skills.** Before you install a Claude Skill, an MCP server, or an agent plugin, skillvet reads the package and tells you what it can actually *do* — phone home, shell out, read your credentials, run an install hook, hide code behind base64 — then gives you a trust score and a **TRUST / REVIEW / BLOCK** verdict. It never runs the code.

[![PyPI](https://img.shields.io/pypi/v/skillvet.svg)](https://pypi.org/project/skillvet/)
[![CI](https://github.com/cognis-digital/skillvet/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/skillvet/actions)
[![License: COCL 1.0](https://img.shields.io/badge/license-COCL%201.0-blue.svg)](LICENSE)
![Verdict](https://img.shields.io/badge/verdict-TRUST%20%2F%20REVIEW%20%2F%20BLOCK-informational)
![Deps](https://img.shields.io/badge/runtime%20deps-none%20(stdlib)-success)

</div>

Agent skills and MCP servers are code you hand your assistant — with your files, your tokens, and a shell. People install them from a gist or a marketplace and *trust them by vibes*. skillvet is the missing supply-chain check: point it at a package and it statically surfaces every dangerous capability, before that code ever touches your agent.

```bash
pip install skillvet
skillvet vet ./some-downloaded-skill
```

Zero runtime dependencies, fully offline, never executes the package. Exit code gates CI/pre-install: `0` TRUST, `1` REVIEW, `2` BLOCK.

## See it work

A skill that reads your SSH key, exfiltrates it, shells out, hides a base64 payload, and runs a `curl | sh` install hook:

```console
$ skillvet vet ./repo-helper
skillvet — repo-helper
============================================================
  verdict: BLOCK  ✗    trust score: 0/100
  3 file(s) analyzed, 6 capability finding(s)
  capabilities: credential_access, install_hook, network_egress, obfuscation, process_exec
------------------------------------------------------------
  [CRIT] process_exec       skill.py:9  spawns a subprocess
  [CRIT] credential_access  skill.py:4  reads credential files
  [HIGH] install_hook       package.json:2  npm install hook runs code on install
  [HIGH] network_egress     package.json:2  shells out to a network tool
  [HIGH] network_egress     skill.py:1  makes HTTP requests
  [HIGH] obfuscation        skill.py:11  executes decoded bytes
------------------------------------------------------------
  BLOCK: do not install without a manual review.
```

A skill that just title-cases text:

```console
$ skillvet vet ./text-titlecase
  verdict: TRUST  ✓    trust score: 100/100
  no risky capabilities detected — this package is inert.
```

## What it checks

| Capability | Why it matters | Severity |
|---|---|:---:|
| `process_exec` | subprocess / `os.system` / `eval` / `child_process` | critical |
| `credential_access` | reads `~/.ssh`, `.env`, `.aws/credentials`, env vars, or embeds a key | critical |
| `dynamic_fetch` | fetches and executes remote code, installs from a URL at runtime | critical |
| `network_egress` | HTTP clients, raw sockets, `curl`/`wget` | high |
| `obfuscation` | base64/hex-then-exec, long encoded blobs | high |
| `install_hook` | npm pre/postinstall, `setup.py`, build hooks that run on install | high |
| `filesystem_write` | writes/deletes files | medium |

Every finding is tagged with a MITRE ATLAS technique. A skill that title-cases text needs none of these — one that has all of them is not a skill, it's malware with a friendly `SKILL.md`.

## Use it

```bash
skillvet vet ./skill                 # analyze a package directory
skillvet vet ./skill -f json         # machine-readable
skillvet vet ./skill --min REVIEW    # gate: nonzero unless verdict is TRUST or REVIEW
```

**As a pre-install gate:**
```bash
skillvet vet "$SKILL_DIR" || { echo "skill failed trust gate"; exit 1; }
```

**Deeper content scan:** install the `content` extra to also scan the skill's prose for
prompt-injection / tool-poisoning via [shrike](https://github.com/cognis-digital/shrike):
```bash
pip install "skillvet[content]"
skillvet vet ./skill                 # now also flags poisoned SKILL.md / tool descriptions
```

## Why static, why offline

skillvet **never executes** the package — that's the point of a pre-install gate. It reads the
files and reports capabilities. It runs fully offline, so you can vet a skill on an air-gapped box
before it ever reaches a machine with your credentials on it.

## Pairs with shrike

- **[skillvet](https://github.com/cognis-digital/skillvet)** — vet a skill/plugin *before* you install it (this repo)
- **[shrike](https://github.com/cognis-digital/shrike)** — audit the MCP servers already wired into your stack, and the AI-threat signature library skillvet's `content` extra uses to scan a skill's prose

## Defensive use

skillvet is a defensive static analyzer. It reads packages and reports capabilities; it does not
execute them or attack anything. Use it to decide what to trust.

## License

[COCL 1.0](LICENSE). See [DISCLAIMER.md](DISCLAIMER.md).

<div align="center"><sub>Part of the <a href="https://github.com/cognis-digital">Cognis</a> AI-security tooling.</sub></div>

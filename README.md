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

A skill that reads your SSH key, exfiltrates it, shells out, hides a base64 payload, and runs a `curl | sh` install hook. skillvet correlates the credential read + egress into an `exfiltration_surface` signal:

```console
$ skillvet vet ./repo-helper
skillvet — malicious-skill
============================================================
  verdict: BLOCK  ✗    trust score: 0/100
  3 file(s) analyzed, 7 capability finding(s)
  capabilities: credential_access, exfiltration_surface, install_hook, network_egress, obfuscation, process_exec
------------------------------------------------------------
  [CRIT] process_exec         skill.py:9  spawns a subprocess
  [CRIT] credential_access    skill.py:4  reads credential files
  [CRIT] exfiltration_surface skill.py  same file reads credentials and has network egress
  [HIGH] install_hook         package.json:2  npm install hook runs code on install
  [HIGH] network_egress       package.json:2  shells out to a network tool
  [HIGH] network_egress       skill.py:1  makes HTTP requests
  [HIGH] obfuscation          skill.py:11  executes decoded bytes
------------------------------------------------------------
  BLOCK: do not install without a manual review — this package can take actions
         (exec / exfiltrate / read credentials) that a skill should not need.
```

A skill that just title-cases text:

```console
$ skillvet vet ./text-titlecase
  verdict: TRUST  ✓    trust score: 100/100
  no risky capabilities detected — this package is inert.
```

A JSON pretty-printer whose *manifest* asks for shell, network, credentials, and filesystem access it never uses — the over-broad permission request skillvet flags without even reaching the code:

```console
$ skillvet vet ./json-prettifier
  verdict: REVIEW ⚠    trust score: 85/100
  capabilities: manifest_overbroad
------------------------------------------------------------
  [HIGH] manifest_overbroad   SKILL.md  manifest declares a credential access permission/scope that the code does not appear to use (over-broad request)
  [HIGH] manifest_overbroad   SKILL.md  manifest declares a process exec permission/scope that the code does not appear to use (over-broad request)
  ...
```

All three are runnable: `python demos/run_all.py` exercises these plus the rug-pull, SARIF, exfiltration, and policy scenarios (28 checks, exits 0).

## What it checks

| Capability | Why it matters | Severity |
|---|---|:---:|
| `process_exec` | subprocess / `os.system` / `eval` / `child_process` | critical |
| `credential_access` | reads `~/.ssh`, `.env`, `.aws/credentials`, env vars, or embeds a key | critical |
| `dynamic_fetch` | fetches and executes remote code, installs from a URL at runtime | critical |
| `exfiltration_surface` | **correlated**: reads credentials *and* has network egress — an exfil path | critical |
| `network_egress` | HTTP clients, raw sockets, `curl`/`wget` | high |
| `obfuscation` | base64/hex-then-exec, long encoded blobs | high |
| `install_hook` | npm pre/postinstall, `setup.py`, build hooks that run on install | high |
| `manifest_overbroad` | manifest declares broad/unused exec/network/credential/fs scopes | high |
| `filesystem_write` | writes/deletes files | medium |

Every finding is tagged with a MITRE ATLAS technique. A skill that title-cases text needs none of these — one that has all of them is not a skill, it's malware with a friendly `SKILL.md`.

## Headline features

- **Rug-pull detection** — record a [baseline](docs/RUG-PULL.md) of a skill you trusted, then `diff` an update against it. New dangerous capabilities appearing on an "update" is the rug-pull signal; `diff` exits `2`.
- **SARIF 2.1.0 output** — `-f sarif` makes skillvet a CI-native [code scanner](docs/SARIF.md): one rule per capability, ATLAS tags, GitHub code-scanning ready.
- **Manifest / permission vetting** — parses `SKILL.md` frontmatter, `package.json`, MCP `mcp.json`, and `pyproject.toml` for over-broad or declared-but-unused permissions.
- **Exfiltration-surface correlation** — a package that both reads secrets *and* phones home is scored worse than either alone.
- **Tunable policy** — a [policy file](docs/POLICY.md) tunes weights, thresholds, and per-capability allow/deny for your environment.

```bash
skillvet vet ./skill -f sarif > skillvet.sarif        # CI code-scanning
skillvet baseline ./skill -o baseline.json            # record what you trust
skillvet diff baseline.json ./skill                   # did the update rug you?
skillvet vet ./skill --policy policy.json              # tune the gate
```

## Use it

```bash
skillvet vet ./skill                 # analyze a package directory
skillvet vet ./skill -f json         # machine-readable
skillvet vet ./skill -f sarif        # SARIF 2.1.0 for CI code-scanning
skillvet vet ./skill --policy p.json # tune weights/thresholds/allow-deny
skillvet vet ./skill --baseline b.json   # also rug-pull check against a baseline
skillvet baseline ./skill -o b.json  # record a fingerprint of a package you trust
skillvet diff b.json ./skill         # what changed since the baseline
```

Exit codes gate CI/pre-install: `0` TRUST, `1` REVIEW, `2` BLOCK. `diff` exits `2` on a rug-pull.

**As a pre-install gate:**
```bash
skillvet vet "$SKILL_DIR" || { echo "skill failed trust gate"; exit 1; }
```

## Install (Windows / macOS / Linux)

Core is stdlib-only — nothing to compile, nothing to pull.

```bash
pip install skillvet                 # from PyPI
# or from a clone:
./install.sh                         # macOS / Linux  (./install.sh --content for shrike scan)
```
```powershell
.\install.ps1                        # Windows PowerShell  (.\install.ps1 -Content for shrike scan)
```
```bash
make install                         # or via Makefile: install / test / demos / smoke
docker build -t skillvet . && docker run --rm -v "$PWD/skill:/scan:ro" skillvet vet /scan
```

Tested on Python 3.10 / 3.11 / 3.12 across Linux, macOS, and Windows. All file I/O is UTF-8;
paths use `pathlib`/`os.path` and normalize to forward slashes for display and fingerprints.

**Deeper content scan:** install the `content` extra to also scan the skill's prose for
prompt-injection / tool-poisoning via [shrike](https://github.com/cognis-digital/shrike):
```bash
pip install "skillvet[content]"
skillvet vet ./skill                 # now also flags poisoned SKILL.md / tool descriptions
```

## Docs

- [How it works](docs/how-it-works.md) — the pipeline at a glance
- [Architecture](docs/ARCHITECTURE.md) — capability model, scoring, threat model
- [Rug-pull detection](docs/RUG-PULL.md) — baseline + diff workflow
- [SARIF output](docs/SARIF.md) — CI code-scanning integration
- [Policy](docs/POLICY.md) — tune the gate for your environment

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

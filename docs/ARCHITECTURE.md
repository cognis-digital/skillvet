# skillvet architecture

skillvet is a **static** supply-chain trust gate for agent skills. It reads a package and reports
what the code is *capable of*, scores it, and returns TRUST / REVIEW / BLOCK — **without ever
executing the package**. That last property is the whole point: you learn what a skill can do
before it touches a machine with your credentials on it.

Core runtime is **standard-library only**. The single optional dependency (`shrike-sec`, the
`content` extra) adds a prose/prompt-injection content scan and degrades to a no-op when absent.

## Pipeline

```
  package dir/file
        │
        ▼
  ┌───────────────┐   walk files, skip node_modules/.git/__pycache__
  │  file walk    │   (os.sep-aware; utf-8 reads with errors="replace")
  └──────┬────────┘
         ▼
  ┌───────────────┐   regex capability checks per code file (analyzer.CHECKS)
  │ capability    │   → Finding(capability, severity, why, file, line, atlas)
  │ scan          │     one finding per capability per file
  └──────┬────────┘
         ▼
  ┌───────────────┐   package.json / setup.py / pyproject build hooks
  │ install-hook  │   → install_hook finding (runs code at install time)
  └──────┬────────┘
         ▼
  ┌───────────────┐   SKILL.md frontmatter / package.json / mcp.json / pyproject
  │ manifest      │   declared permissions & scopes → manifest_overbroad
  │ vetting       │   (broad request, or declared-but-unused = mismatch)
  └──────┬────────┘
         ▼
  ┌───────────────┐   credential_access + network_egress in same file/package
  │ correlation   │   → exfiltration_surface (elevated: the two halves of exfil)
  └──────┬────────┘
         ▼
  ┌───────────────┐   optional: shrike-sec signature scan of prose (0 if absent)
  │ content scan  │
  └──────┬────────┘
         ▼
  ┌───────────────┐   policy-weighted score + thresholds + allow/deny
  │ score+verdict │   → TRUST / REVIEW / BLOCK, exit code 0/1/2
  └───────────────┘
```

## Capability model

Each finding names a **capability** — a class of thing the code can do that a passive skill would
not need. Capabilities are either **pattern-detected** (a regex hit in a code file) or **derived**
(computed from correlations or parsed manifests).

| Capability | Kind | Severity | Weight | ATLAS |
|---|---|---|---:|---|
| `process_exec` | pattern | critical | 30 | AML.T0053 |
| `credential_access` | pattern | critical | 30 | AML.T0055 |
| `dynamic_fetch` | pattern | critical | 30 | AML.T0053 |
| `network_egress` | pattern | high | 20 | AML.T0025 |
| `obfuscation` | pattern | high | 20 | AML.T0051 |
| `install_hook` | pattern (manifest files) | high | 20 | AML.T0053 |
| `exfiltration_surface` | derived (correlation) | critical | 25 | AML.T0025 |
| `manifest_overbroad` | derived (manifest) | high | 15 | AML.T0051 |
| `filesystem_write` | pattern | medium | 10 | AML.T0053 |

Weights and thresholds shown are the **defaults**; a [policy](POLICY.md) can override them.

## Scoring model (honest)

The trust score starts at **100** and subtracts a penalty:

- For each **distinct** capability found, subtract its weight (deduped — ten `network_egress`
  hits still only cost 20; skillvet reports *capability presence*, not a hit count).
- Add `min(content_matches × content_weight, 24)` for optional content-scan matches.
- Clamp to `[0, 100]`.

Verdict from the score + a hard rule:

- **BLOCK** if any *active* (not allow-listed) finding is `critical`, **or** the score is below
  `block_below` (default 40), **or** a *deny-listed* capability is present.
- **REVIEW** if the score is below `review_below` (default 75), or there is any active finding, or
  any content match.
- **TRUST** otherwise.

This is intentionally simple and transparent — you can predict a verdict by hand. It is a
*capability* score, not a probability of maliciousness; see the threat model below.

## Rug-pull / baseline diff

`baseline` records a fingerprint of a package you reviewed: per-file SHA-256, the capability set,
the score, and a BLAKE2b `self_hash` over the canonical body (a tamper check on the baseline file).
`diff` re-analyzes an "update" and reports files added/removed/changed and, the headline, which
capabilities **newly appeared**. New `process_exec` / `credential_access` / `network_egress` /
`exfiltration_surface` on an update is the rug-pull signal — `diff` exits 2. See [RUG-PULL.md](RUG-PULL.md).

## SARIF

`vet -f sarif` emits SARIF 2.1.0: one rule per capability (rule id == capability, help text == the
"why", severity mapped to error/warning/note, ATLAS technique in `properties.tags`), one result per
finding at its file/line. This makes skillvet a drop-in CI code-scanning tool. See [SARIF.md](SARIF.md).

## Threat model & limits (be honest)

**What skillvet catches:** the *capabilities* a package has — exec, egress, credential reads,
install hooks, obfuscation, over-broad manifests, exfiltration surfaces — and the *appearance* of
new dangerous capabilities across an update.

**What it does not:** it is regex/static, so it sees capabilities, not intent. A legitimate skill
may genuinely need the network; skillvet's job is to make sure you *know* and made a deliberate
choice. It does not fully model heavy obfuscation, does not follow dynamic dispatch, and does not
prove maliciousness. It maps to OWASP LLM/agent concerns — supply-chain (LLM03/LLM05-class) and
excessive agency (LLM08-class) — but complements, not replaces, sandboxing and least-privilege.

Roadmap items (AST-based analysis to reduce regex false positives, MCP transport declarations,
cryptographically signed baselines) are tracked as GitHub issues.

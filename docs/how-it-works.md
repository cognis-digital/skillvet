# How skillvet works

skillvet is a **static** analyzer: it reads a package and reports what the code is *capable of*,
without ever running it. That's what makes it safe to use as a pre-install gate — you learn what a
skill can do before it touches a machine with your credentials.

## The pipeline
1. **Walk the package** — every file, skipping `node_modules`, `.git`, `__pycache__`.
2. **Capability scan** — code files (`.py/.js/.ts/.sh/...`) are matched against capability patterns:
   process execution, network egress, credential/filesystem access, obfuscation, dynamic remote
   fetch. One finding per capability per file, each tagged with a MITRE ATLAS technique.
3. **Install-hook scan** — `package.json` (pre/postinstall), `setup.py`, and build hooks that run
   code *at install time* — the classic supply-chain foothold.
4. **Manifest / permission vetting** — `SKILL.md` frontmatter, `package.json`, MCP `mcp.json`, and
   `pyproject.toml` are parsed for declared permissions/scopes. A manifest that asks for broad
   exec/network/credential/fs access — or declares a dangerous scope the code never uses
   (declared-vs-used mismatch) — is flagged `manifest_overbroad`.
5. **Exfiltration-surface correlation** — a package that both reads credentials *and* has network
   egress (especially in the same file) is worse than either alone: the two halves of an exfil
   path. skillvet raises an elevated `exfiltration_surface` signal.
6. **Content scan (optional)** — with the `content` extra, the skill's prose (`SKILL.md`, tool
   descriptions) is scanned by [shrike](https://github.com/cognis-digital/shrike) for prompt
   injection and tool poisoning. Absent shrike, this degrades cleanly to 0.
7. **Score + verdict** — capabilities subtract weight from a 100-point trust score, tunable with a
   [policy](POLICY.md). Any critical capability, or a score under the block threshold, is **BLOCK**;
   anything with findings is at least **REVIEW**; a clean, inert package is **TRUST**.

## Beyond a single scan
- **[Rug-pull detection](RUG-PULL.md)** — record a baseline of a package you trusted, then `diff` an
  update against it; newly-appeared dangerous capabilities are the rug-pull signal.
- **[SARIF 2.1.0 output](SARIF.md)** — `-f sarif` makes skillvet a CI code-scanning tool.
- **[Policy](POLICY.md)** — tune weights, thresholds, and per-capability allow/deny for your team.
- **[Architecture](ARCHITECTURE.md)** — the full pipeline, capability model, scoring, threat model.

## Reading the verdict
- **TRUST** — no dangerous capabilities. A passive skill (text transforms, formatting) lands here.
- **REVIEW** — capable of more than a passive skill; read the flagged lines and decide.
- **BLOCK** — can execute, exfiltrate, or read credentials. Don't install without manual review.

## Limits (be honest)
Static analysis sees capabilities, not intent — a legitimate skill may genuinely need the network.
skillvet's job is to make sure you *know* what a skill can do and made a deliberate choice, not to
prove maliciousness. It complements, not replaces, sandboxing and least-privilege.

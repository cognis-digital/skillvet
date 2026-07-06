# Rug-pull detection

A skill you reviewed and trusted at install can turn hostile on its next "update" — the classic
**rug-pull**. The code you audited is not the code that ships in v1.0.1. skillvet closes that gap
with a two-step baseline/diff workflow.

## 1. Record a baseline of what you trusted

```console
$ skillvet baseline ./markdown-linter -o baseline.json
skillvet: recorded baseline for v1-benign (score 100, 2 file(s), 0 capability(ies)) -> baseline.json
```

The baseline (schema: [`schema/baseline.schema.json`](../schema/baseline.schema.json)) records:

- a **SHA-256 per file** (forward-slash relative paths, stable across OSes),
- the **capability set** and **trust score** at record time,
- a BLAKE2b **`self_hash`** over the canonical body — a tamper check on the baseline file itself.

Commit `baseline.json` next to your lockfile. It is what "trusted" means, made concrete.

## 2. Diff the update against it

When an update arrives, diff it:

```console
$ skillvet diff baseline.json ./markdown-linter
skillvet diff — v2-malicious
============================================================
  score: 100 -> 0
  RUG-PULL: new dangerous capabilities appeared: credential_access, exfiltration_surface, network_egress, process_exec
------------------------------------------------------------
  + new capabilities:     credential_access, exfiltration_surface, network_egress, process_exec
  file changed: SKILL.md
  file changed: skill.py
------------------------------------------------------------
  BLOCK this update: it gained capabilities it did not have when you trusted it.
```

The headline signal is **new capabilities appearing**. A "bugfix" that suddenly reads
`~/.aws/credentials`, phones home, and shells out did not fix a bug — it rugged you.

## Exit codes

`diff` (and `vet --baseline`) gate CI:

| Situation | Exit |
|---|---:|
| new dangerous capability appeared (rug-pull) | `2` |
| package changed but no new dangerous capability | `1` |
| unchanged since baseline | `0` |

"Dangerous" here means: `process_exec`, `credential_access`, `network_egress`, `dynamic_fetch`,
`obfuscation`, `install_hook`, `exfiltration_surface`.

## Wire it into updates

```bash
# in your dependency-update job, before you accept a new skill version:
skillvet diff skills/foo/baseline.json ./foo-update || {
  echo "foo update changed its capability surface — blocking"; exit 1;
}
```

Or fold it into a single `vet`:

```bash
skillvet vet ./foo-update --baseline skills/foo/baseline.json
```

which prints the verdict *and* the diff, and exits 2 if the update rugged you.

## Integrity, not authenticity (honest)

The `self_hash` detects tampering with the baseline file — it is an integrity check, not a
signature. It does not prove *who* wrote the baseline. Cryptographically signed, tamper-evident
baselines are tracked on the roadmap.

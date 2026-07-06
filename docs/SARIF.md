# SARIF output

skillvet emits **SARIF 2.1.0** (Static Analysis Results Interchange Format, OASIS) — the format
GitHub code scanning, Azure DevOps, and most CI security dashboards ingest. That makes skillvet a
drop-in CI-native scanner: run it, upload the SARIF, and every dangerous capability shows up as an
annotated code-scanning alert on the exact line.

```bash
skillvet vet ./some-skill -f sarif > skillvet.sarif
```

## Structure

- **One rule per capability.** Rule id == the capability (`process_exec`, `network_egress`,
  `exfiltration_surface`, …). Every capability skillvet can emit has a rule, even when this run has
  no findings for it — so the ruleset is stable across runs.
- Each rule carries the **"why"** (`fullDescription` / `help`), a **severity** mapped to SARIF
  `error` / `warning` / `note`, a numeric `security-severity` (0-10, what GitHub sorts by), and the
  **MITRE ATLAS technique** as a `properties.tags` entry (`ATLAS/AML.Txxxx`).
- Each finding is a **result** referencing its rule at the file/line skillvet saw it.
- Run `properties` carry the skillvet verdict, score, and capability set.

Sample rule:

```json
{
  "id": "process_exec",
  "name": "ProcessExec",
  "fullDescription": { "text": "The package can execute processes or evaluate code ..." },
  "defaultConfiguration": { "level": "error" },
  "properties": {
    "tags": ["security", "supply-chain", "ATLAS/AML.T0053"],
    "security-severity": "9.0",
    "atlas": "AML.T0053",
    "skillvet-severity": "critical"
  }
}
```

Sample result:

```json
{
  "ruleId": "install_hook",
  "level": "error",
  "message": { "text": "npm install hook runs code on install" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "demos/malicious-skill/package.json" },
      "region": { "startLine": 2 }
    }
  }],
  "properties": { "atlas": "AML.T0053", "capability": "install_hook" }
}
```

## Severity mapping

| skillvet severity | SARIF level | security-severity |
|---|---|---:|
| critical | error | 9.0 |
| high | error | 7.5 |
| medium | warning | 5.0 |
| low | note | 3.0 |

## In GitHub Actions

```yaml
- run: pip install skillvet
- run: skillvet vet ./skill -f sarif > skillvet.sarif
  continue-on-error: true   # let the upload run even when the gate fails
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skillvet.sarif
    category: skillvet
```

The findings appear under **Security → Code scanning**, each on its line, tagged with its ATLAS
technique. Note that the SARIF format still gates: `vet -f sarif` exits `0`/`1`/`2` for
TRUST/REVIEW/BLOCK, exactly like the text output.

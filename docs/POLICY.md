# Policy: tune the gate for your environment

skillvet's defaults are deliberately strict. A policy file lets a team encode *its* risk tolerance
— "in our environment a skill may use the network, but never exec or read credentials" — without
weakening skillvet's ability to *see* a capability. A policy only changes how a capability **scores
and gates**; every capability is still detected and reported.

```bash
skillvet vet ./skill --policy policy.json
```

Schema: [`schema/policy.schema.json`](../schema/policy.schema.json).

## Fields

```json
{
  "name": "allow-network",
  "block_below": 40,
  "review_below": 75,
  "content_weight": 8,
  "weights": { "filesystem_write": 5 },
  "allow": ["network_egress"],
  "deny":  ["process_exec", "dynamic_fetch"]
}
```

| Field | Meaning | Default |
|---|---|---:|
| `name` | label shown in output | `default` |
| `block_below` | score `<` this → BLOCK | 40 |
| `review_below` | score `<` this → at least REVIEW | 75 |
| `content_weight` | penalty per content-signature match (total capped at 24) | 8 |
| `weights` | override the per-capability score penalty | built-in weights |
| `allow` | capabilities that contribute 0 and never force a verdict (still reported) | `[]` |
| `deny` | capabilities that force an unconditional BLOCK if present | `[]` |

A capability cannot be in both `allow` and `deny` (rejected at load).

## What allow / deny actually do

- **`allow`** — the capability is still detected and printed, but it contributes 0 to the score and
  does not trigger the "any critical → BLOCK" rule. Use it when the network (or a specific
  capability) is expected and reviewed in your environment.
- **`deny`** — presence of the capability is an **unconditional BLOCK**, regardless of score. Use it
  for capabilities that must never appear in a skill you install (e.g. `process_exec`).

## Worked example

A network-only skill scores 80 → **REVIEW** by default:

```bash
$ skillvet vet ./fetcher
  verdict: REVIEW ⚠    trust score: 80/100
```

With `allow: ["network_egress"]` it scores 100 → **TRUST**:

```bash
$ skillvet vet ./fetcher --policy allow-network.json
  verdict: TRUST  ✓    trust score: 100/100
  policy: allow-network
```

With `deny: ["network_egress"]` the same skill is **BLOCK**, score notwithstanding.

## Bundled examples

- [`demos/policies/allow-network.json`](../demos/policies/allow-network.json) — tolerate egress,
  discount filesystem writes.
- [`demos/policies/strict-no-exec.json`](../demos/policies/strict-no-exec.json) — hard-deny
  `process_exec` and `dynamic_fetch`, raise the REVIEW bar to 85.

## Honesty note

A policy is about *your* risk acceptance, not about hiding risk. `allow`-listing a capability does
not remove it from the report — it stays visible in the findings and SARIF output; it just stops
counting against the score. Static analysis still sees everything.

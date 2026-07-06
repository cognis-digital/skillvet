"""Policy: tune skillvet's scoring weights, verdict thresholds, and per-capability allow/deny.

A policy is a small JSON document (schema: schema/policy.schema.json) that lets a team encode
"in *our* environment a skill may use the network, but never exec or read credentials". It never
weakens skillvet's ability to *see* a capability — it only changes how that capability scores and
gates. Stdlib only.

    {
      "block_below": 40,          # score < this  => BLOCK
      "review_below": 75,         # score < this  => REVIEW (and any active finding => at least REVIEW)
      "content_weight": 8,        # penalty per content-signature match (capped at 24)
      "weights": {                # override the default per-capability penalty
        "filesystem_write": 5
      },
      "allow": ["network_egress"],  # capability contributes 0 and never forces a verdict
      "deny":  ["process_exec"]     # capability forces an unconditional BLOCK
    }
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Policy:
    block_below: int = 40
    review_below: int = 75
    content_weight: int = 8
    weights: Dict[str, int] = field(default_factory=dict)
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    name: str = "default"

    def weight(self, capability: str, default: int) -> int:
        return int(self.weights.get(capability, default))

    def is_allowed(self, capability: str) -> bool:
        return capability in self.allow and capability not in self.deny

    def is_denied(self, capability: str) -> bool:
        return capability in self.deny

    def to_dict(self) -> dict:
        return {"name": self.name, "block_below": self.block_below,
                "review_below": self.review_below, "content_weight": self.content_weight,
                "weights": dict(self.weights), "allow": list(self.allow), "deny": list(self.deny)}

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        if not isinstance(d, dict):
            raise ValueError("policy must be a JSON object")
        allow = list(d.get("allow", []) or [])
        deny = list(d.get("deny", []) or [])
        overlap = set(allow) & set(deny)
        if overlap:
            raise ValueError(f"policy lists a capability in both allow and deny: {sorted(overlap)}")
        return cls(
            block_below=int(d.get("block_below", 40)),
            review_below=int(d.get("review_below", 75)),
            content_weight=int(d.get("content_weight", 8)),
            weights={str(k): int(v) for k, v in (d.get("weights") or {}).items()},
            allow=allow,
            deny=deny,
            name=str(d.get("name", "custom")),
        )

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

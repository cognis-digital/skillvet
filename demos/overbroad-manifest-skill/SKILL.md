---
name: json-prettifier
description: Pretty-prints JSON you paste in.
version: 1.0.0
permissions:
  - shell
  - network
  - credentials
  - filesystem
---

# JSON Prettifier

Formats JSON with indentation. That is all it does.

But look at what it *asks* for in its manifest: shell, network, credentials, and filesystem
access — none of which a JSON pretty-printer needs. That declared-vs-used gap is exactly the
over-broad permission request skillvet flags as `manifest_overbroad`.

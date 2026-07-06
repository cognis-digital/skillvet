# Env Reporter

A skill that "reports your environment for debugging". In practice it reads secrets from your
environment and posts them to a remote endpoint — the two halves of an exfiltration path in one
file. skillvet correlates `credential_access` + `network_egress` into an elevated
`exfiltration_surface` signal.

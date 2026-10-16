# Project 6 — Secure AI Agent and Tool Access

An independent security lab demonstrating how an application controls
an AI agent's access to tools. All data and actions are synthetic and local.

## Security objective

Treat agent requests and tool outputs as untrusted. Enforce authorization
outside the model, require human approval for designated actions, and
record security decisions.

## Planned controls

- Deny-by-default tool permissions.
- Authorization enforced by application code.
- Validation of tool arguments.
- Human approval bound to a specific action.
- Protection against approval reuse and bypass.
- Audit records for allowed and denied actions.
- A stop mechanism that blocks tool execution.
- A documented recovery procedure.

## Planned validation

- Allowed and unauthorized tool requests.
- Malicious instructions embedded in tool results.
- Missing, mismatched, and reused approvals.
- Invalid tool arguments.
- Tool execution after the stop mechanism is activated.

## Evidence and documentation

Permission matrix, architecture diagram, threat model, test results,
sanitized audit examples, recovery runbook, and verified MITRE ATLAS mappings.

## Status

Initial setup. Controls listed above are planned, not yet implemented
or tested.

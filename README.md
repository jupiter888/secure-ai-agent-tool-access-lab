# Project 6 — Secure AI Agent and Tool Access

An independent security lab demonstrating application-enforced controls
over AI agent tool requests. All records and actions are synthetic and local.

## Implemented controls

- Deny-by-default role and workspace authorization.
- Strict tool argument validation.
- Application-controlled resource ownership resolution.
- Explicit local human confirmation for ticket closure.
- Expiring, single-use approvals bound to identity, tool, and exact arguments.
- Serialized tool execution and atomic approval consumption.
- A stop mechanism blocking subsequent gateway requests.
- Sanitized execution audit events with pseudonymous actor references.

## Tools

| Tool | reader | operator | Human approval |
| --- | --- | --- | --- |
| read_document | Own workspace | Own workspace | No |
| create_ticket | Denied | Own workspace | No |
| close_ticket | Denied | Own workspace | Required |

## Setup

Requires Python 3.11 or later.

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -e .
    python -m pip install -r requirements-dev.txt

## Run tests

    python -m pytest -q

Latest observed result: 119 tests passed.

Coverage includes role and workspace isolation, invalid arguments,
approval binding, expiration, replay, concurrent consumption, stop behavior,
audit sanitization, and simulated malicious tool-result instructions.

## Run the console demonstration

    python -m agent_security.demo

Type APPROVE when prompted to demonstrate approved closure and replay denial.
Any other response declines approval. Each run starts with fresh lab records.

## Documentation

- [Architecture and trust boundaries](docs/architecture.md)
- [Architecture diagram source](diagrams/architecture.mmd)
- [Human approval sequence](diagrams/approval-sequence.mmd)
- [Malicious tool-result attack flow](diagrams/tool-result-attack-flow.mmd)
- [Permission matrix](docs/permission-matrix.md)
- [Threat model and residual risks](docs/threat-model.md)
- [Stop and recovery runbook](docs/recovery-runbook.md)
- [Manual approval demonstration](evidence/manual-approval-demo.md)

## Evidence boundaries

No live model is integrated. Injection tests simulate requests made after
an agent follows malicious tool output; they validate the application
controls rather than model resistance to prompt injection.

Identity and the local approval console are trusted. Separate approver
authentication, process isolation, durable storage, and distributed
enforcement are not implemented.

Audit events cover tool execution outcomes. Approval lifecycle events
and stop activation are not separately audited.

## MITRE ATLAS

[Technique mappings and evidence limits](docs/mitre-atlas-mapping.md)
cover indirect prompt injection and agent tool invocation, using an
official MITRE reference.

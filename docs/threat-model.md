# Threat Model

## Scope

Local, single-process tool execution using synthetic documents and tickets.
Agent behavior is represented by deterministic requests, including requests
that simulate following malicious tool-result instructions.

## Assets

- Workspace isolation and document confidentiality.
- Ticket integrity.
- Human approval integrity.
- Execution accountability.
- Ability to stop subsequent tool execution.

## Attacker capabilities

The attacker can influence retrieved document content and proposed tool
names and arguments. Tests also model fabricated, mismatched, expired,
replayed, and concurrently submitted approval tokens.

The attacker cannot modify trusted Python code, identity context, resource
ownership records, approval storage, or the human console interaction.

## Threats and implemented controls

| Threat | Control | Validation |
| --- | --- | --- |
| Role spoofing through arguments | Exact argument schemas; trusted identity context | Validation and injection tests |
| Unauthorized tool use | Deny-by-default role policy | Policy and gateway tests |
| Cross-workspace access | Ownership resolved from trusted records | Policy, gateway and injection tests |
| Instructions in tool results | Application authorization independent of document content | Deterministic injection simulations |
| Fabricated human approval | Server-side token lookup; reject approval flags | Approval and gateway tests |
| Approval used for another action or actor | Bind identity, tool and exact arguments | Approval tests |
| Expired or replayed approval | Expiry checks; atomic single-use consumption | Approval and concurrency tests |
| Execution after stop | Shared gateway lock and stop flag | Gateway stop tests |
| Request contents leaking through logs | Fixed labels; exclude raw arguments and tokens | Audit tests |

## Security assumptions

Identity is supplied by trusted application code. This lab does not
authenticate users.

Only the gateway is exposed for agent tool execution. Direct store,
approval issuer, Python runtime, and console access remain trusted.

Tests demonstrate controls inside this boundary. They do not establish
process isolation or production deployment security.

## Residual risks

- No live-model prompt-injection evaluation has been performed.
- A malicious request within the caller's existing permissions may succeed.
  For example, an operator can create an unwanted ticket without approval.
- Human confirmation can be mistaken or socially engineered.
- Separate approver authentication and separation of duties are absent.
- Approval binds request arguments, not a version of the underlying record.
  Record changes between review and execution need additional handling.
- Stop does not interrupt an operation already executing.
- Stop state, approvals, records, and audit events are process-local.
- Audit storage is volatile and mutable by trusted application code.
- Resource changes and audit writes are not one atomic transaction.
- Approval issuance, refusal, and stop activation lack dedicated audit events.
- Request rates, record counts, and audit storage are not bounded.
- Resource-not-found responses may reveal identifier existence to callers.
- Compromise of the trusted host or application invalidates these controls.

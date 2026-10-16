# Architecture and Trust Boundaries

## Execution flow

1. Trusted application code supplies the requesting identity.
2. The agent proposes a tool name and arguments.
3. The gateway checks the stop state and validates arguments.
4. The policy checks the caller's role.
5. The gateway resolves resource ownership from the local store.
6. The policy checks workspace access.
7. For ticket closure, the gateway consumes a matching approval.
8. The store executes the operation.
9. The gateway records the execution outcome.

## Trust boundaries

### Agent to application

Tool names, arguments, and model-generated claims are untrusted.
The agent cannot supply its role, workspace, or an approval flag
through tool arguments.

### Tool output to agent

Document content is untrusted data. Instructions embedded in a document
cannot change the application's authorization policy.

Tests simulate an agent following malicious document instructions.
They do not evaluate a live model's susceptibility to prompt injection.

### Application to resource store

The gateway reads existing resource ownership from trusted records.
New tickets inherit the trusted caller's workspace.

Store methods do not enforce authorization themselves. The agent must
not receive direct store access or arbitrary Python execution.

### Human approval to execution

Approval tokens bind the complete Identity value, tool name, and exact
validated arguments. They expire and can be consumed only once.

ApprovalStore.issue() is a trusted internal operation.

HumanApproval.request_closure() implements a local console interaction.
It checks role, workspace, and ticket status, displays the exact request
with JSON-escaped record values, and requires the exact text APPROVE.
Refusal, EOF, and interruption deny approval. Approval does not itself
execute the action.

The console operator is trusted. Separate approver authentication and
separation of duties are not implemented. The agent must not receive
access to the approval interaction, token issuer, or console input.

Unit tests exercise token enforcement directly. Human interaction tests
use simulated input. A manual console demonstration verified denial
without approval, successful approved closure, and denial of token reuse.
See evidence/manual-approval-demo.md.

## Stop behavior

The stop operation and execution share a lock. Once stop() returns,
subsequent requests through that gateway are blocked.

The stop mechanism does not interrupt an operation already running.
It applies to one gateway instance in one Python process.

## Audit behavior

Events include a unique ID, UTC timestamp, hashed actor reference,
tool label, outcome, and fixed reason label.

Raw arguments, document content, ticket titles, approval tokens, and
raw subject identifiers are excluded.

Actor hashes are pseudonymous, not anonymous. Predictable identifiers
can be guessed and hashed for comparison.

The audit log is in memory. It is not durable, tamper-proof, or an
atomic transaction with the resource operation.

## Current deployment boundary

This is a local, single-process lab using synthetic in-memory records.
Identity authentication, process isolation, durable storage, distributed
coordination, and external service integration are not implemented.

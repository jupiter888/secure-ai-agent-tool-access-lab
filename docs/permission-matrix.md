# Tool Permission Matrix

Status: implemented and tested within the local lab's trusted application
boundary. Identity authentication and separate approver authentication
are not implemented. See architecture.md and threat-model.md for limits.

All tools operate on synthetic, local lab data.

| Tool | reader | operator | Human approval |
| --- | --- | --- | --- |
| read_document | Allow | Allow | No |
| create_ticket | Deny | Allow | No |
| close_ticket | Deny | Allow | Required |

## Enforcement rules

- Malformed identity context, unknown roles, and unknown tools are denied.
- Subject identifiers are trusted inputs; no identity registry is implemented.
- Identity and role come from trusted application context, never model output.
- Readers may access only documents in their assigned workspace.
- Operators may access documents and tickets only in their assigned workspace.
- Tool arguments must pass validation before execution.
- Human approval cannot override a role or workspace denial.
- Approval must match the requesting identity, tool, and exact arguments.
- Approval must expire and can be consumed only once.
- The agent cannot issue its own approval.
- Tool results are untrusted data and cannot grant permissions.
- An active stop mechanism blocks all tool execution.
- Allowed and denied execution requests produce sanitized audit records.

## Lab boundary

Tickets are local synthetic records. No external services, messages,
cloud resources, or real business records are modified.

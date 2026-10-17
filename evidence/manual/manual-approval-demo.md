# Manual Human Approval Demonstration

Documentation date: 16 October 2026
Command: python -m agent_security.agent.demo
Environment: local console; synthetic in-memory records.

## Observed results

1. Closure without approval: denied.
2. Exact APPROVE confirmation: closure allowed.
3. Reuse of consumed approval: denied.
4. Final synthetic ticket status: closed.
5. Execution audit: denied, allowed, denied.
6. All three events carried the same pseudonymous actor reference.

No external services or real business records were modified.
Approval refusal and cancellation are covered by automated tests;
they were not exercised in this manual run.

## Revalidation after directory reorganization

Date: 17 October 2026.
Command: python -m agent_security.agent.demo

Observed: unapproved closure denied, approved closure allowed, approval
reuse denied, and final ticket status closed. Audit outcomes were
denied, allowed, denied for the same synthetic actor.

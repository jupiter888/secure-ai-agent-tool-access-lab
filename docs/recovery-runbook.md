# Stop and Recovery Runbook

## Scope

Local, single-process lab with synthetic in-memory state.

## Stop

1. From trusted application code, call gateway.stop().
2. Wait for the call to return. An operation already running may complete
   before stop acquires the execution lock.
3. Subsequent execution requests through this gateway must raise
   ExecutionStopped.
4. Review gateway.audit.snapshot() and the synthetic resource state.

Do not expose stop controls or recovery operations as agent tools.

## Investigation

- Identify the triggering request and affected synthetic records.
- Review allowed, denied, and error events.
- Check whether an operation completed before stopping.
- Treat document content and model explanations as untrusted evidence.
- Do not assume the audit log survives process exit.

The current log does not record stop activation itself or approval
issuance and refusal.

## Recovery

There is no resume method.

1. Preserve any needed sanitized evidence before exiting.
2. Correct or remove the triggering input.
3. Exit the affected process.
4. Start a fresh process with a new LabStore, ApprovalStore, and ToolGateway.
5. Run the automated tests and console demonstration before further work.

A new LabStore resets all synthetic records. A new ApprovalStore contains
no previously issued tokens. A new ToolGateway starts with execution enabled.

Creating only a new gateway while reusing the old approval store does not
invalidate outstanding tokens.

## Verification

Run:

    python -m pytest -q
    python -m agent_security.demo

Expected demonstration:

- Closure without approval is denied.
- Exact APPROVE confirmation permits closure.
- Reusing the approval is denied.

Automated gateway tests also verify that stop blocks every registered tool.

## Limitations

This procedure resets a disposable lab. It does not restore production
data, revoke external credentials, coordinate multiple processes, or
interrupt external actions already underway.

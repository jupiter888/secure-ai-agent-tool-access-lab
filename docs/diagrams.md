# Project 6 Diagrams

## Architecture

```mermaid
flowchart TD
    Context["Trusted identity context"] --> Gateway["Tool gateway"]
    Agent["Agent: untrusted requests"] --> Gateway
    Gateway --> Checks["Argument, role and workspace checks"]
    Checks --> Approval["Approval check for closure"]
    Human["Trusted local human confirmation"] --> Tokens["Approval store"]
    Tokens --> Approval
    Approval --> Store["Synthetic resource store"]
    Store --> Output["Untrusted tool results"]
    Output --> Agent
    Gateway --> Audit["Sanitized audit log"]
    Stop["Trusted stop control"] --> Gateway
```

## Human approval sequence

```mermaid
sequenceDiagram
    actor Human as Local human
    participant App as Trusted application
    participant Approvals as Approval store
    participant Gateway as Tool gateway
    participant Store as Resource store

    App->>Gateway: Close ticket without token
    Gateway->>Gateway: Validate and authorize
    Gateway->>Approvals: Consume missing token
    Approvals-->>Gateway: Deny
    Gateway-->>App: ApprovalDenied; audit denial

    App->>Store: Resolve ticket for human review
    Store-->>App: Ownership, title and status
    App->>App: Check role, workspace and open status
    App->>Human: Display exact proposed closure
    Human-->>App: Type APPROVE
    App->>Approvals: Issue bound, expiring token
    Approvals-->>App: Token

    App->>Gateway: Close ticket with token
    Gateway->>Gateway: Check stop, arguments and role
    Gateway->>Store: Resolve current ownership
    Store-->>Gateway: Ticket
    Gateway->>Gateway: Authorize workspace
    Gateway->>Approvals: Validate and consume token
    Approvals-->>Gateway: Accepted
    Gateway->>Store: Close ticket
    Store-->>Gateway: Closed ticket
    Gateway-->>App: Success; audit allowed

    App->>Gateway: Repeat closure with same token
    Gateway->>Gateway: Validate and authorize again
    Gateway->>Approvals: Consume reused token
    Approvals-->>Gateway: Deny
    Gateway-->>App: ApprovalDenied; audit denial
```

## Malicious tool-result attack flow

```mermaid
flowchart TD
    Document["Synthetic document with malicious instructions"]
    Retrieve["Authorized retrieval from workspace A"]
    Simulate["Tests simulate agent following instructions"]

    Document --> Retrieve
    Retrieve --> Simulate

    Simulate --> Read["Request document from workspace B"]
    Simulate --> Role["Reader requests ticket closure"]
    Simulate --> Claim["Operator claims approval in text"]
    Simulate --> Flag["Supply approved=true argument"]

    Read --> Ownership["Workspace check denies access"]
    Role --> Permission["Role check denies closure"]
    Claim --> Token["Missing approval token denies closure"]
    Flag --> Schema["Argument validation rejects extra field"]

    Ownership --> Audit["Denied execution recorded"]
    Permission --> Audit
    Token --> Audit
    Schema --> Audit

    Audit --> Result["No unauthorized document returned; ticket remains open"]
```

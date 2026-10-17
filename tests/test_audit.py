from dataclasses import asdict

import pytest

from agent_security.security.approvals import ApprovalDenied, ApprovalStore
from agent_security.security.audit import AuditLog
from agent_security.security.gateway import ExecutionStopped, ToolGateway
from agent_security.security.policy import AuthorizationDenied, Identity
from agent_security.tools.store import LabStore
from agent_security.security.validation import InvalidArguments


@pytest.fixture
def context():
    audit = AuditLog()
    gateway = ToolGateway(LabStore(), ApprovalStore(), audit)
    identity = Identity("user-001", "operator", "workspace-a")
    return gateway, audit, identity


def test_success_records_one_allowed_event(context):
    gateway, audit, identity = context

    gateway.execute(identity, "read_document", {"document_id": "doc-a"})

    events = audit.snapshot()
    assert len(events) == 1
    assert events[0].tool == "read_document"
    assert events[0].outcome == "allowed"
    assert events[0].reason == "executed"


@pytest.mark.parametrize(
    "tool,arguments,exception,reason",
    [
        (
            "read_document",
            {"document_id": "doc-b"},
            AuthorizationDenied,
            "AuthorizationDenied",
        ),
        (
            "close_ticket",
            {"ticket_id": "ticket-a"},
            ApprovalDenied,
            "ApprovalDenied",
        ),
        (
            "create_ticket",
            {"title": "Example", "approved": True},
            InvalidArguments,
            "InvalidArguments",
        ),
    ],
)
def test_denials_record_one_event(
    context, tool, arguments, exception, reason
):
    gateway, audit, identity = context

    with pytest.raises(exception):
        gateway.execute(identity, tool, arguments)

    events = audit.snapshot()
    assert len(events) == 1
    assert events[0].outcome == "denied"
    assert events[0].reason == reason


def test_stopped_request_is_audited(context):
    gateway, audit, identity = context
    gateway.stop()

    with pytest.raises(ExecutionStopped):
        gateway.execute(
            identity, "read_document", {"document_id": "doc-a"}
        )

    assert audit.snapshot()[0].reason == "ExecutionStopped"


def test_title_and_token_are_excluded(context):
    gateway, audit, identity = context
    title = "SYNTHETIC-SENSITIVE-TITLE"
    token = "SYNTHETIC-SECRET-TOKEN"

    gateway.execute(
        identity, "create_ticket", {"title": title}, token
    )

    serialized = repr([asdict(event) for event in audit.snapshot()])
    assert title not in serialized
    assert token not in serialized


def test_unknown_tool_name_is_sanitized(context):
    gateway, audit, identity = context
    untrusted_name = "SYNTHETIC-SECRET\nforged-log-entry"

    with pytest.raises(InvalidArguments):
        gateway.execute(identity, untrusted_name, {})

    assert audit.snapshot()[0].tool == "unknown"
    assert untrusted_name not in repr(audit.snapshot())


def test_snapshot_does_not_change_when_log_grows():
    audit = AuditLog()
    audit.record("read_document", "allowed", "executed")
    earlier = audit.snapshot()

    audit.record("create_ticket", "allowed", "executed")

    assert len(earlier) == 1
    assert len(audit.snapshot()) == 2
    assert earlier[0].event_id != audit.snapshot()[1].event_id


def test_same_actor_has_stable_reference(context):
    gateway, audit, identity = context

    for _ in range(2):
        gateway.execute(
            identity, "read_document", {"document_id": "doc-a"}
        )

    first, second = audit.snapshot()
    assert first.actor_ref == second.actor_ref
    assert first.actor_ref != "unknown"
    assert len(first.actor_ref) == 64


def test_different_actors_have_different_references(context):
    gateway, audit, identity = context
    other = Identity("user-002", "operator", "workspace-a")

    for actor in (identity, other):
        gateway.execute(
            actor, "read_document", {"document_id": "doc-a"}
        )

    first, second = audit.snapshot()
    assert first.actor_ref != second.actor_ref


def test_raw_subject_is_not_logged(context):
    gateway, audit, _ = context
    subject = "SYNTHETIC-PRIVATE-USER-IDENTIFIER"
    identity = Identity(subject, "operator", "workspace-a")

    gateway.execute(
        identity, "read_document", {"document_id": "doc-a"}
    )

    assert subject not in repr(audit.snapshot())


def test_denied_request_retains_actor_reference(context):
    gateway, audit, identity = context

    gateway.execute(
        identity, "read_document", {"document_id": "doc-a"}
    )
    with pytest.raises(AuthorizationDenied):
        gateway.execute(
            identity, "read_document", {"document_id": "doc-b"}
        )

    allowed, denied = audit.snapshot()
    assert denied.outcome == "denied"
    assert denied.actor_ref == allowed.actor_ref


def test_missing_subject_uses_unknown_reference():
    audit = AuditLog()

    audit.record("read_document", "denied", "AuthorizationDenied")

    assert audit.snapshot()[0].actor_ref == "unknown"


def test_audit_failure_does_not_roll_back_completed_action():
    class FailingAudit(AuditLog):
        def record(self, *args, **kwargs):
            raise OSError("Synthetic audit failure")

    store = LabStore()
    approvals = ApprovalStore()
    gateway = ToolGateway(store, approvals, FailingAudit())
    identity = Identity("user-001", "operator", "workspace-a")
    arguments = {"ticket_id": "ticket-a"}
    token = approvals.issue(
        identity, "close_ticket", arguments, "workspace-a"
    )

    with pytest.raises(OSError, match="Synthetic audit failure"):
        gateway.execute(identity, "close_ticket", arguments, token)

    assert store.get_ticket("ticket-a").status == "closed"

    # The action completed and its approval remains consumed.
    with pytest.raises(ApprovalDenied):
        approvals.consume(token, identity, "close_ticket", arguments)

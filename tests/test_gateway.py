import pytest

from agent_security.approvals import ApprovalDenied, ApprovalStore
from agent_security.gateway import ExecutionStopped, ToolGateway
from agent_security.policy import AuthorizationDenied, Identity
from agent_security.store import LabStore
from agent_security.validation import InvalidArguments


@pytest.fixture
def context():
    store = LabStore()
    approvals = ApprovalStore()
    gateway = ToolGateway(store, approvals)
    operator = Identity("user-001", "operator", "workspace-a")
    return store, approvals, gateway, operator


def test_reader_can_read_own_document(context):
    _, _, gateway, _ = context
    reader = Identity("reader-001", "reader", "workspace-a")

    result = gateway.execute(
        reader, "read_document", {"document_id": "doc-a"}
    )

    assert result.document_id == "doc-a"


def test_operator_can_create_ticket_in_own_workspace(context):
    store, _, gateway, operator = context

    result = gateway.execute(
        operator, "create_ticket", {"title": "Synthetic alert"}
    )

    assert result.workspace == "workspace-a"
    assert store.get_ticket(result.ticket_id) == result


def test_reader_cannot_create_ticket(context):
    _, _, gateway, _ = context
    reader = Identity("reader-001", "reader", "workspace-a")

    with pytest.raises(AuthorizationDenied):
        gateway.execute(reader, "create_ticket", {"title": "Denied"})


def test_cross_workspace_document_is_denied(context):
    _, _, gateway, operator = context

    with pytest.raises(AuthorizationDenied):
        gateway.execute(
            operator, "read_document", {"document_id": "doc-b"}
        )


def test_close_without_approval_does_not_change_ticket(context):
    store, _, gateway, operator = context

    with pytest.raises(ApprovalDenied):
        gateway.execute(
            operator, "close_ticket", {"ticket_id": "ticket-a"}
        )

    assert store.get_ticket("ticket-a").status == "open"


def test_matching_approval_allows_closure(context):
    store, approvals, gateway, operator = context
    arguments = {"ticket_id": "ticket-a"}
    token = approvals.issue(
        operator, "close_ticket", arguments, "workspace-a"
    )

    gateway.execute(operator, "close_ticket", arguments, token)

    assert store.get_ticket("ticket-a").status == "closed"


def test_approval_for_another_ticket_is_denied(context):
    store, approvals, gateway, operator = context
    token = approvals.issue(
        operator,
        "close_ticket",
        {"ticket_id": "another-ticket"},
        "workspace-a",
    )

    with pytest.raises(ApprovalDenied):
        gateway.execute(
            operator, "close_ticket", {"ticket_id": "ticket-a"}, token
        )

    assert store.get_ticket("ticket-a").status == "open"


def test_cross_workspace_ticket_cannot_be_closed(context):
    store, _, gateway, operator = context

    with pytest.raises(AuthorizationDenied):
        gateway.execute(
            operator, "close_ticket", {"ticket_id": "ticket-b"}
        )

    assert store.get_ticket("ticket-b").status == "open"


def test_forged_approval_field_is_rejected(context):
    store, _, gateway, operator = context

    with pytest.raises(InvalidArguments):
        gateway.execute(
            operator,
            "close_ticket",
            {"ticket_id": "ticket-a", "approved": True},
        )

    assert store.get_ticket("ticket-a").status == "open"


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("read_document", {"document_id": "doc-a"}),
        ("create_ticket", {"title": "Blocked"}),
        ("close_ticket", {"ticket_id": "ticket-a"}),
    ],
)
def test_stop_blocks_every_tool(context, tool, arguments):
    store, approvals, gateway, operator = context
    token = ""
    if tool == "close_ticket":
        token = approvals.issue(
            operator, tool, arguments, "workspace-a"
        )

    gateway.stop()

    with pytest.raises(ExecutionStopped):
        gateway.execute(operator, tool, arguments, token)

    assert store.get_ticket("ticket-a").status == "open"


def test_reused_approval_is_denied_at_gateway(context):
    store, approvals, gateway, operator = context
    arguments = {"ticket_id": "ticket-a"}
    token = approvals.issue(
        operator, "close_ticket", arguments, "workspace-a"
    )

    gateway.execute(operator, "close_ticket", arguments, token)

    with pytest.raises(ApprovalDenied):
        gateway.execute(operator, "close_ticket", arguments, token)

    assert store.get_ticket("ticket-a").status == "closed"
    events = gateway.audit.snapshot()
    assert [event.outcome for event in events] == ["allowed", "denied"]


def test_concurrent_closures_execute_only_once(context):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    store, approvals, gateway, operator = context
    arguments = {"ticket_id": "ticket-a"}
    token = approvals.issue(
        operator, "close_ticket", arguments, "workspace-a"
    )
    barrier = Barrier(2)

    def attempt():
        barrier.wait(timeout=5)
        try:
            gateway.execute(operator, "close_ticket", arguments, token)
            return "executed"
        except ApprovalDenied:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(attempt) for _ in range(2)]
        results = [future.result(timeout=10) for future in futures]

    assert sorted(results) == ["denied", "executed"]
    assert store.get_ticket("ticket-a").status == "closed"
    events = gateway.audit.snapshot()
    assert sum(event.outcome == "allowed" for event in events) == 1
    assert sum(event.outcome == "denied" for event in events) == 1

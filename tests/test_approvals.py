import pytest

from agent_security.security.approvals import ApprovalDenied, ApprovalStore
from agent_security.security.policy import AuthorizationDenied, Identity


@pytest.fixture
def context():
    now = [100.0]
    store = ApprovalStore(clock=lambda: now[0])
    identity = Identity("user-001", "operator", "workspace-a")
    arguments = {"ticket_id": "ticket-a"}
    return store, identity, arguments, now


def issue(store, identity, arguments, ttl_seconds=60):
    return store.issue(
        identity,
        "close_ticket",
        arguments,
        "workspace-a",
        ttl_seconds=ttl_seconds,
    )


def test_matching_approval_can_be_consumed(context):
    store, identity, arguments, _ = context
    token = issue(store, identity, arguments)

    store.consume(token, identity, "close_ticket", arguments)


def test_approval_cannot_be_reused(context):
    store, identity, arguments, _ = context
    token = issue(store, identity, arguments)
    store.consume(token, identity, "close_ticket", arguments)

    with pytest.raises(ApprovalDenied):
        store.consume(token, identity, "close_ticket", arguments)


@pytest.mark.parametrize("elapsed", [60, 61])
def test_approval_expires_at_deadline(context, elapsed):
    store, identity, arguments, now = context
    token = issue(store, identity, arguments)
    now[0] += elapsed

    with pytest.raises(ApprovalDenied):
        store.consume(token, identity, "close_ticket", arguments)


def test_approval_valid_before_deadline(context):
    store, identity, arguments, now = context
    token = issue(store, identity, arguments)
    now[0] += 59

    store.consume(token, identity, "close_ticket", arguments)


@pytest.mark.parametrize(
    "other_identity",
    [
        Identity("user-002", "operator", "workspace-a"),
        Identity("user-001", "reader", "workspace-a"),
        Identity("user-001", "operator", "workspace-b"),
    ],
)
def test_approval_is_bound_to_identity(context, other_identity):
    store, identity, arguments, _ = context
    token = issue(store, identity, arguments)

    with pytest.raises(ApprovalDenied):
        store.consume(token, other_identity, "close_ticket", arguments)


def test_approval_is_bound_to_arguments(context):
    store, identity, arguments, _ = context
    token = issue(store, identity, arguments)

    with pytest.raises(ApprovalDenied):
        store.consume(
            token, identity, "close_ticket", {"ticket_id": "ticket-b"}
        )


def test_approval_is_bound_to_tool(context):
    store, identity, arguments, _ = context
    token = issue(store, identity, arguments)

    with pytest.raises(ApprovalDenied):
        store.consume(
            token, identity, "read_document", {"document_id": "doc-a"}
        )


@pytest.mark.parametrize("token", ["", "fabricated-token", None])
def test_missing_or_fabricated_approval_is_denied(context, token):
    store, identity, arguments, _ = context

    with pytest.raises(ApprovalDenied):
        store.consume(token, identity, "close_ticket", arguments)


def test_approval_cannot_override_role_denial(context):
    store, _, arguments, _ = context
    reader = Identity("user-001", "reader", "workspace-a")

    with pytest.raises(AuthorizationDenied):
        issue(store, reader, arguments)


def test_approval_cannot_override_workspace_denial(context):
    store, identity, arguments, _ = context

    with pytest.raises(AuthorizationDenied):
        store.issue(identity, "close_ticket", arguments, "workspace-b")


@pytest.mark.parametrize("ttl", [0, -1, 301, True, 1.5])
def test_invalid_approval_lifetime_is_rejected(context, ttl):
    store, identity, arguments, _ = context

    with pytest.raises(ApprovalDenied):
        issue(store, identity, arguments, ttl_seconds=ttl)


def test_nonapproval_tool_cannot_receive_approval(context):
    store, identity, _, _ = context

    with pytest.raises(ApprovalDenied):
        store.issue(
            identity,
            "read_document",
            {"document_id": "doc-a"},
            "workspace-a",
        )


def test_concurrent_requests_cannot_reuse_approval(context):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    store, identity, arguments, _ = context
    token = issue(store, identity, arguments)
    barrier = Barrier(2)

    def attempt():
        barrier.wait(timeout=5)
        try:
            store.consume(token, identity, "close_ticket", arguments)
            return "consumed"
        except ApprovalDenied:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(attempt) for _ in range(2)]
        results = [future.result(timeout=10) for future in futures]

    assert sorted(results) == ["consumed", "denied"]

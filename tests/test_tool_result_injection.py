import pytest

from agent_security.approvals import ApprovalDenied, ApprovalStore
from agent_security.fixtures import MALICIOUS_DOCUMENT
from agent_security.gateway import ToolGateway
from agent_security.policy import AuthorizationDenied, Identity
from agent_security.store import LabStore
from agent_security.validation import InvalidArguments


class InjectedLabStore(LabStore):
    def get_document(self, document_id):
        if document_id == MALICIOUS_DOCUMENT.document_id:
            return MALICIOUS_DOCUMENT
        return super().get_document(document_id)


@pytest.fixture
def context():
    store = InjectedLabStore()
    gateway = ToolGateway(store, ApprovalStore())
    return store, gateway


def retrieve_injection(gateway, identity):
    result = gateway.execute(
        identity, "read_document", {"document_id": "doc-injected"}
    )
    assert result == MALICIOUS_DOCUMENT
    return result


def test_tool_output_cannot_grant_cross_workspace_access(context):
    _, gateway = context
    identity = Identity("user-001", "operator", "workspace-a")
    retrieve_injection(gateway, identity)

    with pytest.raises(AuthorizationDenied):
        gateway.execute(
            identity, "read_document", {"document_id": "doc-b"}
        )

    assert gateway.audit.snapshot()[-1].outcome == "denied"


def test_claimed_operator_role_does_not_elevate_reader(context):
    store, gateway = context
    identity = Identity("user-001", "reader", "workspace-a")
    retrieve_injection(gateway, identity)

    with pytest.raises(AuthorizationDenied):
        gateway.execute(
            identity, "close_ticket", {"ticket_id": "ticket-a"}
        )

    assert store.get_ticket("ticket-a").status == "open"


def test_claimed_human_approval_is_insufficient(context):
    store, gateway = context
    identity = Identity("user-001", "operator", "workspace-a")
    retrieve_injection(gateway, identity)

    with pytest.raises(ApprovalDenied):
        gateway.execute(
            identity, "close_ticket", {"ticket_id": "ticket-a"}
        )

    assert store.get_ticket("ticket-a").status == "open"


def test_injected_approval_flag_is_rejected_and_audited(context):
    store, gateway = context
    identity = Identity("user-001", "operator", "workspace-a")
    retrieve_injection(gateway, identity)

    with pytest.raises(InvalidArguments):
        gateway.execute(
            identity,
            "close_ticket",
            {"ticket_id": "ticket-a", "approved": True},
        )

    assert store.get_ticket("ticket-a").status == "open"
    events = gateway.audit.snapshot()
    assert len(events) == 2
    assert events[-1].outcome == "denied"
    assert events[-1].reason == "InvalidArguments"

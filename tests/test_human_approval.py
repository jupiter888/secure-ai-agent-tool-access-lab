import json

import pytest

from agent_security.approvals import ApprovalDenied, ApprovalStore
from agent_security.gateway import ToolGateway
from agent_security.human_approval import HumanApproval
from agent_security.policy import AuthorizationDenied, Identity
from agent_security.store import LabStore


@pytest.fixture
def context():
    store = LabStore()
    approvals = ApprovalStore()
    identity = Identity("user-001", "operator", "workspace-a")
    return store, approvals, identity


def test_human_approval_allows_exact_closure(context):
    store, approvals, identity = context
    output = []
    human = HumanApproval(
        store, approvals,
        read_input=lambda _: "APPROVE",
        write_output=output.append,
    )

    token = human.request_closure(identity, "ticket-a")

    # Approval alone does not execute the action.
    assert store.get_ticket("ticket-a").status == "open"
    summary = json.loads(output[1])
    assert summary["requesting_subject"] == identity.subject
    assert summary["workspace"] == "workspace-a"
    assert summary["tool"] == "close_ticket"
    assert summary["arguments"] == {"ticket_id": "ticket-a"}

    gateway = ToolGateway(store, approvals)
    gateway.execute(
        identity, "close_ticket", {"ticket_id": "ticket-a"}, token
    )
    assert store.get_ticket("ticket-a").status == "closed"


@pytest.mark.parametrize("answer", ["", "approve", "yes", "APPROVE "])
def test_nonexact_confirmation_is_declined(context, answer):
    store, approvals, identity = context
    human = HumanApproval(
        store, approvals,
        read_input=lambda _: answer,
        write_output=lambda _: None,
    )

    with pytest.raises(ApprovalDenied, match="declined"):
        human.request_closure(identity, "ticket-a")

    assert store.get_ticket("ticket-a").status == "open"


@pytest.mark.parametrize("exception", [EOFError, KeyboardInterrupt])
def test_cancelled_interaction_is_denied(context, exception):
    store, approvals, identity = context

    def cancel(_):
        raise exception()

    human = HumanApproval(
        store, approvals,
        read_input=cancel,
        write_output=lambda _: None,
    )

    with pytest.raises(ApprovalDenied, match="cancelled"):
        human.request_closure(identity, "ticket-a")

    assert store.get_ticket("ticket-a").status == "open"


@pytest.mark.parametrize(
    "identity,ticket_id",
    [
        (Identity("reader-001", "reader", "workspace-a"), "ticket-a"),
        (Identity("user-001", "operator", "workspace-a"), "ticket-b"),
    ],
)
def test_unauthorized_action_never_prompts(context, identity, ticket_id):
    store, approvals, _ = context
    prompts = []
    human = HumanApproval(
        store, approvals,
        read_input=lambda prompt: prompts.append(prompt) or "APPROVE",
        write_output=lambda _: None,
    )

    with pytest.raises(AuthorizationDenied):
        human.request_closure(identity, ticket_id)

    assert prompts == []


def test_closed_ticket_never_prompts(context):
    store, approvals, identity = context
    store.close_ticket("ticket-a")
    prompts = []
    human = HumanApproval(
        store, approvals,
        read_input=lambda prompt: prompts.append(prompt) or "APPROVE",
        write_output=lambda _: None,
    )

    with pytest.raises(ApprovalDenied, match="not open"):
        human.request_closure(identity, "ticket-a")

    assert prompts == []


@pytest.mark.parametrize("identity", [None, {}, "operator"])
def test_malformed_identity_never_prompts(context, identity):
    store, approvals, _ = context
    prompts = []
    human = HumanApproval(
        store,
        approvals,
        read_input=lambda prompt: prompts.append(prompt) or "APPROVE",
        write_output=lambda _: None,
    )

    with pytest.raises(AuthorizationDenied):
        human.request_closure(identity, "ticket-a")

    assert prompts == []
    assert store.get_ticket("ticket-a").status == "open"

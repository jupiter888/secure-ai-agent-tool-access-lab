from dataclasses import FrozenInstanceError

import pytest

from agent_security.store import LabStore, ResourceNotFound


@pytest.mark.parametrize(
    "document_id,workspace",
    [("doc-a", "workspace-a"), ("doc-b", "workspace-b")],
)
def test_document_ownership(document_id, workspace):
    document = LabStore().get_document(document_id)

    assert document.document_id == document_id
    assert document.workspace == workspace


@pytest.mark.parametrize(
    "ticket_id,workspace",
    [("ticket-a", "workspace-a"), ("ticket-b", "workspace-b")],
)
def test_ticket_ownership(ticket_id, workspace):
    ticket = LabStore().get_ticket(ticket_id)

    assert ticket.ticket_id == ticket_id
    assert ticket.workspace == workspace
    assert ticket.status == "open"


def test_missing_document():
    with pytest.raises(ResourceNotFound):
        LabStore().get_document("missing")


def test_missing_ticket():
    with pytest.raises(ResourceNotFound):
        LabStore().get_ticket("missing")


def test_document_ownership_cannot_be_reassigned():
    document = LabStore().get_document("doc-a")

    with pytest.raises(FrozenInstanceError):
        document.workspace = "workspace-b"


def test_ticket_ownership_cannot_be_reassigned():
    ticket = LabStore().get_ticket("ticket-a")

    with pytest.raises(FrozenInstanceError):
        ticket.workspace = "workspace-b"

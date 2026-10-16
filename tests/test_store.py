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


def test_create_ticket_preserves_workspace_and_title():
    store = LabStore()

    ticket = store.create_ticket("workspace-a", "Investigate synthetic alert")

    assert ticket.workspace == "workspace-a"
    assert ticket.title == "Investigate synthetic alert"
    assert ticket.status == "open"
    assert store.get_ticket(ticket.ticket_id) == ticket


def test_created_tickets_have_distinct_ids():
    store = LabStore()

    first = store.create_ticket("workspace-a", "First ticket")
    second = store.create_ticket("workspace-a", "Second ticket")

    assert first.ticket_id != second.ticket_id
    assert store.get_ticket(first.ticket_id) == first
    assert store.get_ticket(second.ticket_id) == second


def test_close_ticket_preserves_ownership_and_title():
    store = LabStore()
    original = store.get_ticket("ticket-a")

    closed = store.close_ticket("ticket-a")

    assert closed.status == "closed"
    assert closed.ticket_id == original.ticket_id
    assert closed.workspace == original.workspace
    assert closed.title == original.title
    assert store.get_ticket("ticket-a") == closed
    assert store.get_ticket("ticket-b").status == "open"


def test_closed_ticket_cannot_be_closed_again():
    store = LabStore()
    store.close_ticket("ticket-a")

    with pytest.raises(ValueError, match="Ticket is not open"):
        store.close_ticket("ticket-a")


def test_closing_missing_ticket_is_rejected():
    with pytest.raises(ResourceNotFound):
        LabStore().close_ticket("missing")


def test_store_instances_do_not_share_changes():
    first = LabStore()
    second = LabStore()

    first.close_ticket("ticket-a")

    assert second.get_ticket("ticket-a").status == "open"

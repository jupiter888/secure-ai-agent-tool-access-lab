from dataclasses import dataclass


@dataclass(frozen=True)
class Document:
    document_id: str
    workspace: str
    content: str


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    workspace: str
    title: str
    status: str = "open"


class ResourceNotFound(Exception):
    pass


class LabStore:
    """In-memory synthetic records; resets for each new instance."""

    def __init__(self):
        self._documents = {
            "doc-a": Document(
                "doc-a",
                "workspace-a",
                "Synthetic workspace A operations guide.",
            ),
            "doc-b": Document(
                "doc-b",
                "workspace-b",
                "Synthetic workspace B internal guide.",
            ),
        }
        self._tickets = {
            "ticket-a": Ticket(
                "ticket-a", "workspace-a", "Review synthetic alert"
            ),
            "ticket-b": Ticket(
                "ticket-b", "workspace-b", "Review synthetic incident"
            ),
        }

    def get_document(self, document_id: str) -> Document:
        try:
            return self._documents[document_id]
        except KeyError:
            raise ResourceNotFound("Document not found") from None

    def get_ticket(self, ticket_id: str) -> Ticket:
        try:
            return self._tickets[ticket_id]
        except KeyError:
            raise ResourceNotFound("Ticket not found") from None

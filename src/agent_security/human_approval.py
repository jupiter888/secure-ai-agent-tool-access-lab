import json
from collections.abc import Callable

from agent_security.approvals import ApprovalDenied, ApprovalStore
from agent_security.policy import Identity, authorize
from agent_security.store import LabStore
from agent_security.validation import validate_arguments


class HumanApproval:
    """Trusted local console interaction; never register as an agent tool."""

    def __init__(
        self,
        store: LabStore,
        approvals: ApprovalStore,
        read_input: Callable[[str], str] = input,
        write_output: Callable[[str], None] = print,
    ):
        self._store = store
        self._approvals = approvals
        self._read_input = read_input
        self._write_output = write_output

    def request_closure(self, identity: Identity, ticket_id: str) -> str:
        arguments = validate_arguments(
            "close_ticket", {"ticket_id": ticket_id}
        )
        authorize(identity, "close_ticket", identity.workspace)
        ticket = self._store.get_ticket(arguments["ticket_id"])
        authorize(identity, "close_ticket", ticket.workspace)

        if ticket.status != "open":
            raise ApprovalDenied("Ticket is not open")

        # JSON escaping prevents record text from injecting terminal controls.
        summary = json.dumps(
            {
                "requesting_subject": identity.subject,
                "role": identity.role,
                "workspace": ticket.workspace,
                "tool": "close_ticket",
                "arguments": arguments,
                "ticket_title": ticket.title,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
        self._write_output("Review the proposed action:")
        self._write_output(summary)

        try:
            answer = self._read_input(
                "Type APPROVE to authorize this exact closure: "
            )
        except (EOFError, KeyboardInterrupt):
            raise ApprovalDenied("Human approval cancelled") from None

        if answer != "APPROVE":
            raise ApprovalDenied("Human approval declined")

        return self._approvals.issue(
            identity,
            "close_ticket",
            arguments,
            ticket.workspace,
        )

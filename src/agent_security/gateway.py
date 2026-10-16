from threading import RLock

from agent_security.approvals import ApprovalStore
from agent_security.policy import Identity, authorize
from agent_security.store import LabStore
from agent_security.validation import validate_arguments


class ExecutionStopped(Exception):
    pass


class ToolGateway:
    """Agent-facing execution boundary; dependencies remain trusted."""

    def __init__(self, store: LabStore, approvals: ApprovalStore):
        self._store = store
        self._approvals = approvals
        self._stopped = False
        self._lock = RLock()

    def stop(self) -> None:
        """Trusted application operation; blocks subsequent executions."""
        with self._lock:
            self._stopped = True

    def execute(
        self,
        identity: Identity,
        tool: str,
        arguments: dict,
        approval_token: str = "",
    ):
        with self._lock:
            if self._stopped:
                raise ExecutionStopped("Tool execution is stopped")

            validated = validate_arguments(tool, arguments)

            # Check role before looking up a resource.
            authorize(identity, tool, identity.workspace)

            if tool == "read_document":
                resource = self._store.get_document(
                    validated["document_id"]
                )
                workspace = resource.workspace
            elif tool == "close_ticket":
                resource = self._store.get_ticket(
                    validated["ticket_id"]
                )
                workspace = resource.workspace
            else:
                # Ticket creation uses the trusted identity's workspace.
                workspace = identity.workspace

            policy = authorize(identity, tool, workspace)

            if policy.requires_approval:
                self._approvals.consume(
                    approval_token, identity, tool, validated
                )

            if tool == "read_document":
                return resource

            if tool == "create_ticket":
                return self._store.create_ticket(
                    workspace, validated["title"]
                )

            return self._store.close_ticket(validated["ticket_id"])

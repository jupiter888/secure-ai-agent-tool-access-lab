import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Callable

from agent_security.policy import Identity, authorize
from agent_security.validation import validate_arguments


class ApprovalDenied(Exception):
    pass


@dataclass(frozen=True)
class Approval:
    identity: Identity
    tool: str
    arguments: tuple[tuple[str, str], ...]
    expires_at: float


class ApprovalStore:
    """Trusted application component; never expose issue() as an agent tool."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._approvals: dict[str, Approval] = {}
        self._lock = Lock()

    def issue(
        self,
        identity: Identity,
        tool: str,
        arguments: dict,
        resource_workspace: str,
        ttl_seconds: int = 60,
    ) -> str:
        """Call only after a trusted human approval interaction."""

        validated = validate_arguments(tool, arguments)
        policy = authorize(identity, tool, resource_workspace)

        if not policy.requires_approval:
            raise ApprovalDenied("This tool does not require approval")

        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise ApprovalDenied("Approval lifetime must be 1–300 seconds")

        approval = Approval(
            identity=identity,
            tool=tool,
            arguments=tuple(sorted(validated.items())),
            expires_at=self._clock() + ttl_seconds,
        )

        with self._lock:
            token = secrets.token_urlsafe(32)
            self._approvals[token] = approval

        return token

    def consume(
        self,
        token: str,
        identity: Identity,
        tool: str,
        arguments: dict,
    ) -> None:
        """Atomically check and consume an approval before execution."""

        validated = validate_arguments(tool, arguments)

        if not isinstance(token, str) or not token:
            raise ApprovalDenied("Approval required")

        with self._lock:
            approval = self._approvals.get(token)

            if approval is None:
                raise ApprovalDenied("Unknown or already consumed approval")

            if self._clock() >= approval.expires_at:
                del self._approvals[token]
                raise ApprovalDenied("Approval expired")

            if (
                approval.identity != identity
                or approval.tool != tool
                or approval.arguments != tuple(sorted(validated.items()))
            ):
                raise ApprovalDenied("Approval does not match this action")

            del self._approvals[token]

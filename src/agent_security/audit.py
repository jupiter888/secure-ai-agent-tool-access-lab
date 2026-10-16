from dataclasses import dataclass
from hashlib import sha256
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: str
    actor_ref: str
    tool: str
    outcome: str
    reason: str


class AuditLog:
    """In-memory lab audit log; not durable or tamper-proof storage."""

    def __init__(self):
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    def record(
        self, tool: str, outcome: str, reason: str,
        subject: str = "",
    ) -> None:
        safe_tool = (
            tool
            if isinstance(tool, str)
            and tool in {
                "read_document", "create_ticket", "close_ticket"
            }
            else "unknown"
        )

        if outcome not in {"allowed", "denied", "error"}:
            raise ValueError("Invalid audit outcome")

        allowed_reasons = {
            "executed",
            "ExecutionStopped",
            "InvalidArguments",
            "AuthorizationDenied",
            "ApprovalDenied",
            "ResourceNotFound",
            "execution_error",
        }
        if reason not in allowed_reasons:
            raise ValueError("Invalid audit reason")

        actor_ref = (
            sha256(subject.encode("utf-8")).hexdigest()
            if isinstance(subject, str) and subject.strip()
            else "unknown"
        )

        event = AuditEvent(
            event_id=uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor_ref=actor_ref,
            tool=safe_tool,
            outcome=outcome,
            reason=reason,
        )

        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

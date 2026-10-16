from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class Identity:
    """Supplied by trusted application code, never by the agent."""

    subject: str
    role: str
    workspace: str


@dataclass(frozen=True)
class ToolPolicy:
    roles: frozenset[str]
    requires_approval: bool = False


TOOL_POLICIES = MappingProxyType({
    "read_document": ToolPolicy(frozenset({"reader", "operator"})),
    "create_ticket": ToolPolicy(frozenset({"operator"})),
    "close_ticket": ToolPolicy(
        frozenset({"operator"}),
        requires_approval=True,
    ),
})


class AuthorizationDenied(Exception):
    pass


def authorize(
    identity: Identity,
    tool: str,
    resource_workspace: str,
) -> ToolPolicy:
    """Check role and workspace; approval is enforced separately."""

    if not isinstance(identity, Identity):
        raise AuthorizationDenied("Invalid identity context")

    if not all(
        isinstance(value, str) and value.strip()
        for value in (
            identity.subject,
            identity.role,
            identity.workspace,
            resource_workspace,
        )
    ):
        raise AuthorizationDenied("Invalid identity or workspace")

    policy = TOOL_POLICIES.get(tool)
    if policy is None:
        raise AuthorizationDenied("Unknown tool")

    if identity.role not in policy.roles:
        raise AuthorizationDenied("Role does not permit this tool")

    if identity.workspace != resource_workspace:
        raise AuthorizationDenied("Workspace access denied")

    return policy

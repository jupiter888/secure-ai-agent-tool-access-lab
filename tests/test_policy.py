import pytest

from agent_security.security.policy import (
    AuthorizationDenied,
    Identity,
    authorize,
)


@pytest.mark.parametrize(
    "role,tool,approval_required",
    [
        ("reader", "read_document", False),
        ("operator", "read_document", False),
        ("operator", "create_ticket", False),
        ("operator", "close_ticket", True),
    ],
)
def test_permitted_actions(role, tool, approval_required):
    identity = Identity("user-001", role, "workspace-a")

    policy = authorize(identity, tool, "workspace-a")

    assert policy.requires_approval is approval_required


@pytest.mark.parametrize("tool", ["create_ticket", "close_ticket"])
def test_reader_cannot_modify_tickets(tool):
    identity = Identity("user-001", "reader", "workspace-a")

    with pytest.raises(AuthorizationDenied):
        authorize(identity, tool, "workspace-a")


@pytest.mark.parametrize("role", ["admin", "unknown", ""])
def test_unrecognized_roles_are_denied(role):
    identity = Identity("user-001", role, "workspace-a")

    with pytest.raises(AuthorizationDenied):
        authorize(identity, "read_document", "workspace-a")


def test_unknown_tool_is_denied():
    identity = Identity("user-001", "operator", "workspace-a")

    with pytest.raises(AuthorizationDenied):
        authorize(identity, "delete_workspace", "workspace-a")


@pytest.mark.parametrize(
    "tool", ["read_document", "create_ticket", "close_ticket"]
)
def test_cross_workspace_access_is_denied(tool):
    identity = Identity("user-001", "operator", "workspace-a")

    with pytest.raises(AuthorizationDenied):
        authorize(identity, tool, "workspace-b")


@pytest.mark.parametrize(
    "subject,workspace,resource_workspace",
    [
        ("", "workspace-a", "workspace-a"),
        ("   ", "workspace-a", "workspace-a"),
        ("user-001", "", "workspace-a"),
        ("user-001", "workspace-a", ""),
    ],
)
def test_incomplete_context_is_denied(
    subject, workspace, resource_workspace
):
    identity = Identity(subject, "operator", workspace)

    with pytest.raises(AuthorizationDenied):
        authorize(identity, "read_document", resource_workspace)

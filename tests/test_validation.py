import pytest

from agent_security.security.validation import InvalidArguments, validate_arguments


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("read_document", {"document_id": "doc-a"}),
        ("create_ticket", {"title": "Review synthetic alert"}),
        ("close_ticket", {"ticket_id": "ticket-a"}),
    ],
)
def test_valid_arguments_return_independent_copy(tool, arguments):
    result = validate_arguments(tool, arguments)

    assert result == arguments
    assert result is not arguments


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("unknown_tool", {}),
        ("read_document", None),
        ("read_document", []),
        ("read_document", {}),
        ("read_document", {"document_id": 123}),
        ("read_document", {"document_id": ""}),
        ("read_document", {"document_id": "   "}),
        ("read_document", {"document_id": "../doc-a"}),
        ("read_document", {"document_id": "doc a"}),
        ("read_document", {"document_id": "dóc-a"}),
        ("read_document", {"document_id": "a" * 65}),
        ("create_ticket", {"title": ""}),
        ("create_ticket", {"title": " "}),
        ("create_ticket", {"title": "a" * 201}),
        ("close_ticket", {"document_id": "doc-a"}),
    ],
)
def test_invalid_arguments_are_rejected(tool, arguments):
    with pytest.raises(InvalidArguments):
        validate_arguments(tool, arguments)


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "operator"),
        ("subject", "another-user"),
        ("workspace", "workspace-b"),
        ("approved", True),
        ("requires_approval", False),
    ],
)
def test_agent_cannot_supply_trusted_context(field, value):
    arguments = {"ticket_id": "ticket-a", field: value}

    with pytest.raises(InvalidArguments):
        validate_arguments("close_ticket", arguments)


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("read_document", {"document_id": "a" * 64}),
        ("create_ticket", {"title": "a" * 200}),
    ],
)
def test_length_limits_are_inclusive(tool, arguments):
    assert validate_arguments(tool, arguments) == arguments

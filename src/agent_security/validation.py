class InvalidArguments(Exception):
    pass


SCHEMAS = {
    "read_document": {"document_id"},
    "create_ticket": {"title"},
    "close_ticket": {"ticket_id"},
}


def validate_arguments(tool: str, arguments: dict) -> dict[str, str]:
    """Return a validated copy; reject unknown tools and extra fields."""

    if not isinstance(tool, str) or tool not in SCHEMAS:
        raise InvalidArguments("Unknown tool")

    if not isinstance(arguments, dict):
        raise InvalidArguments("Arguments must be a dictionary")

    if set(arguments) != SCHEMAS[tool]:
        raise InvalidArguments("Missing or unexpected argument fields")

    validated = {}

    for name, value in arguments.items():
        if not isinstance(value, str) or not value.strip():
            raise InvalidArguments("Arguments must be nonempty strings")

        limit = 200 if name == "title" else 64
        if len(value) > limit:
            raise InvalidArguments("Argument exceeds length limit")

        if name.endswith("_id"):
            if not value.isascii() or not all(
                character.isalnum() or character in "-_"
                for character in value
            ):
                raise InvalidArguments("Invalid resource identifier")

        validated[name] = value

    return validated

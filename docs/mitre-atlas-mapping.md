# MITRE ATLAS Mapping

Documentation date: 16 October 2026.

## Mappings

| Technique | Lab scenario | Evidence | Limit |
| --- | --- | --- | --- |
| AML.T0051.001 — LLM Prompt Injection: Indirect | Malicious instructions embedded in a retrieved synthetic document | fixtures.py; test_tool_result_injection.py | Agent compliance is simulated; no live model is evaluated |
| AML.T0053 — AI Agent Tool Invocation | Simulated attacker-directed requests to read another workspace or close a ticket | test_tool_result_injection.py; test_gateway.py | Tests validate application enforcement, not successful compromise of a real agent |

## Interpretation

The malicious document represents the indirect injection entry point.
The subsequent tool requests represent attempted attacker-directed actions.

Role checks, workspace isolation, strict arguments, and approval enforcement
block the tested unauthorized requests. These results do not establish
complete prevention of either technique.

Approval replay and concurrency tests validate supporting application
controls. They are not assigned separate ATLAS techniques here.

## Official reference

MITRE ATLAS OpenClaw Investigation:
https://www.mitre.org/sites/default/files/2026-02/PR-26-00176-1-MITRE-ATLAS-OpenClaw-Investigation.pdf

The report identifies both technique IDs and names above.
This is a scenario mapping, not an ATLAS certification or coverage claim.

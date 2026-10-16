from dataclasses import asdict
import json

from agent_security.approvals import ApprovalDenied, ApprovalStore
from agent_security.gateway import ToolGateway
from agent_security.human_approval import HumanApproval
from agent_security.policy import Identity
from agent_security.store import LabStore


def main():
    store = LabStore()
    approvals = ApprovalStore()
    gateway = ToolGateway(store, approvals)
    identity = Identity("demo-operator", "operator", "workspace-a")
    arguments = {"ticket_id": "ticket-a"}

    print("Local synthetic lab: no external actions.")
    print("\n1. Attempt closure without approval:")
    try:
        gateway.execute(identity, "close_ticket", arguments)
    except ApprovalDenied:
        print("DENIED: human approval required.")

    print("\n2. Request human approval:")
    human = HumanApproval(store, approvals)
    try:
        token = human.request_closure(identity, "ticket-a")
    except ApprovalDenied:
        print("Approval declined or cancelled. Ticket remains open.")
    else:
        gateway.execute(identity, "close_ticket", arguments, token)
        print("ALLOWED: synthetic ticket closed.")

        print("\n3. Attempt to reuse approval:")
        try:
            gateway.execute(identity, "close_ticket", arguments, token)
        except ApprovalDenied:
            print("DENIED: approval already consumed.")

    print("\nFinal ticket status:", store.get_ticket("ticket-a").status)
    print("\nSanitized execution audit:")
    for event in gateway.audit.snapshot():
        print(json.dumps(asdict(event), sort_keys=True))


if __name__ == "__main__":
    main()

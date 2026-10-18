"""Estimate first; run a synthetic check only after explicit cost confirmation."""

import os

from guardfulai import GuardfulAI, GuardfulAIError


def main():
    content = "Synthetic support response"
    try:
        with GuardfulAI(
            os.environ["GUARDFULAI_API_KEY"], base_url=os.environ["GUARDFULAI_BASE_URL"]
        ) as client:
            policy = os.environ["GUARDFULAI_POLICY_ID"]
            version = int(os.environ["GUARDFULAI_POLICY_VERSION"])
            event = os.environ["GUARDFULAI_EVENT_ID"]
            quote = client.estimate(policy, content, version=version)
            if (
                input(f"Estimated credits: {quote.credits}. Type CHECK {quote.credits}: ")
                != f"CHECK {quote.credits}"
            ):
                print("Stopped without running")
                return
            result = client.check(policy, content, version=version, idempotency_key=event)
            if result.status == "completed" and result.decision == "allow":
                print("Allow: continue the protected operation")
            else:
                print("Stop: block or route to review")
    except GuardfulAIError:
        print("No usable result: stop; preserve the event ID for an exact retry")


if __name__ == "__main__":
    main()

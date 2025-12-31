from src.rules.rules import check_budget, check_velocity, calculate_risk
from src.agent.decision import make_decision

def agent_decision(amount, tx_count_last_hour, agent_state):
    flags = []

    # 1. Budget check
    ok, flag = check_budget(amount, agent_state)
    if not ok:
        flags.append(flag)
        risk = calculate_risk(flags)

        return make_decision(
            result="reject",
            reason="Payment exceeds agent daily budget",
            risk_score=risk,
            flags=flags,
            action=None
        )

    # 2. Velocity check
    ok, flag = check_velocity(tx_count_last_hour)
    if not ok:
        flags.append(flag)
        risk = calculate_risk(flags)

        return make_decision(
            result="review",
            reason="Suspicious transaction velocity detected",
            risk_score=risk,
            flags=flags,
            action={
                "type": "manual_review",
                "currency": "USDC",
                "network": "Arc"
            }
        )

    # 3. Approve payment
    risk = calculate_risk(flags)

    return make_decision(
        result="approve",
        reason="All policy checks passed",
        risk_score=risk,
        flags=flags,
        action={
            "type": "execute_payment",
            "currency": "USDC",
            "network": "Arc"
        }
    )

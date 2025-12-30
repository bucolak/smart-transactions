def make_decision(result, reason, risk_score, flags=None, action=None):
    return{
        "decision": result,
        "reason": reason,
        "risk_score": risk_score,
        "flags": flags or [],
        "action": action
    }
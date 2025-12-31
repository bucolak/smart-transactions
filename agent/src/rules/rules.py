def check_budget(amount, state):
    if state["daily_spent"] + amount > state["daily_limit"]:
        return False, "daily_budget_exceeded"
    return True, None


def check_velocity(tx_count_last_hour):
    if tx_count_last_hour > 5:
        return False, "high_velocity"
    return True, None


def calculate_risk(flags):
    base = 10
    for f in flags:
        if f == "daily_budget_exceeded":  # Değişiklik burada
            base += 50
        if f == "high_velocity":
            base += 30
    return min(base, 100)
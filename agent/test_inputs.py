from agent import agent_decision
from gemini import gemini_explain

agent_state = {
    "daily_spent": 300,
    "daily_limit": 500
}

decision = agent_decision(
    amount=50,
    tx_count_last_hour=10,
    agent_state=agent_state
)

print("Agent Decision:", decision)

explanation = gemini_explain(decision)
print("Gemini Explanation:", explanation)

execute_workflow(decision)

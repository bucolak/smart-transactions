"""
ARC Sentinel Agent API
Blockchain tarafından kullanılacak JSON endpoint
"""

import sys
import os
# Proje root'unu Python'a tanıt
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

import json
from src.agent.agent import agent_decision

class AgentAPI:
    """Agent API wrapper"""
    
    def __init__(self, agent_state):
        self.agent_state = agent_state
    
    def evaluate_payment(self, payment_request):
        """
        Ödeme isteğini değerlendir
        
        payment_request = {
            "amount": 100,
            "tx_count_last_hour": 3,
            "recipient": "0x...",
            "purpose": "API subscription"
        }
        
        Returns JSON decision
        """
        decision = agent_decision(
            amount=payment_request["amount"],
            tx_count_last_hour=payment_request["tx_count_last_hour"],
            agent_state=self.agent_state
        )
        
        return json.dumps(decision, indent=2)
    
    def get_agent_status(self):
        """Agent durumunu döndür"""
        return {
            "daily_spent": self.agent_state["daily_spent"],
            "daily_limit": self.agent_state["daily_limit"],
            "remaining": self.agent_state["daily_limit"] - self.agent_state["daily_spent"],
            "status": "active"
        }

# Test kullanımı
if __name__ == "__main__":
    # Agent durumu
    state = {
        "daily_spent": 300,
        "daily_limit": 500
    }
    
    api = AgentAPI(state)
    
    # Test isteği
    request = {
        "amount": 50,
        "tx_count_last_hour": 2,
        "recipient": "0x1234...",
        "purpose": "API usage"
    }
    
    print("=== AGENT API TEST ===")
    print("\n📊 Agent Status:")
    print(json.dumps(api.get_agent_status(), indent=2))
    
    print("\n💰 Payment Evaluation:")
    print(api.evaluate_payment(request))
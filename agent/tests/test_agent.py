"""
ARC Sentinel Test - Agent karar verme sistemi testi
"""

import sys
import os

# Proje root'u Python'a tanıt
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.agent.agent import agent_decision

print("=" * 70)
print("ARC SENTINEL - AGENT TEST")
print("=" * 70)

# Agent'ın durumu (bugün ne kadar harcadı)
agent_state = {
    "daily_spent": 300,    # Bugün 300 USDC harcadı
    "daily_limit": 500     # Günlük limit 500 USDC
}

print("\n📊 AGENT DURUMU:")
print(f"  Bugün harcanan: {agent_state['daily_spent']} USDC")
print(f"  Günlük limit: {agent_state['daily_limit']} USDC")
print(f"  Kalan: {agent_state['daily_limit'] - agent_state['daily_spent']} USDC")

# TEST 1: Normal ödeme (başarılı olmalı)
print("\n" + "-" * 70)
print("TEST 1: Normal Ödeme (50 USDC)")
print("-" * 70)

decision1 = agent_decision(
    amount=50,                  # 50 USDC ödeme
    tx_count_last_hour=2,       # Son 1 saatte 2 işlem (normal)
    agent_state=agent_state
)

print(f"\n✅ Karar: {decision1['decision']}")
print(f"📝 Sebep: {decision1['reason']}")
print(f"⚠️  Risk: {decision1['risk_score']}/100")
print(f"🚩 Sorunlar: {decision1['flags']}")
if decision1['action']:
    print(f"🎯 Aksiyon: {decision1['action']['type']}")

# TEST 2: Çok hızlı işlem (review olmalı)
print("\n" + "-" * 70)
print("TEST 2: Hızlı İşlem (50 USDC, 10 işlem/saat)")
print("-" * 70)

decision2 = agent_decision(
    amount=50,
    tx_count_last_hour=10,      # Son 1 saatte 10 işlem (ÇOK FAZLA!)
    agent_state=agent_state
)

print(f"\n⚠️  Karar: {decision2['decision']}")
print(f"📝 Sebep: {decision2['reason']}")
print(f"⚠️  Risk: {decision2['risk_score']}/100")
print(f"🚩 Sorunlar: {decision2['flags']}")
if decision2['action']:
    print(f"🎯 Aksiyon: {decision2['action']['type']}")

# TEST 3: Bütçe aşımı (reject olmalı)
print("\n" + "-" * 70)
print("TEST 3: Bütçe Aşımı (300 USDC)")
print("-" * 70)

decision3 = agent_decision(
    amount=300,                 # 300 USDC (limit 500, harcanan 300 → toplam 600!)
    tx_count_last_hour=2,
    agent_state=agent_state
)

print(f"\n❌ Karar: {decision3['decision']}")
print(f"📝 Sebep: {decision3['reason']}")
print(f"⚠️  Risk: {decision3['risk_score']}/100")
print(f"🚩 Sorunlar: {decision3['flags']}")
if decision3['action']:
    print(f"🎯 Aksiyon: {decision3['action']['type']}")
else:
    print(f"🎯 Aksiyon: Ödeme reddedildi")

print("\n" + "=" * 70)
print("TEST TAMAMLANDI!")
print("=" * 70)
"""
ARC Sentinel - Gemini AI Açıklama Testi
"""

import sys
import os

# Proje root'u Python'a tanıt
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.agent.agent import agent_decision
from src.ai.gemini_explainer import GeminiExplainer

print("=" * 70)
print("ARC SENTINEL - GEMINI AI TEST")
print("=" * 70)

# Agent durumu
agent_state = {
    "daily_spent": 300,
    "daily_limit": 500
}

# Gemini'yi başlat
try:
    explainer = GeminiExplainer()
    print("\n✅ Gemini AI bağlantısı başarılı!")
except Exception as e:
    print(f"\n❌ Gemini bağlantı hatası: {e}")
    print("🔧 .env dosyasında GEMINI_API_KEY var mı kontrol et!")
    exit(1)

# TEST 1: Normal ödeme kararını açıklat
print("\n" + "-" * 70)
print("TEST 1: Normal Ödeme Kararı")
print("-" * 70)

decision = agent_decision(
    amount=50,
    tx_count_last_hour=2,
    agent_state=agent_state
)

print(f"\n📊 KARAR:")
print(f"  Sonuç: {decision['decision']}")
print(f"  Risk: {decision['risk_score']}/100")
print(f"  Sebep: {decision['reason']}")

print(f"\n🤖 GEMINI AÇIKLAMASI:")
print("-" * 70)
explanation = explainer.explain_decision(decision)
print(explanation)

# TEST 2: Hızlı işlem kararını açıklat
print("\n" + "=" * 70)
print("TEST 2: Hızlı İşlem Kararı")
print("=" * 70)

decision2 = agent_decision(
    amount=50,
    tx_count_last_hour=10,
    agent_state=agent_state
)

print(f"\n📊 KARAR:")
print(f"  Sonuç: {decision2['decision']}")
print(f"  Risk: {decision2['risk_score']}/100")
print(f"  Sebep: {decision2['reason']}")

print(f"\n🤖 GEMINI AÇIKLAMASI:")
print("-" * 70)
explanation2 = explainer.explain_decision(decision2)
print(explanation2)

# TEST 3: Bütçe aşımı kararını açıklat
print("\n" + "=" * 70)
print("TEST 3: Bütçe Aşımı Kararı")
print("=" * 70)

decision3 = agent_decision(
    amount=300,
    tx_count_last_hour=2,
    agent_state=agent_state
)

print(f"\n📊 KARAR:")
print(f"  Sonuç: {decision3['decision']}")
print(f"  Risk: {decision3['risk_score']}/100")
print(f"  Sebep: {decision3['reason']}")

print(f"\n🤖 GEMINI AÇIKLAMASI:")
print("-" * 70)
explanation3 = explainer.explain_decision(decision3)
print(explanation3)

print("\n" + "=" * 70)
print("TÜM TESTLER TAMAMLANDI!")
print("=" * 70)
"""
Gemini AI ile karar açıklama (Yeni SDK)
"""
from google import genai
from google.genai import types
import os
from dotenv import load_dotenv
import json

load_dotenv()

class GeminiExplainer:
    """Gemini AI ile karar açıklama"""
    
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY bulunamadı!")
        
        self.client = genai.Client(api_key=api_key)
    
    def explain_decision(self, decision):
        """Agent kararını açıkla"""
        
        prompt = f"""Sen bir risk analisti yapay zekasısın.
Bu agent kararını açıkla:

Karar Detayları:
{json.dumps(decision, indent=2, ensure_ascii=False)}

Şunları açıkla:
1. Ne kararı verildi ve neden?
2. Risk skoru ne anlama geliyor?
3. Hangi aksiyonlar alınmalı?

Kısa ve net açıkla (maksimum 5 cümle)."""

        try:
            response = self.client.models.generate_content(
                model='gemini-2.0-flash-exp',
                contents=prompt
            )
            return response.text
        
        except Exception as e:
            # Eğer quota bittiyse basit açıklama döndür
            if "RESOURCE_EXHAUSTED" in str(e):
                return self._generate_simple_explanation(decision)
            return f"❌ Açıklama hatası: {str(e)}"
    
    def _generate_simple_explanation(self, decision):
        """Basit açıklama oluştur (AI kullanmadan)"""
        result = decision['decision']
        risk = decision['risk_score']
        reason = decision['reason']
        
        if result == "approve":
            return f"✅ Ödeme onaylandı. Risk seviyesi düşük ({risk}/100). {reason}. İşlem güvenle gerçekleştirilebilir."
        elif result == "review":
            return f"⚠️ Manuel inceleme gerekiyor. Risk seviyesi orta ({risk}/100). {reason}. İşlem onaylanmadan önce kontrol edilmeli."
        else:
            return f"❌ Ödeme reddedildi. Risk seviyesi yüksek ({risk}/100). {reason}. İşlem güvenlik politikalarına aykırı."
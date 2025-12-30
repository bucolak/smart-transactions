from google import genai
import os

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

def gemini_explain(decision):
    prompt = f"""
You are an AI assistant explaining an autonomous payment agent's decision.

Decision data:
{decision}

Explain in 1–2 short sentences why this decision was made.
"""

    response = client.models.generate_content(
        model="models/gemini-1.5-flash",  # 👈 BU FORMAT ÖNEMLİ
        contents=prompt
    )

    return response.text.strip()

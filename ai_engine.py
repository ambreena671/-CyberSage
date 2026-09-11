"""
CyberSage - AI Engine
Handles all Gemini / Groq API interactions cleanly with fallback mechanisms and robust error handling.
API keys are read exclusively from Streamlit secrets (st.secrets).
"""

import os
import streamlit as st
from typing import Dict, Any, Tuple

def get_ai_client() -> Tuple[str, Any, str]:
    """
    Checks for available API keys in st.secrets or environment variables.
    Returns: (provider_name: str, client_instance: Any, error_message: str)
    """
    # 1. Try Google Gemini Secrets
    google_key = None
    try:
        google_key = st.secrets.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    except Exception:
        google_key = os.environ.get("GOOGLE_API_KEY")

    if google_key:
        try:
            from google import genai
            client = genai.Client(api_key=google_key)
            return "google", client, ""
        except Exception as e:
            return "", None, f"Failed to initialize Google Gemini client: {str(e)}"

    # 2. Try Groq Secrets as Fallback
    groq_key = None
    try:
        groq_key = st.secrets.get("GROQ_API_KEY") or os.environ.get("GROQ_API_KEY")
    except Exception:
        groq_key = os.environ.get("GROQ_API_KEY")

    if groq_key:
        try:
            from groq import Groq
            client = Groq(api_key=groq_key)
            return "groq", client, ""
        except Exception as e:
            return "", None, f"Failed to initialize Groq client: {str(e)}"

    return "", None, "AI service configuration missing. Please configure GOOGLE_API_KEY in Streamlit Secrets."

def generate_ai_completion(prompt: str, system_instruction: str = "") -> str:
    """
    Executes an AI text completion request using the available provider.
    Fails gracefully without revealing secrets.
    """
    provider, client, err = get_ai_client()

    if not provider or not client:
        return (
            "⚠️ [AI Insight Unavailable]: System running in deterministic-only mode. "
            "No valid AI API key detected in Streamlit Secrets."
        )

    try:
        if provider == "google":
            # Using current official google-genai SDK
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config={
                    'system_instruction': system_instruction or "You are an expert Cybersecurity Incident Response AI."
                } if system_instruction else None
            )
            return response.text.strip()

        elif provider == "groq":
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": system_instruction or "You are CyberSage, an expert Cybersecurity Investigator."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            return response.choices[0].message.content.strip()

    except Exception as e:
        return f"⚠️ [AI Service Notice]: Unable to generate narrative due to transient API response error. (Details: {str(e)})"
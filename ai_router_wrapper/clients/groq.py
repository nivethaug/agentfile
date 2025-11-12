import requests
from typing import List, Dict, Optional
from config import GROQ_API_KEYS  # List of keys: ["key1", "key2", ...]

DEFAULT_GROQ_MODEL = "mixtral-8x7b"  # Caller can pass mapped model

Message = Dict[str, str]

def call_groq(
    messages: Optional[List[Message]] = None,
    prompt: Optional[str] = None,
    model: str = DEFAULT_GROQ_MODEL,
    temperature: float = 0.7,
    timeout: int = 20,
    **kwargs
) -> str:
    """
    Chat-first. If only 'prompt' is provided, wrap it as a single user message.
    Automatic API key failover.
    """
    if messages is None:
        messages = [{"role": "user", "content": prompt or ""}]

    last_error = None

    for key in GROQ_API_KEYS:
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    **({} if not kwargs else kwargs)
                },
                timeout=timeout
            )

            if response.status_code == 200:
                return response.json().get("choices", [{}])[0].get("message", {}).get("content", "Groq error")
            else:
                last_error = f"HTTP {response.status_code}: {response.text}"

        except requests.exceptions.RequestException as e:
            last_error = str(e)
            continue  # Try next key

    return f"All Groq API keys failed. Last error: {last_error}"

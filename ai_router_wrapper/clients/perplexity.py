import requests
from typing import List, Dict, Optional, Union

DEFAULT_PPLX_MODEL = "sonar-reasoning-pro"

Message = Dict[str, str]

def call_perplexity(
    messages: Optional[List[Message]] = None,
    prompt: Optional[str] = None,
    model: str = DEFAULT_PPLX_MODEL,
    timeout: int = 30,
    **kwargs
):
    """
    Chat-first. If only 'prompt' is provided, wrap it as a single user message.
    """
    if messages is None:
        messages = [{"role": "user", "content": prompt or ""}]

    response = requests.post(
        'https://api.perplexity.ai/chat/completions',
        headers={
            'Authorization': f'Bearer {PERPLEXITY_API_KEY}',
            'Content-Type': 'application/json'
        },
        json={
            'model': model,
            'messages': messages,
            **({} if not kwargs else kwargs)
        },
        timeout=timeout
    )
    try:
        print(f"Perplexity response status: {response}")
        return response.json().get("choices", [{}])[0].get("message", {}).get("content", "Perplexity error")
    except Exception:
        return f"Perplexity error: {response.text}"

def _join_messages_text(prompt_or_messages: Union[str, List[Message]]) -> str:
    if isinstance(prompt_or_messages, str):
        return prompt_or_messages
    return " ".join(m["content"] for m in prompt_or_messages if m.get("role") in ("user", "assistant"))

def classify_task_type_llm(prompt_or_messages: Union[str, List[Message]]) -> str:
    """
    Accepts either a str or a list of chat messages.
    Uses Perplexity to classify into a task type.
    """
    text = _join_messages_text(prompt_or_messages)

    url = "https://api.perplexity.ai/chat/completions"
    headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json"
    }

    classification_prompt = f"""
You are a classification agent. Read the prompt and classify it into one of these task types:

- resume_generation
- portfolio_generation
- quote_generation
- prompt_optimization
- strategy_idea_generation
- market_news_summary
- backtest_summary
- education_faq
- code_gen
- summarize
- deep_reasoning
- document_analysis
- search
- risk_analysis

Only return the task type as a single token like market_news_summary (no explanations).

Prompt: "{text}"
"""

    payload = {
        "model": DEFAULT_PPLX_MODEL,
        "messages": [{"role": "user", "content": classification_prompt}]
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        return response.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print("Error during classification:", e)
        return "unknown"

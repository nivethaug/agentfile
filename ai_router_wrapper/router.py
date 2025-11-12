import re
from typing import List, Dict, Union, Optional

from clients.groq import call_groq
from clients.perplexity import call_perplexity, classify_task_type_llm
from clients.claude import call_claude

# === Safe Groq Model Name Mapping (2025) ===
GROQ_MODEL_MAP = {
    "groq-mixtral": "llama-3.3-70b-versatile",  # Was mixtral-8x7b, safer default
    "groq-llama3": "llama-3.3-70b-versatile",
    "groq-llama3-8b": "llama-3.1-8b-instant",
    "groq-llama3-70b": "llama-3.1-70b-versatile",
    "groq-gemma": "gemma-2-9b"
}

# === TASK → MODEL MAP (DreamBigWithAI) ===
TASK_MODEL_MAP = {
    "resume_generation": "groq-mixtral",
    "portfolio_generation": "groq-mixtral",
    "quote_generation": "sonar-pro",
    "prompt_optimization": "claude-opus",
    "strategy_idea_generation": "sonar-reasoning-pro",
    "market_news_summary": "sonar-pro",
    "backtest_summary": "groq-mixtral",
    "education_faq": "sonar",
    "document_analysis": "claude-opus",
    "code_gen": "groq-llama3",
    "summarize": "groq-mixtral",
    "search": "sonar",
    "deep_reasoning": "claude-opus"
}

Message = Dict[str, str]

def _join_for_detection(messages: List[Message]) -> str:
    return " ".join(m["content"] for m in messages if m["role"] in ("user", "assistant"))

def detect_task_type_by_rule(text: str) -> str:
    rules = {
        "resume_generation": ["resume", "cv", "curriculum vitae"],
        "portfolio_generation": ["portfolio", "work showcase", "profile"],
        "quote_generation": ["quote", "quotation", "estimate", "pricing"],
        "prompt_optimization": ["optimize prompt", "improve prompt", "refine prompt"],
        "strategy_idea_generation": ["strategy idea", "market strategy", "plan idea"],
        "market_news_summary": ["market news", "news summary", "financial update"],
        "backtest_summary": ["backtest result", "strategy performance", "backtesting"],
        "education_faq": ["faq", "frequently asked", "explain"],
        "document_analysis": ["analyze document", "doc analysis", "contract review"],
        "code_gen": ["python", "javascript", "code", "script"],
        "summarize": ["summarize", "brief", "short version"],
        "search": ["search", "lookup", "find info"],
        "deep_reasoning": ["reasoning", "complex logic", "multi-step thinking"]
    }
    s = text.lower()
    for task, keywords in rules.items():
        if any(k in s for k in keywords):
            return task
    return classify_task_type_llm(text)

def resolve_model(task_type: str) -> str:
    base = TASK_MODEL_MAP.get(task_type, "groq-mixtral")
    return GROQ_MODEL_MAP.get(base, base)

def dr_route_llm(
    prompt_or_messages: Union[str, List[Message]],
    task_type: Optional[str] = None,
    priority: str = 'medium',
    dry_run: bool = False,
    **gen_kwargs
) -> str:
    # Normalize to messages
    if isinstance(prompt_or_messages, str):
        messages: List[Message] = [{"role": "user", "content": prompt_or_messages}]
    else:
        messages = list(prompt_or_messages)

    # Detect task
    if not task_type:
        joined = _join_for_detection(messages)
        task_type = detect_task_type_by_rule(joined) or classify_task_type_llm(joined)

    print(f"[Dream Router] Task={task_type}")

    model_choice = resolve_model(task_type)
    if dry_run:
        return {"task": task_type, "model": model_choice, "priority": priority}


    if model_choice.startswith("claude"):
        if priority == "high":
            return call_claude(messages=messages, **gen_kwargs)
        else:
            return call_groq(messages=messages, model=GROQ_MODEL_MAP["groq-mixtral"], **gen_kwargs)

    if model_choice.startswith("sonar"):
        return call_perplexity(messages=messages, model=model_choice, **gen_kwargs)

    if model_choice.startswith("groq") or model_choice in GROQ_MODEL_MAP:
        groq_model = GROQ_MODEL_MAP.get(model_choice, GROQ_MODEL_MAP["groq-mixtral"])
        return call_groq(messages=messages, model=groq_model, **gen_kwargs)

    return call_groq(messages=messages, model=GROQ_MODEL_MAP["groq-mixtral"], **gen_kwargs)

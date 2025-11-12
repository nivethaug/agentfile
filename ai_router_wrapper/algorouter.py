import re
from typing import List, Dict, Union, Optional

from clients.groq import call_groq
from clients.perplexity import call_perplexity, classify_task_type_llm
from clients.claude import call_claude

# === Safe Groq Model Name Mapping (2025) ===
GROQ_MODEL_MAP = {
    "groq-mixtral": "llama-3.3-70b-versatile",  # replaces mixtral-8x7b
    "mixtral-8x7b": "llama-3.3-70b-versatile",
    "groq-llama3": "llama-3.3-70b-versatile",
    "groq-llama3-8b": "llama-3.1-8b-instant",
    "groq-llama3-70b": "llama-3.1-70b-versatile",
    "groq-gemma": "gemma-2-9b"
}

# === TASK → MODEL MAP (AlgoBillionaire) ===
TASK_MODEL_MAP = {
    "code_gen": "claude-opus",
    "strategy_idea_generation": "sonar-reasoning-pro",
    "market_news_summary": "sonar-pro",
    "backtest_summary": "groq-mixtral",
    "document_analysis": "claude-opus",
    "education_faq": "sonar",
    "summarize": "groq-mixtral",
    "search": "sonar",
    "deep_reasoning": "claude-opus",
    "portfolio_generation": "groq-mixtral",
    "risk_analysis": "claude-opus"
}

Message = Dict[str, str]

def _join_for_detection(messages: List[Message]) -> str:
    return " ".join(m["content"] for m in messages if m["role"] in ("user", "assistant"))

def detect_task_type_by_rule(text: str) -> str:
    """
    Detect task type using simple keyword rules for Algo tasks.
    Falls back to LLM-based classification if nothing matches.
    """
    rules = {
        "code_gen": [r"\bpython\b", "strategy code", "trading bot", r"\bindicator\b", r"\balgorithm\b"],
        "strategy_idea_generation": ["trading idea", "market strategy", "trade plan"],
        "market_news_summary": ["market news", "crypto news", "forex update"],
        "backtest_summary": [r"\bbacktest\b", "performance report", "historical test"],
        "document_analysis": ["regulation", "market doc", "pdf analysis"],
        "education_faq": [r"\bfaq\b", "how to", r"\bexplain\b"],
        "summarize": [r"\bsummary\b", r"\bsummarize\b", "short version"],
        "search": [r"\bsearch\b", r"\blookup\b", "find market info"],
        "deep_reasoning": [r"\breasoning\b", "complex analysis", "multi-step logic"],
        "risk_analysis": ["risk model", "drawdown", "volatility", r"\bvar\b", "value at risk", "risk analysis"],
        "portfolio_generation": ["asset allocation", "portfolio", "risk mix"]
    }

    s = text.lower()
    for task, keywords in rules.items():
        if any((re.search(p, s) if p.startswith("\\b") or "[" in p else (p in s)) for p in keywords):
            return task
    return classify_task_type_llm(text)

def resolve_model(task_type: str) -> str:
    base = TASK_MODEL_MAP.get(task_type, "groq-mixtral")
    return GROQ_MODEL_MAP.get(base, base)

def route_llm(
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

    print(f"[Algo Router] Task={task_type}")

    model_choice = resolve_model(task_type)
    if dry_run:
        return {"task": task_type, "model": model_choice, "priority": priority}


    # Special handling for code_gen
    if task_type == "code_gen":
        if priority == "high":
            return call_claude(messages=messages, **gen_kwargs)
        return call_groq(messages=messages, model=GROQ_MODEL_MAP["groq-llama3"], **gen_kwargs)

    # Claude handling
    if model_choice.startswith("claude"):
        if priority == "high":
            return call_claude(messages=messages, **gen_kwargs)
        return call_groq(messages=messages, model=GROQ_MODEL_MAP["groq-mixtral"], **gen_kwargs)

    # Perplexity handling
    if model_choice.startswith("sonar"):
        return call_perplexity(messages=messages, model=model_choice, **gen_kwargs)

    # Groq handling
    if model_choice.startswith("groq") or model_choice in GROQ_MODEL_MAP:
        groq_model = GROQ_MODEL_MAP.get(model_choice, GROQ_MODEL_MAP["groq-mixtral"])
        return call_groq(messages=messages, model=groq_model, **gen_kwargs)

    # Default fallback
    return call_groq(messages=messages, model=GROQ_MODEL_MAP["groq-mixtral"], **gen_kwargs)

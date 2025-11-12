import requests
from config import CLAUDE_API_KEY

def call_claude(prompt, model="claude-sonnet-4-20250514"):
    response = requests.post("https://api.anthropic.com/v1/messages", 
    headers = {
        "x-api-key": CLAUDE_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
    }, json={
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}]
    }, timeout=30)
    return response.json().get("content", [{}])[0].get("text", "Claude error")
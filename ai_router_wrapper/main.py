from algorouter import route_llm
from router import dr_route_llm

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Literal, Union, Dict, Any
import uvicorn

Role = Literal["system", "user", "assistant"]

class Message(BaseModel):
    role: Role
    content: str

class PromptRequest(BaseModel):
    domain: Literal["dream", "algo"]
    # Either send a single prompt...
    prompt: Optional[str] = None
    # ...or send chat-style messages:
    messages: Optional[List[Message]] = None
    # Optional: system prompt (will be inserted at the top automatically)
    system_prompt: Optional[str] = None
    task_type: Optional[str] = None
    priority: Optional[Literal["low", "medium", "high"]] = "medium"
    dry_run: bool = False   # 👈 NEW

    # Optional passthrough generation kwargs
    gen_kwargs: Optional[Dict[str, Any]] = Field(default_factory=dict)


def normalize_messages(payload_prompt: Optional[str], payload_messages: Optional[List[Message]], system_prompt: Optional[str]) -> List[Dict[str, str]]:
    if payload_messages and len(payload_messages) > 0:
        msgs = [m.model_dump() for m in payload_messages]
    else:
        msgs = [{"role": "user", "content": payload_prompt or ""}]

    if system_prompt:
        # Remove any existing leading system to avoid duplicates, then insert
        msgs = [m for m in msgs if m["role"] != "system"]
        msgs.insert(0, {"role": "system", "content": system_prompt})
    return msgs

app = FastAPI(
    title="LLM Router API",
    description="Routes prompts/messages to Dream or Algo LLM pipelines",
    version="2.0"
)



# allow your local dev app + your production site(s)
ALLOWED_ORIGINS = [
    "http://localhost:8080",
    "http://localhost:3000",
    "https://dreambigwithai.com", 
    "https://portfolio.dreambigwithai.com",  # if you’ll call from this origin too
    "https://salesdocpilot.dreambigwithai.com",
    "https://esignpilot.dreambigwithai.com",
    "https://resume.dreambigwithai.com",
    "https://promptcraft.dreambigwithai.com",   # if you’ll call from this origin too
    "https://algobillionaire.com"   # add your real frontend domain(s)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,             # set True only if you use cookies/auth headers
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=[],
    max_age=600,
)


@app.post("/route")
async def route_prompt(req: PromptRequest):
    messages = normalize_messages(req.prompt, req.messages, req.system_prompt)

    if req.domain == "dream":
        result = dr_route_llm(messages, req.task_type, req.priority,req.dry_run, **(req.gen_kwargs or {}))
    else:
        result = route_llm(messages, req.task_type, req.priority,req.dry_run, **(req.gen_kwargs or {}))

    return {
        "domain": req.domain,
        "task_type": req.task_type,
        "priority": req.priority,
        "response": result
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8008)

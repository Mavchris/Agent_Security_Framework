"""
Minimal example: expose an existing Python agent function as a local HTTP
endpoint so it can be registered in ASIF as a `remote_http` agent.

ASIF never executes your code directly - you run this yourself, next to
your agent, and only give ASIF the resulting URL. Uses FastAPI (already
an ASIF dependency) for consistency with the rest of the project; any
HTTP framework works the same way.

Run:      uvicorn docs.examples.local_agent_http_wrapper:app --port 8500
Register: in ASIF's "Test Agent" tab, add a new agent of type
          remote_http with endpoint_url=http://localhost:8500/query
          (request_field/response_field can stay at their defaults,
          "prompt"/"response", since that's what's used below).
"""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


def mon_agent(prompt: str) -> str:
    """Replace this with a call into your actual agent."""
    return f"You said: {prompt}"


class Query(BaseModel):
    prompt: str


@app.post("/query")
def query(body: Query):
    return {"response": mon_agent(body.prompt)}

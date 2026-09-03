"""
Run a HuggingFace model as its own, dedicated process and expose it as a
`remote_http` agent - the same pattern as local_agent_http_wrapper.py in
this directory, but for a specific, real problem rather than a template.

Why this needs its own process, unlike every other wrapper in
testing/agent_wrappers.py (which all stay in-process): torch and pyarrow
each bundle their own, incompatible copy of Windows' MSVCP140.dll. On
this project's Windows dev environment, any process that has already
imported pandas/pyarrow (the dashboard, always - pandas is imported at
every page's module load time; the API too, if it ever ends up importing
pandas transitively) crashes the instant torch is imported afterward:

    OSError: [WinError 1114] ... Error loading ...torch\\lib\\c10.dll ...

Confirmed via Windows' own Application Error log, which names pyarrow's
bundled msvcp140.dll (not torch's) as the faulting module - both DLLs are
correct for their own package, they just can't coexist in one process.
Pinning compatible versions doesn't fix this - only not sharing a process
does. See testing.agent_wrappers.HuggingFaceAgentWrapper's docstring and
testing.agent_wrappers.get_agent_wrapper()'s explicit rejection of
'huggingface'/'hf' for the same reasoning.

This script reuses HuggingFaceAgentWrapper's model-loading logic directly
(imported, not duplicated) - it is only the HTTP shell around it.

Install (separate from the rest of ASIF's dependencies and from
requirements-translation.txt - see requirements-huggingface.txt for why):
    pip install -r requirements-huggingface.txt

Run, picking the model via --model:
    python docs/examples/huggingface_agent_server.py \\
        --model mistralai/Mistral-7B-Instruct-v0.1 --port 8501

or via the HF_AGENT_MODEL environment variable (needed for the
`uvicorn module:app` launch style, which never runs this file's
`if __name__` block so there's no CLI argument to read):
    set HF_AGENT_MODEL=mistralai/Mistral-7B-Instruct-v0.1
    uvicorn docs.examples.huggingface_agent_server:app --port 8501

Register: in ASIF's "Test Agent" tab, add a new agent of type
          remote_http with endpoint_url=http://localhost:8501/query
          (request_field/response_field can stay at their defaults,
          "prompt"/"response", since that's what's used below).
"""

import argparse
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from testing.agent_wrappers import HuggingFaceAgentWrapper

MODEL_ENV_VAR = "HF_AGENT_MODEL"
DEFAULT_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"

# Set by _load_model() during startup - not before, so the process comes
# up and starts serving even while a large model is still downloading/
# loading; a request that arrives before it's ready gets a clear 503
# instead of an AttributeError on None.
_agent = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _agent
    model_name = os.environ.get(MODEL_ENV_VAR, DEFAULT_MODEL)
    _agent = HuggingFaceAgentWrapper(model_name=model_name)
    yield


app = FastAPI(lifespan=lifespan)


class Query(BaseModel):
    prompt: str


@app.post("/query")
def query(body: Query):
    if _agent is None:
        raise HTTPException(status_code=503, detail="Model is still loading - try again shortly")
    return {"response": _agent.query(body.prompt)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a HuggingFace model as an isolated remote_http agent"
    )
    parser.add_argument(
        "--model",
        default=os.environ.get(MODEL_ENV_VAR, DEFAULT_MODEL),
        help=f"HuggingFace model name/path (default: ${MODEL_ENV_VAR} if set, else {DEFAULT_MODEL})",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8501)
    args = parser.parse_args()

    # The lifespan hook above reads MODEL_ENV_VAR, not a CLI arg directly
    # (uvicorn's `module:app` launch style never runs this block at all) -
    # funneling --model through the same env var keeps a single source of
    # truth for both launch styles instead of two parallel code paths.
    os.environ[MODEL_ENV_VAR] = args.model

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)

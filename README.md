# Safe AI Mailroom Agent — GA5

This is a FastAPI implementation scaffold for `ga5-mailroom-action-gate/v2`.

## What it implements
- `POST /v1/mailroom/actions` with `propose` and `commit`.
- Canonical compact recursively key-sorted JSON SHA-256 digests.
- Persistent SQLite storage for evaluations, proposals, cached decisions, and receipts.
- Stable proposal call IDs based on dossier ID + canonical dossier content.
- Exact replay handling and changed-content conflicts for evaluation IDs.
- Strict action target/payload shape validation.
- Ed25519 receipt signature verification before any outcomes are recorded.
- Atomic validation of the whole receipt batch before writing outcomes.

## Important
This code needs a working OpenAI-compatible model API to make case decisions. Add a valid API key in the deployment environment. Do not put secrets in source control. The model's decisions can still be wrong; test against the assignment's grader and inspect feedback. The code intentionally fails closed if model output or signatures are invalid.

## Deploy quickly with Render
1. Create a GitHub repository and upload these files.
2. In Render, choose **New + → Blueprint** and select the repository (or create a Web Service manually).
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
5. Add environment variables:
   - `LLM_API_KEY` = your own OpenAI-compatible API key
   - `LLM_MODEL` = `gpt-4o-mini` (or a model your provider supports with JSON mode)
   - `LLM_BASE_URL` = `https://api.openai.com/v1`
6. Wait for deployment. Visit `https://YOUR-SERVICE.onrender.com/health` and confirm `{"status":"ok"}`.
7. Submit exactly `https://YOUR-SERVICE.onrender.com/v1/mailroom/actions` in the assignment field. Do not include a query, fragment, credentials, or trailing `/`.

## Run locally
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:LLM_API_KEY="your-key"
uvicorn app:app --reload --port 8000
```
Local endpoint: `http://127.0.0.1:8000/v1/mailroom/actions` (not acceptable for final submission; it must be public HTTPS).

## Before pressing Check
- Confirm `/health` works on the deployed public HTTPS host.
- Paste the exact `/v1/mailroom/actions` endpoint, not the base website URL.
- Confirm `LLM_API_KEY` is configured in the deployed service, not just locally.
- Use Check sparingly: the task allows only 10 checks and reserves the last check for Save.
- If Check returns an error, copy the full message and logs before changing code.

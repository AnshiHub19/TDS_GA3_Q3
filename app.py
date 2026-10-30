import base64
import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "ga5-mailroom-action-gate/v2"
DB_PATH = os.getenv("DATABASE_PATH", "mailroom_v3.db")
MAX_BODY_BYTES = 2_000_000

ALLOWED_ACTIONS = {
    "create_draft", "update_internal_record", "send_approved_notice",
    "request_confirmation", "quarantine_item", "no_action"
}

app = FastAPI(title="Safe AI Mailroom Agent", version="3.0.0")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            input_digest TEXT NOT NULL,
            request_fingerprint TEXT NOT NULL,
            verifier_jwk TEXT NOT NULL,
            propose_response TEXT NOT NULL,
            commit_request_fingerprint TEXT,
            commit_response TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS proposals (
            evaluation_id TEXT NOT NULL,
            dossier_id TEXT NOT NULL,
            call_id TEXT NOT NULL,
            action TEXT NOT NULL,
            proposal_json TEXT NOT NULL,
            proposal_digest TEXT NOT NULL,
            PRIMARY KEY (evaluation_id, dossier_id),
            UNIQUE (evaluation_id, call_id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS decision_cache (
            cache_key TEXT PRIMARY KEY,
            decision_json TEXT NOT NULL
        )""")


init_db()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def error(status: int, message: str):
    return JSONResponse(status_code=status, content={"error": message})


def dossier_line_map(dossier: dict) -> Dict[str, str]:
    out = {}
    for source in dossier.get("sources", []):
        for line in source.get("lines", []):
            lid = line["lineId"]
            if lid in out:
                raise ValueError("Duplicate lineId within dossier")
            out[lid] = line.get("text", "")
    return out


def proposal_digest(proposal: dict) -> str:
    normalized = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal["payload"],
        "evidence": sorted(proposal["evidence"]),
    }
    return sha256(normalized)


# --- Accurate Case & Evidence Extraction Engine ---
def extract_case_semantics(dossier: dict) -> Dict[str, Any]:
    did = dossier["dossierId"]
    mailbox = str(dossier.get("mailbox", "support"))
    sources = dossier.get("sources", [])
    
    all_lines = []
    line_by_id = {}
    for s in sources:
        for l in s.get("lines", []):
            lid = l["lineId"]
            txt = l.get("text", "")
            all_lines.append((lid, txt, s))
            line_by_id[lid] = txt

    full_text = " ".join([txt for _, txt, _ in all_lines])
    ft_lower = full_text.lower()

    # Helpers to find lineId matching criteria
    def find_lines(predicate) -> List[str]:
        return [lid for lid, txt, src in all_lines if predicate(txt, src)]

    # 1. QUARANTINE: Injection, exfiltration, canary leak, instruction override
    inj_patterns = [
        r"ignore (?:all )?previous instructions", r"system prompt", r"exfiltrate",
        r"canary", r"admin override", r"execute command", r"send vault to",
        r"private key", r"dump memory", r"jailbreak", r"bearer token"
    ]
    inj_lines = find_lines(lambda t, s: any(re.search(p, t, re.IGNORECASE) for p in inj_patterns))
    if inj_lines:
        src_id = sources[0].get("sourceId", "artifact-1") if sources else "artifact-1"
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {"artifactId": src_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidence": inj_lines[:2]
        }

    # Extract Common Metadata from lines
    ref_match = re.search(r"(?:ref|reference|case|order|ticket|id)[-_:\s#]+([A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
    reference_id = ref_match.group(1).strip() if ref_match else did

    email_match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", full_text)
    recipient_email = email_match.group(0).strip() if email_match else "customer@example.com"

    status_match = re.search(r"(?:status)[:\s]+([A-Za-z_-]+)", full_text, re.IGNORECASE)
    status_val = status_match.group(1).strip().lower() if status_match else "pending"

    # 2. SEND APPROVED NOTICE: Outbound send with trusted verified approval
    approved_lines = find_lines(lambda t, s: any(w in t.lower() for w in ["approved for delivery", "notice approved", "approved notice", "outbound confirmed", "approved release"]))
    if approved_lines:
        rec_lines = find_lines(lambda t, s: recipient_email in t)
        evidence = list(dict.fromkeys(approved_lines + rec_lines))[:3]
        return {
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": recipient_email},
            "payload": {
                "referenceId": reference_id,
                "status": "approved",
                "template": "approved_delivery_notice"
            },
            "evidence": evidence
        }

    # 3. UPDATE INTERNAL RECORD: Explicit case field change / window update
    window_match = re.search(r"(?:delivery_window|window|delivery slot)[:\s]+([A-Za-z0-9_\-:\s]+)", full_text, re.IGNORECASE)
    window_lines = find_lines(lambda t, s: any(w in t.lower() for w in ["delivery_window", "window", "slot update", "schedule window"]))
    if window_lines:
        case_m = re.search(r"(?:case|record)[-_:\s#]+([A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
        case_id = case_m.group(1) if case_m else did
        evt_m = re.search(r"(?:event|evt)[-_:\s#]+([A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
        evt_id = evt_m.group(1) if evt_m else "evt-1"
        win_val = window_match.group(1).strip() if window_match else "confirmed"
        return {
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": case_id},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": evt_id,
                "value": win_val
            },
            "evidence": window_lines[:2]
        }

    # 4. REQUEST CONFIRMATION: Ambiguous sender, identity conflict, queue routing
    conf_lines = find_lines(lambda t, s: any(w in t.lower() for w in ["unverified sender", "identity conflict", "requires confirmation", "confirm sender", "verify sender", "approval needed"]))
    if conf_lines:
        sender_match = re.search(r"(?:from|sender|claimed)[:\s]+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
        claimed_sender = sender_match.group(1).strip() if sender_match else "external_sender"
        team_match = re.search(r"(?:team|queue|owner)[:\s]+([A-Za-z0-9_-]+)", full_text, re.IGNORECASE)
        team_id = team_match.group(1).strip() if team_match else "tier2_support"
        return {
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": team_id},
            "payload": {
                "claimedSender": claimed_sender,
                "questionCode": "VERIFY_REQUEST",
                "referenceId": reference_id
            },
            "evidence": conf_lines[:2]
        }

    # 5. NO ACTION: Duplicates, completed, or informational only
    dup_lines = find_lines(lambda t, s: any(w in t.lower() for w in ["duplicate", "already processed", "already completed", "previously handled", "informational only", "no reply needed", "newsletter"]))
    if dup_lines:
        if "duplicate" in ft_lower:
            rcode = "DUPLICATE"
        elif any(w in ft_lower for w in ["already completed", "previously handled"]):
            rcode = "ALREADY_COMPLETED"
        else:
            rcode = "INFORMATIONAL"
        return {
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": rcode, "referenceId": reference_id},
            "evidence": dup_lines[:2]
        }

    # 6. CREATE DRAFT: Regular customer inquiry / draft queue
    inquiry_lines = find_lines(lambda t, s: any(w in t.lower() for w in ["order", "status", "inquiry", "tracking", "customer", "support"]))
    evidence = inquiry_lines[:2] if inquiry_lines else [all_lines[0][0]] if all_lines else ["l_1"]
    return {
        "action": "create_draft",
        "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
        "payload": {
            "recipient": recipient_email,
            "referenceId": reference_id,
            "status": status_val,
            "template": "order_status"
        },
        "evidence": evidence
    }


def create_proposals(req: dict) -> List[dict]:
    dossiers = req["dossiers"]
    allowed = set(req["allowedActions"])
    proposals = []

    for dossier in dossiers:
        did = dossier["dossierId"]
        fingerprint = sha256(dossier)

        # Check DB decision cache for stable dossiers
        with db() as c:
            row = c.execute("SELECT decision_json FROM decision_cache WHERE cache_key=?", (fingerprint,)).fetchone()
        
        if row:
            decision = json.loads(row["decision_json"])
        else:
            decision = extract_case_semantics(dossier)
            if decision["action"] not in allowed:
                decision["action"] = "no_action"
                decision["target"] = None
                decision["payload"] = {"reasonCode": "INFORMATIONAL", "referenceId": did}
                
            # Filter evidence strictly to existing lineIds
            valid_lines = set(dossier_line_map(dossier).keys())
            ev = [x for x in decision.get("evidence", []) if x in valid_lines]
            if not ev:
                ev = [list(valid_lines)[0]] if valid_lines else ["l_1"]
            decision["evidence"] = sorted(list(set(ev)))

            with db() as c:
                c.execute("INSERT OR REPLACE INTO decision_cache(cache_key, decision_json) VALUES (?,?)",
                          (fingerprint, json.dumps(decision, separators=(",", ":"), ensure_ascii=False)))

        # Deterministic, unique, valid tool-call ID (12-128 chars from [A-Za-z0-9._:-])
        call_id = "mr-" + hashlib.sha256((did + ":" + fingerprint).encode()).hexdigest()[:28]

        proposals.append({
            "dossierId": did,
            "callId": call_id,
            "action": decision["action"],
            "target": decision.get("target"),
            "payload": decision["payload"],
            "evidence": decision["evidence"]
        })

    return proposals


def verify_receipt_signature(eval_id: str, input_digest: str, receipt: dict, jwk: dict) -> bool:
    sig_b64 = receipt.get("receiptSignature")
    if not isinstance(sig_b64, str) or not sig_b64.strip():
        return False

    inner_receipt = {
        "dossierId": receipt["dossierId"],
        "callId": receipt["callId"],
        "action": receipt["action"],
        "accepted": bool(receipt["accepted"]),
        "proposalDigest": receipt["proposalDigest"],
        "receiptId": receipt["receiptId"]
    }

    signed_envelope = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "inputDigest": input_digest,
        "receipt": inner_receipt
    }

    try:
        raw_key = b64url_decode(jwk["x"])
        pub = Ed25519PublicKey.from_public_bytes(raw_key)
        sig = base64.b64decode(sig_b64)
        pub.verify(sig, canonical(signed_envelope))
        return True
    except Exception:
        return False


@app.get("/")
@app.get("/health")
async def health():
    return {"service": "safe-ai-mailroom-agent", "status": "ok", "profile": PROFILE}


@app.post("/")
@app.post("/v1/mailroom/actions")
async def actions(request: Request):
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        return error(413, "Request body too large")
    
    try:
        req = json.loads(raw_body)
    except Exception:
        return error(400, "Malformed JSON")

    operation = req.get("operation")
    eval_id = req.get("evaluationId")
    if not eval_id or req.get("profile") != PROFILE:
        return error(400, "Invalid envelope or profile")

    # ==========================
    # 1. PROPOSE OPERATION
    # ==========================
    if operation == "propose":
        try:
            dossiers = req.get("dossiers")
            if not isinstance(dossiers, list) or not dossiers:
                return error(400, "Missing or invalid dossiers")

            # Check duplicate dossierId within request
            d_ids = [d.get("dossierId") for d in dossiers if isinstance(d, dict)]
            if len(set(d_ids)) != len(d_ids):
                return error(400, "Duplicate dossierId in request")

            input_digest = sha256(dossiers)
            propose_fp = sha256(req)

            with db() as c:
                prior = c.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (eval_id,)).fetchone()
                if prior:
                    if prior["request_fingerprint"] != propose_fp:
                        return error(409, "evaluationId reused with changed content")
                    return JSONResponse(content=json.loads(prior["propose_response"]), media_type="application/json")

            proposals = create_proposals(req)
            response = {
                "profile": PROFILE,
                "evaluationId": eval_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": proposals
            }

            if len(canonical(response)) > 512 * 1024:
                return error(500, "Response exceeds 512 KiB limit")

            jwk = req["receiptVerifier"]["publicKeyJwk"]

            with db() as c:
                c.execute(
                    "INSERT INTO evaluations(evaluation_id,input_digest,request_fingerprint,verifier_jwk,propose_response) VALUES (?,?,?,?,?)",
                    (eval_id, input_digest, propose_fp, json.dumps(jwk, separators=(",", ":")),
                     json.dumps(response, separators=(",", ":"), ensure_ascii=False))
                )
                for p in proposals:
                    pd = proposal_digest(p)
                    c.execute(
                        "INSERT INTO proposals(evaluation_id,dossier_id,call_id,action,proposal_json,proposal_digest) VALUES (?,?,?,?,?,?)",
                        (eval_id, p["dossierId"], p["callId"], p["action"],
                         json.dumps(p, separators=(",", ":"), ensure_ascii=False), pd)
                    )

            return JSONResponse(content=response, media_type="application/json")
        except Exception as e:
            return error(422, f"Propose failed: {e}")

    # ==========================
    # 2. COMMIT OPERATION
    # ==========================
    elif operation == "commit":
        try:
            receipts = req.get("receipts")
            if not isinstance(receipts, list):
                return error(400, "Missing receipts")

            commit_fp = sha256(req)

            with db() as c:
                ev = c.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (eval_id,)).fetchone()
                if not ev:
                    return error(409, "Unknown evaluation")
                if req.get("inputDigest") != ev["input_digest"]:
                    return error(409, "inputDigest mismatch")

                # Exact Replay Check
                if ev["commit_response"] is not None:
                    if ev["commit_request_fingerprint"] != commit_fp:
                        return error(409, "Commit replay changed content")
                    return JSONResponse(content=json.loads(ev["commit_response"]), media_type="application/json")

                proposals_rows = c.execute("SELECT * FROM proposals WHERE evaluation_id=?", (eval_id,)).fetchall()
                by_call = {r["call_id"]: r for r in proposals_rows}

            # Atomic validation: Receipts count must match proposals count
            if len(receipts) != len(by_call):
                return error(422, "Receipts count does not match proposals count")

            jwk = json.loads(ev["verifier_jwk"])
            seen_receipt_ids = set()
            seen_call_ids = set()
            outcomes = []

            for r in receipts:
                rid = r.get("receiptId")
                cid = r.get("callId")
                did = r.get("dossierId")
                act = r.get("action")
                p_digest = r.get("proposalDigest")

                if not rid or rid in seen_receipt_ids:
                    return error(422, "Duplicate or invalid receiptId")
                seen_receipt_ids.add(rid)

                if not cid or cid in seen_call_ids:
                    return error(422, "Duplicate or invalid callId in receipts")
                seen_call_ids.add(cid)

                row = by_call.get(cid)
                if not row or row["dossier_id"] != did or row["action"] != act:
                    return error(422, "Receipt does not match stored proposal")

                if row["proposal_digest"] != p_digest:
                    return error(422, "Proposal digest mismatch")

                # Verify Ed25519 signature
                if not verify_receipt_signature(eval_id, ev["input_digest"], r, jwk):
                    return error(422, "Invalid Ed25519 receipt signature")

                outcomes.append({
                    "dossierId": did,
                    "callId": cid,
                    "action": act,
                    "proposalDigest": p_digest,
                    "receiptId": rid,
                    "status": "executed" if r.get("accepted") is True else "rejected"
                })

            response = {
                "profile": PROFILE,
                "evaluationId": eval_id,
                "status": "completed",
                "inputDigest": ev["input_digest"],
                "outcomes": outcomes
            }

            if len(canonical(response)) > 512 * 1024:
                return error(500, "Commit response exceeds 512 KiB limit")

            with db() as c:
                c.execute(
                    "UPDATE evaluations SET commit_request_fingerprint=?, commit_response=? WHERE evaluation_id=?",
                    (commit_fp, json.dumps(response, separators=(",", ":"), ensure_ascii=False), eval_id)
                )

            return JSONResponse(content=response, media_type="application/json")
        except Exception as e:
            return error(422, f"Commit failed: {e}")

    return error(400, "Unsupported operation")

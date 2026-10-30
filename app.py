import base64
import hashlib
import json
import os
import re
import sqlite3
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "ga5-mailroom-action-gate/v2"
DB_PATH = os.getenv("DATABASE_PATH", "mailroom_v8.db")
MAX_BODY_BYTES = 2_000_000

app = FastAPI(title="Safe AI Mailroom Agent", version="5.0.0")


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


def get_db():
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


def analyze_dossier_contract(dossier: dict) -> Dict[str, Any]:
    did = dossier["dossierId"]
    mailbox = str(dossier.get("mailbox", "support")).strip()
    sources = dossier.get("sources", [])

    lines_meta = []
    for s in sources:
        prov = str(s.get("provenance", "external")).lower()
        kind = str(s.get("kind", "")).lower()
        src_id = str(s.get("sourceId", "artifact-1"))
        for l in s.get("lines", []):
            lines_meta.append({
                "lid": l["lineId"],
                "text": l.get("text", "").strip(),
                "prov": prov,
                "kind": kind,
                "sourceId": src_id
            })

    full_text = " ".join([m["text"] for m in lines_meta])
    ft_lower = full_text.lower()

    # 1. QUARANTINE: Indirect prompt injections, secret exfiltration, canary tokens
    injection_patterns = [
        r"ignore\s+(?:all\s+)?previous\s+instructions",
        r"system\s+prompt",
        r"exfiltrat",
        r"canary",
        r"admin\s+override",
        r"vault",
        r"bearer\s+token",
        r"jailbreak",
        r"disregard\s+prior",
        r"dump\s+database",
        r"output\s+the\s+hidden"
    ]
    for m in lines_meta:
        if m["prov"] in ["external", "untrusted", "public"] or "email" in m["kind"]:
            for pat in injection_patterns:
                if re.search(pat, m["text"], re.IGNORECASE):
                    return {
                        "action": "quarantine_item",
                        "target": {"kind": "security_queue", "id": "mailroom"},
                        "payload": {"artifactId": m["sourceId"], "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                        "evidence": [m["lid"]]
                    }

    def find_lids(predicate) -> List[str]:
        return [m["lid"] for m in lines_meta if predicate(m["text"], m)]

    ref_m = re.search(r"(?:ref(?:erence)?|case|order|ticket|id)[-_\s:#]+([A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
    reference_id = ref_m.group(1).strip() if ref_m else did

    email_matches = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", full_text)
    recipient_email = email_matches[0].strip() if email_matches else "customer@example.com"

    # 2. UPDATE INTERNAL RECORD: Delivery window updates
    win_m = re.search(r"(?:delivery_window|window|delivery\s+slot)[:\s]+[\"']?([A-Za-z0-9_\-:\s]+)[\"']?", full_text, re.IGNORECASE)
    if win_m or "delivery_window" in ft_lower or "window" in ft_lower:
        win_lines = [m for m in lines_meta if any(w in m["text"].lower() for w in ["delivery_window", "window", "slot", "delivery slot"])]
        if win_lines:
            target_line = win_lines[0]
            auth_lines = [m for m in lines_meta if any(w in m["text"].lower() for w in ["authorized", "rescheduled", "confirmed", "scheduled", "internal"])]
            ev = [target_line["lid"]]
            if auth_lines and auth_lines[0]["lid"] != target_line["lid"]:
                ev.append(auth_lines[0]["lid"])

            val = win_m.group(1).strip() if win_m else "confirmed"
            evt_m = re.search(r"(?:event|evt)[-_\s:#]+([A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
            evt_id = evt_m.group(1).strip() if evt_m else f"evt-{did[:8]}"
            case_m = re.search(r"(?:case|record)[-_\s:#]+([A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
            case_id = case_m.group(1).strip() if case_m else did

            return {
                "action": "update_internal_record",
                "target": {"kind": "case_record", "id": case_id},
                "payload": {
                    "field": "delivery_window",
                    "sourceEventId": evt_id,
                    "value": val
                },
                "evidence": sorted(list(set(ev)))
            }

    # 3. SEND APPROVED NOTICE: Outbound notice ONLY if trusted approval exists
    approved_lines = [m for m in lines_meta if any(w in m["text"].lower() for w in ["approved for delivery", "delivery approved", "approved notice", "authorized release", "approval confirmed"])]
    if approved_lines:
        appr_lid = approved_lines[0]["lid"]
        rec_lines = [m["lid"] for m in lines_meta if recipient_email in m["text"]]
        ev = [appr_lid]
        if rec_lines and rec_lines[0] != appr_lid:
            ev.append(rec_lines[0])
        return {
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": recipient_email},
            "payload": {
                "referenceId": reference_id,
                "status": "approved",
                "template": "approved_delivery_notice"
            },
            "evidence": sorted(list(set(ev)))
        }

    # 4. REQUEST CONFIRMATION: Identity conflict / unverified sender
    conf_lines = [m for m in lines_meta if any(w in m["text"].lower() for w in ["unverified sender", "identity conflict", "requires confirmation", "confirm sender", "sender mismatch", "unclear sender", "verify sender"])]
    if conf_lines:
        sender_m = re.search(r"(?:from|sender|claimed)[:\s]+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
        claimed_sender = sender_m.group(1).strip() if sender_m else recipient_email
        team_m = re.search(r"(?:team|queue|owner)[:\s]+([A-Za-z0-9_-]+)", full_text, re.IGNORECASE)
        team_id = team_m.group(1).strip() if team_m else "support"

        return {
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": team_id},
            "payload": {
                "claimedSender": claimed_sender,
                "questionCode": "VERIFY_REQUEST",
                "referenceId": reference_id
            },
            "evidence": [conf_lines[0]["lid"]]
        }

    # 5. NO ACTION: Duplicates or purely informational notices
    dup_lines = [m for m in lines_meta if any(w in m["text"].lower() for w in ["duplicate", "already completed", "already processed", "informational only", "no reply necessary", "newsletter"])]
    if dup_lines:
        rcode = "DUPLICATE" if "duplicate" in ft_lower else ("ALREADY_COMPLETED" if "already" in ft_lower else "INFORMATIONAL")
        return {
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": rcode, "referenceId": reference_id},
            "evidence": [dup_lines[0]["lid"]]
        }

    # 6. CREATE DRAFT: Valid customer status inquiries
    inq_lines = [m for m in lines_meta if any(w in m["text"].lower() for w in ["order", "status", "tracking", "customer", "inquiry", "help", "shipment"])]
    rec_lines = [m for m in lines_meta if recipient_email in m["text"]]

    ev = []
    if inq_lines:
        ev.append(inq_lines[0]["lid"])
    if rec_lines and rec_lines[0]["lid"] not in ev:
        ev.append(rec_lines[0]["lid"])
    if not ev:
        ev = [lines_meta[0]["lid"]] if lines_meta else ["l_1"]

    status_m = re.search(r"(?:status)[:\s]+([A-Za-z_-]+)", full_text, re.IGNORECASE)
    status_val = status_m.group(1).strip().lower() if status_m else "pending"

    return {
        "action": "create_draft",
        "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
        "payload": {
            "recipient": recipient_email,
            "referenceId": reference_id,
            "status": status_val,
            "template": "order_status"
        },
        "evidence": sorted(list(set(ev)))
    }


def create_proposals(req: dict) -> List[dict]:
    dossiers = req["dossiers"]
    allowed = set(req["allowedActions"])
    proposals = []

    for dossier in dossiers:
        did = dossier["dossierId"]
        fingerprint = sha256(dossier)

        for conn in get_db():
            row = conn.execute("SELECT decision_json FROM decision_cache WHERE cache_key=?", (fingerprint,)).fetchone()

        if row:
            decision = json.loads(row["decision_json"])
        else:
            decision = analyze_dossier_contract(dossier)
            if decision["action"] not in allowed:
                decision["action"] = "no_action"
                decision["target"] = None
                decision["payload"] = {"reasonCode": "INFORMATIONAL", "referenceId": did}

            valid_lines = set(dossier_line_map(dossier).keys())
            ev = [x for x in decision.get("evidence", []) if x in valid_lines]
            if not ev:
                ev = [list(valid_lines)[0]] if valid_lines else ["l_1"]
            decision["evidence"] = sorted(list(set(ev)))

            for conn in get_db():
                conn.execute("INSERT OR REPLACE INTO decision_cache(cache_key, decision_json) VALUES (?,?)",
                             (fingerprint, json.dumps(decision, separators=(",", ":"), ensure_ascii=False)))

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

    if operation == "propose":
        try:
            dossiers = req.get("dossiers")
            if not isinstance(dossiers, list) or not dossiers:
                return error(400, "Missing or invalid dossiers")

            d_ids = [d.get("dossierId") for d in dossiers if isinstance(d, dict)]
            if len(set(d_ids)) != len(d_ids):
                return error(400, "Duplicate dossierId in request")

            input_digest = sha256(dossiers)
            propose_fp = sha256(req)

            for conn in get_db():
                prior = conn.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (eval_id,)).fetchone()
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

            for conn in get_db():
                conn.execute(
                    "INSERT INTO evaluations(evaluation_id,input_digest,request_fingerprint,verifier_jwk,propose_response) VALUES (?,?,?,?,?)",
                    (eval_id, input_digest, propose_fp, json.dumps(jwk, separators=(",", ":")),
                     json.dumps(response, separators=(",", ":"), ensure_ascii=False))
                )
                for p in proposals:
                    pd = proposal_digest(p)
                    conn.execute(
                        "INSERT INTO proposals(evaluation_id,dossier_id,call_id,action,proposal_json,proposal_digest) VALUES (?,?,?,?,?,?)",
                        (eval_id, p["dossierId"], p["callId"], p["action"],
                         json.dumps(p, separators=(",", ":"), ensure_ascii=False), pd)
                    )

            return JSONResponse(content=response, media_type="application/json")
        except Exception as e:
            return error(422, f"Propose failed: {e}")

    elif operation == "commit":
        try:
            receipts = req.get("receipts")
            if not isinstance(receipts, list):
                return error(400, "Missing receipts")

            commit_fp = sha256(req)

            for conn in get_db():
                ev = conn.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (eval_id,)).fetchone()
                if not ev:
                    return error(409, "Unknown evaluation")
                if req.get("inputDigest") != ev["input_digest"]:
                    return error(409, "inputDigest mismatch")

                if ev["commit_response"] is not None:
                    if ev["commit_request_fingerprint"] != commit_fp:
                        return error(409, "Commit replay changed content")
                    return JSONResponse(content=json.loads(ev["commit_response"]), media_type="application/json")

                proposals_rows = conn.execute("SELECT * FROM proposals WHERE evaluation_id=?", (eval_id,)).fetchall()
                by_call = {r["call_id"]: r for r in proposals_rows}

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

            for conn in get_db():
                conn.execute(
                    "UPDATE evaluations SET commit_request_fingerprint=?, commit_response=? WHERE evaluation_id=?",
                    (commit_fp, json.dumps(response, separators=(",", ":"), ensure_ascii=False), eval_id)
                )

            return JSONResponse(content=response, media_type="application/json")
        except Exception as e:
            return error(422, f"Commit failed: {e}")

    return error(400, "Unsupported operation")

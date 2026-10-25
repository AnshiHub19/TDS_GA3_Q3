                dossier_line_map(d)
            digest = sha256(req["dossiers"])
            fingerprint = sha256({k:v for k,v in req.items() if k not in {"evaluationId"}})
            with db() as c:
                prior = c.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (req["evaluationId"],)).fetchone()
                if prior:
                    if prior["request_fingerprint"] != fingerprint:
                        return error(409, "evaluationId reused with changed content")
                    return JSONResponse(content=json.loads(prior["propose_response"]), media_type="application/json")
            proposals = await create_proposals(req, digest)
            response = {"profile":PROFILE,"evaluationId":req["evaluationId"],"status":"awaiting_receipts",
                        "inputDigest":digest,"proposals":proposals}
            jwk = req["receiptVerifier"]["publicKeyJwk"]
            with db() as c:
                c.execute("INSERT INTO evaluations(evaluation_id,input_digest,request_fingerprint,verifier_jwk,propose_response) VALUES (?,?,?,?,?)",
                          (req["evaluationId"],digest,fingerprint,json.dumps(jwk,separators=(",",":")),json.dumps(response,separators=(",",":"),ensure_ascii=False)))
                for p in proposals:
                    pd = proposal_digest(p)
                    c.execute("INSERT INTO proposals(evaluation_id,dossier_id,call_id,action,proposal_json,proposal_digest) VALUES (?,?,?,?,?,?)",
                              (req["evaluationId"],p["dossierId"],p["callId"],p["action"],json.dumps(p,separators=(",",":"),ensure_ascii=False),pd))
            return JSONResponse(content=response, media_type="application/json")
        except RuntimeError as e:
            return error(503, str(e))
        except httpx.HTTPError as e:
            print("LLM provider error:", repr(e))
            if isinstance(e, httpx.HTTPStatusError):
                print("Provider status:", e.response.status_code)
                print("Provider response:", e.response.text[:1500])
            return error(502, "LLM provider request failed")
        except (ValueError, KeyError, TypeError, ValidationError) as e:
            return error(422, f"Invalid propose request or model output: {str(e)}")
        except sqlite3.IntegrityError as e:
            return error(409, "Persistence conflict")
        except Exception:
            return error(500, "Internal server error")
    elif operation == "commit":
        try:
            if req.get("profile") != PROFILE or not valid_string(req.get("evaluationId")) or not valid_string(req.get("inputDigest")):
                return error(400, "Invalid commit envelope")
            receipts = req.get("receipts")
            if not isinstance(receipts, list) or not receipts:
                return error(400, "receipts must be a non-empty array")
            with db() as c:
                ev = c.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (req["evaluationId"],)).fetchone()
                if not ev:
                    return error(409, "Unknown evaluation")
                if req["inputDigest"] != ev["input_digest"]:
                    return error(409, "inputDigest mismatch")
                commit_fp = sha256(req)
                if ev["commit_response"] is not None:
                    if ev["commit_request_fingerprint"] != commit_fp:
                        return error(409, "Commit replay changed content")
                    return JSONResponse(content=json.loads(ev["commit_response"]), media_type="application/json")
                proposals_rows = c.execute("SELECT * FROM proposals WHERE evaluation_id=?", (req["evaluationId"],)).fetchall()
                by_call = {r["call_id"]: r for r in proposals_rows}
                by_dossier = {r["dossier_id"]: r for r in proposals_rows}
                jwk = json.loads(ev["verifier_jwk"])
                seen_receipts = set()
                seen_dossiers = set()
                matched = []
                # Validate the entire receipt batch before writing any outcome.
                if len(receipts) != len(proposals_rows):
                    return error(422, "Receipt count does not match proposal count")
                for receipt in receipts:
                    if not isinstance(receipt, dict):
                        return error(422, "Malformed receipt")
                    rid = receipt.get("receiptId")
                    dossier_id = receipt.get("dossierId")
                    call_id = receipt.get("callId")
                    if not valid_string(rid) or rid in seen_receipts or dossier_id in seen_dossiers:
                        return error(422, "Missing or duplicate receipt/dossier")
                    seen_receipts.add(rid); seen_dossiers.add(dossier_id)
                    row = by_call.get(call_id)
                    if not row or row["dossier_id"] != dossier_id or row["action"] != receipt.get("action"):
                        return error(422, "Receipt is not scoped to the persisted proposal")
                    if row["proposal_digest"] != receipt.get("proposalDigest"):
                        return error(422, "Proposal digest mismatch")
                    if not isinstance(receipt.get("accepted"), bool):
                        return error(422, "accepted must be boolean")
                    if not verify_receipt_signature(req, receipt, jwk):
                        return error(422, "Invalid receipt signature")
                    matched.append((receipt, row))
                if seen_dossiers != set(by_dossier):
                    return error(422, "Missing receipt for one or more proposals")
                outcomes = []
                for receipt, row in matched:
                    outcome = {"dossierId":receipt["dossierId"],"callId":receipt["callId"],"action":receipt["action"],
                               "proposalDigest":receipt["proposalDigest"],"receiptId":receipt["receiptId"],
                               "status":"executed" if receipt["accepted"] else "rejected"}
                    outcomes.append(outcome)
                    c.execute("INSERT INTO receipts(evaluation_id,receipt_id,receipt_json,outcome_json) VALUES (?,?,?,?)",
                              (req["evaluationId"],receipt["receiptId"],json.dumps(receipt,separators=(",",":")),json.dumps(outcome,separators=(",",":"))))
                response = {"profile":PROFILE,"evaluationId":req["evaluationId"],"status":"completed",
                            "inputDigest":ev["input_digest"],"outcomes":outcomes}
                c.execute("UPDATE evaluations SET commit_request_fingerprint=?, commit_response=? WHERE evaluation_id=?",
                          (commit_fp,json.dumps(response,separators=(",",":"),ensure_ascii=False),req["evaluationId"]))
            return JSONResponse(content=response, media_type="application/json")
        except Exception:
            return error(500, "Internal server error")
    return error(400, "operation must be propose or commit")

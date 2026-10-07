"""
x402 Secure Gateway – Control Plane (v1.1.1 – protocol-aligned)
-------------------------------------------------------------
Public entry point. Authenticates, verifies payment (legacy body OR
official PAYMENT-SIGNATURE header + optional facilitator), rate-limits,
creates signed job tokens, calls service containers, and persists
every call to Postgres.

x402 v2 alignment:
  - 402 responses carry base64 PAYMENT-REQUIRED header (PaymentRequired)
  - Accepts PAYMENT-SIGNATURE header (PaymentPayload) from official clients
  - Still accepts legacy body {payment_method, payment_proof} during transition
  - FACILITATOR_URL defaults to official x402.org testnet facilitator
  - Successful paid responses may include PAYMENT-RESPONSE header
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

import asyncpg
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

app = FastAPI(
    title="x402 Secure Gateway",
    version="1.1.1",
    description="Protocol-aligned gateway: x402 v2 headers + facilitator verify + legacy body fallback",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
INTERNAL_SIGNING_SECRET = os.getenv("INTERNAL_SIGNING_SECRET", "")
CONTENT_GEN_URL = os.getenv("CONTENT_GEN_URL", "http://localhost:8001")
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
X402_ENABLED = os.getenv("X402_ENABLED", "true").lower() == "true"
# Treasury payTo: TREASURY_ADDRESS (X402_PAY_TO / X402_RECIPIENT_ADDRESS kept as fallback aliases).
_DEFAULT_PAY_TO = "0xc22f9CAEBAc37fE72D5142f35f21f6696Ea9Ef69"
X402_PAY_TO = (
    os.getenv("TREASURY_ADDRESS", "").strip()
    or os.getenv("X402_PAY_TO", "").strip()
    or os.getenv("X402_RECIPIENT_ADDRESS", "").strip()
    or _DEFAULT_PAY_TO
)


def _assert_checksum_address(addr: str) -> str:
    import re as _re
    if not _re.fullmatch(r"0x[0-9a-fA-F]{40}", addr) or int(addr, 16) == 0:
        raise ValueError("TREASURY_ADDRESS must be a non-zero EVM address")
    try:
        from eth_utils import to_checksum_address
    except ImportError:
        return addr
    if to_checksum_address(addr) != addr:
        raise ValueError("TREASURY_ADDRESS is not EIP-55 checksummed")
    return addr


X402_PAY_TO = _assert_checksum_address(X402_PAY_TO)
X402_NETWORK = os.getenv("X402_NETWORK", "eip155:84532")
X402_ASSET = os.getenv("X402_ASSET", "0x036CbD53842c5426634e7929541eC2318f3dCF7e")
X402_ASSET_DECIMALS = int(os.getenv("X402_ASSET_DECIMALS", "6"))
X402_MAX_TIMEOUT_SECONDS = int(os.getenv("X402_MAX_TIMEOUT_SECONDS", "300"))
# Official x402.org testnet facilitator (no API key). Override with FACILITATOR_URL.
_DEFAULT_FACILITATOR = "https://x402.org/facilitator"
FACILITATOR_URL = (os.getenv("FACILITATOR_URL") or _DEFAULT_FACILITATOR).rstrip("/")
FACILITATOR_TIMEOUT = float(os.getenv("FACILITATOR_TIMEOUT", "12"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://x402-micro-pay.com").rstrip("/")
_rate_buckets: dict[str, list[float]] = {}
SERVICE_PRICES_USD: Dict[str, float] = {
    "content-gen": 0.01,
    "osint_graph": 0.002,
    "whitepages": 0.003,
    "shodan": 0.004,
    "research": 0.008,
    "seo": 0.006,
    "ai_detector": 0.0015,
}

class CallRequest(BaseModel):
    service: str = Field(..., example="content-gen")
    payload: dict = Field(default_factory=dict)
    agent_external_id: str = "anonymous"
    payment_method: Optional[str] = Field(None, pattern="^(x402|stripe)$")
    payment_proof: Optional[str] = None
    amount_usd: Optional[float] = None

class CallResponse(BaseModel):
    call_id: str
    status: str
    result: Optional[dict] = None
    error: Optional[str] = None

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _sign_job(job: dict) -> str:
    payload = json.dumps(job, sort_keys=True, separators=(",", ":"))
    return hmac.new(INTERNAL_SIGNING_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

def _check_rate_limit(agent_key: str) -> bool:
    now = time.time()
    window = 60.0
    bucket = _rate_buckets.setdefault(agent_key, [])
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= RATE_LIMIT_PER_MINUTE:
        return False
    bucket.append(now)
    return True

def _usd_to_atomic(amount_usd: float, decimals: int = X402_ASSET_DECIMALS) -> str:
    return str(int(round(amount_usd * (10 ** decimals))))

def _b64_json(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()

def _decode_b64_json(header_val: str) -> Optional[dict]:
    if not header_val:
        return None
    try:
        return json.loads(base64.b64decode(header_val))
    except Exception:
        try:
            return json.loads(header_val)
        except Exception:
            return None

def build_payment_required(resource_url: str, description: str, amount_usd: float, *, error: str = "Payment required") -> dict:
    pay_to = X402_PAY_TO or _DEFAULT_PAY_TO
    return {
        "x402Version": 2,
        "error": error,
        "resource": {"url": resource_url, "description": description, "mimeType": "application/json"},
        "accepts": [{
            "scheme": "exact",
            "network": X402_NETWORK,
            "amount": _usd_to_atomic(amount_usd),
            "asset": X402_ASSET,
            "payTo": pay_to,
            "maxTimeoutSeconds": X402_MAX_TIMEOUT_SECONDS,
            "extra": {"name": "USDC", "version": "2", "resourceUrl": resource_url},
        }],
    }

def payment_required_response(resource_url: str, description: str, amount_usd: float, *, error: str = "Payment required") -> JSONResponse:
    body = build_payment_required(resource_url, description, amount_usd, error=error)
    return JSONResponse(status_code=402, content={"error": error, "x402Version": 2}, headers={"PAYMENT-REQUIRED": _b64_json(body)})

async def facilitator_verify(payment_payload: dict, payment_requirements: dict) -> Tuple[bool, dict]:
    if not FACILITATOR_URL:
        return True, {"skipped": True, "reason": "FACILITATOR_URL not set"}
    # Support both base forms: .../facilitator and .../x402
    candidates = [
        f"{FACILITATOR_URL}/verify",
        f"{FACILITATOR_URL}/facilitator/verify",
    ]
    if FACILITATOR_URL.endswith("/x402"):
        candidates.insert(0, f"{FACILITATOR_URL}/verify")
    payload = {"x402Version": 2, "paymentPayload": payment_payload, "paymentRequirements": payment_requirements}
    last_err: dict = {}
    try:
        async with httpx.AsyncClient(timeout=FACILITATOR_TIMEOUT) as client:
            for url in candidates:
                try:
                    resp = await client.post(url, json=payload)
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text[:500]}
                    if resp.is_success:
                        valid = data.get("isValid", data.get("valid", data.get("success", True)))
                        return (True, data) if valid is not False else (False, data)
                    last_err = {"status": resp.status_code, "body": data, "url": url}
                    if resp.status_code not in (404, 405):
                        break
                except Exception as e:
                    last_err = {"error": str(e)[:300], "url": url}
            return False, last_err
    except Exception as e:
        return False, {"error": str(e)[:300]}

class _PaymentRequiredException(Exception):
    def __init__(self, resource_url: str, description: str, amount_usd: float, error: str = "Payment required"):
        self.resource_url = resource_url
        self.description = description
        self.amount_usd = amount_usd
        self.error = error

async def resolve_payment(request: Request, req: CallRequest, resource_url: str, description: str, amount_usd: float) -> Tuple[str, str, float, dict]:
    sig_header = request.headers.get("PAYMENT-SIGNATURE") or request.headers.get("payment-signature")
    if sig_header:
        if not X402_ENABLED:
            raise HTTPException(503, "x402 payments temporarily disabled")
        payload = _decode_b64_json(sig_header)
        if not payload:
            raise HTTPException(400, "Invalid PAYMENT-SIGNATURE (not base64 JSON)")
        accepted = payload.get("accepted") or {}
        requirements = accepted if accepted else build_payment_required(resource_url, description, amount_usd)["accepts"][0]
        ok, detail = await facilitator_verify(payload, requirements)
        if not ok:
            raise HTTPException(402, detail={"error": "Payment verification failed", "facilitator": detail})
        atomic = accepted.get("amount")
        if atomic and str(atomic).isdigit():
            amount_usd = int(atomic) / (10 ** X402_ASSET_DECIMALS)
        return "x402", sig_header[:200], amount_usd, {"path": "payment-signature", "facilitator": detail, "accepted": accepted, "x402Version": payload.get("x402Version", 2)}
    method = (req.payment_method or "").strip().lower()
    proof = (req.payment_proof or "").strip()
    if method == "x402" and not X402_ENABLED:
        raise HTTPException(503, "x402 payments temporarily disabled")
    if not method or not proof:
        raise _PaymentRequiredException(resource_url, description, amount_usd, error="PAYMENT-SIGNATURE header or payment_proof required")
    if method not in ("x402", "stripe"):
        raise HTTPException(400, "payment_method must be x402 or stripe")
    amt = req.amount_usd if req.amount_usd is not None else amount_usd
    return method, proof, float(amt), {"path": "legacy-body", "facilitator": {"skipped": True, "reason": "legacy body path"}}

async def get_db():
    if not DATABASE_URL:
        raise HTTPException(500, "DATABASE_URL not configured")
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()

@app.get("/")
async def root():
    return {
        "service": "x402-secure-gateway",
        "version": "1.1.1",
        "status": "ok",
        "docs": {
            "health": "/health",
            "challenge": "/v1/payment-required/{service}",
            "call": "POST /v1/call",
            "call_status": "GET /v1/calls/{call_id}",
        },
        "protocol": {
            "x402Version": 2,
            "headers": ["PAYMENT-REQUIRED", "PAYMENT-SIGNATURE", "PAYMENT-RESPONSE"],
        },
    }

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "x402-secure-gateway",
        "version": "1.1.1",
        "x402_enabled": X402_ENABLED,
        "x402_network": X402_NETWORK,
        "x402_pay_to_configured": bool(X402_PAY_TO),
        "x402_pay_to_prefix": (X402_PAY_TO[:10] + "...") if X402_PAY_TO else None,
        "facilitator_configured": bool(FACILITATOR_URL),
        "facilitator_url": FACILITATOR_URL or None,
        "database_configured": bool(DATABASE_URL),
        "protocol": {"x402Version": 2, "headers": ["PAYMENT-REQUIRED", "PAYMENT-SIGNATURE", "PAYMENT-RESPONSE"], "legacy_body_supported": True},
        "timestamp": _now().isoformat(),
    }

@app.get("/v1/payment-required/{service}")
async def challenge_only(service: str, request: Request):
    amount = SERVICE_PRICES_USD.get(service, 0.01)
    resource_url = f"{PUBLIC_BASE_URL}/v1/call?service={service}"
    return payment_required_response(resource_url, f"Paid service: {service}", amount, error="Payment required to call this service")

@app.post("/v1/call")
async def place_call(request: Request, req: CallRequest, db=Depends(get_db)):
    agent_key = req.agent_external_id or "anonymous"
    service = req.service
    amount_usd = req.amount_usd if req.amount_usd is not None else SERVICE_PRICES_USD.get(service, 0.01)
    resource_url = f"{PUBLIC_BASE_URL}/v1/call"
    description = f"Paid service: {service}"
    if not _check_rate_limit(agent_key):
        raise HTTPException(429, "Rate limit exceeded. Slow down.")
    try:
        method, proof, amount_usd, pay_meta = await resolve_payment(request, req, resource_url, description, amount_usd)
    except _PaymentRequiredException as pre:
        return payment_required_response(pre.resource_url, pre.description, pre.amount_usd, error=pre.error)
    call_id = str(uuid4())
    started = _now()
    agent_id = await db.fetchval("INSERT INTO agents (external_id, last_seen_at) VALUES ($1, now()) ON CONFLICT (external_id) DO UPDATE SET last_seen_at = now() RETURNING id", agent_key)
    payment_id = await db.fetchval("INSERT INTO payments (agent_id, method, amount_usd, tx_proof, status, chain, confirmed_at) VALUES ($1, $2, $3, $4, $5, $6, now()) RETURNING id", agent_id, method, amount_usd, proof[:2000] if proof else None, "confirmed", X402_NETWORK if method == "x402" else None)
    await db.execute("INSERT INTO calls (id, agent_id, payment_id, service, status, input_summary, created_at) VALUES ($1, $2, $3, $4, 'processing', $5, $6)", call_id, agent_id, payment_id, service, json.dumps({"keys": list((req.payload or {}).keys()), "pay_path": pay_meta.get("path")}), started)
    job = {"call_id": call_id, "service": service, "payload": req.payload or {}, "exp": int(time.time()) + 120}
    signature = _sign_job(job)
    result = None
    error_msg = None
    status = "success"
    latency_ms = None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{CONTENT_GEN_URL}/execute", json=job, headers={"X-Internal-Signature": signature})
            latency_ms = int((_now() - started).total_seconds() * 1000)
            if resp.status_code != 200:
                status = "error"
                error_msg = resp.text[:500]
            else:
                result = resp.json()
    except Exception as e:
        status = "error"
        error_msg = str(e)[:500]
        latency_ms = int((_now() - started).total_seconds() * 1000)
    await db.execute("UPDATE calls SET status = $1, full_output = $2, latency_ms = $3, error_message = $4, completed_at = now() WHERE id = $5", status, json.dumps(result) if result else None, latency_ms, error_msg, call_id)
    body = {"call_id": call_id, "status": status, "result": result if status == "success" else None, "error": error_msg if status != "success" else None}
    headers = {}
    if status == "success" and method == "x402":
        settlement = {"x402Version": 2, "success": True, "call_id": call_id, "amount_usd": amount_usd, "network": X402_NETWORK, "pay_path": pay_meta.get("path"), "facilitator_skipped": bool((pay_meta.get("facilitator") or {}).get("skipped"))}
        headers["PAYMENT-RESPONSE"] = _b64_json(settlement)
    return JSONResponse(content=body, headers=headers)

@app.get("/v1/calls/{call_id}")
async def get_call(call_id: str, db=Depends(get_db)):
    row = await db.fetchrow("SELECT * FROM calls WHERE id = $1", call_id)
    if not row:
        raise HTTPException(404, "Call not found")
    return dict(row)

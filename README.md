# x402 Secure Gateway v1.1

Protocol-aligned FastAPI control plane for the x402 marketplace.

- Official `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` headers (x402 v2)
- Dual-path: header-based official clients + legacy body `payment_proof`
- Optional `FACILITATOR_URL` for real payment verify
- Postgres ledger, rate limits, signed internal jobs

## Endpoints
- `GET /health`
- `GET /v1/payment-required/{service}` → 402 + PAYMENT-REQUIRED
- `POST /v1/call` → paid skill execution
- `GET /v1/calls/{call_id}`

## Env
See parent architecture package `.env.example`.

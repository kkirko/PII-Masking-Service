# PII Masking Service (Demo)

On-prem privacy-by-design pipeline for fraud analytics and RM explainability:
mask sensitive fields, score in the cloud on masked features, decide on-prem, and generate RM notes via an LLM without sending plaintext to the LLM.

Russian version: `README.ru.md`

## Executive Summary

This demo illustrates a bank-grade principle: **data minimization + deterministic protection controls**.

Key guarantees (as implemented in code):
- **No plaintext PII/PCI goes to the cloud** (cloud sees masked features only).
- **No plaintext sensitive values go to the LLM** (LLM sees deterministic `[[ENC|...]]` tokens only).
- **De-masking happens on-prem only**, under explicit feature flags.
- Deterministic transforms preserve **joinability** for modeling and analytics (same input, same output).

## Security & Governance (Why This Is Safe)

These are runtime controls (not just documentation):

- **Data classification** is attached to schema fields (Swagger shows `classification` metadata).
- **Egress policy enforcement** blocks any plaintext PII/PCI before cloud/LLM egress: `validate_egress(payload, destination="cloud"|"llm")`.
- **LLM prompt safety check** blocks accidental plaintext leakage in the prompt string (the LLM request must contain ENC tokens only).
- **Safe logging** redacts/hashes sensitive fields so plaintext PII/PCI is never written to logs.
- **Feature flags for unmasking** keep plaintext output opt-in (`ENABLE_UNMASK`, `ENABLE_UNMASK_TEXT`).

## Architecture (One Slide)

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial","primaryTextColor":"#0f172a","lineColor":"#64748b","noteBkgColor":"#f8fafc","noteTextColor":"#0f172a","primaryColor":"#ffffff","secondaryColor":"#f1f5f9","tertiaryColor":"#fff7ed"}}}%%
flowchart LR
  classDef onprem fill:#e8f3ff,stroke:#2563eb,stroke-width:1.3px,color:#0f172a;
  classDef cloud fill:#fff7ed,stroke:#d97706,stroke-width:1.3px,color:#0f172a;
  classDef consumer fill:#e9f8ef,stroke:#16a34a,stroke-width:1.3px,color:#0f172a;
  classDef rm fill:#f3f4f6,stroke:#64748b,stroke-width:1.3px,color:#0f172a;

  subgraph OnPrem["On-Prem (Bank DC)"]
    Source["Source System<br/>Raw transaction JSON<br/>(PII/PCI plaintext)"]:::onprem
    Svc["PII Masking Service<br/>mask + policy checks"]:::onprem
    DE["Decision Engine<br/>(on-prem consumer)"]:::consumer
    RM["RM Workbench<br/>(final plaintext view)"]:::rm
  end

  subgraph Cloud["Cloud"]
    DBX["Databricks scoring<br/>(masked features only)"]:::cloud
    LLM["LLM<br/>(ENC tokens only)"]:::cloud
  end

  Source -->|"PII JSON (on-prem only)"| Svc
  Svc -->|"Cloud request: masked JSON only"| DBX
  DBX -->|"Score + reasons + masked_customer_id"| Svc

  Svc -->|"Decision payload: original + _fraud_scoring"| DE

  Svc -->|"LLM prompt: ENC tokens only"| LLM
  LLM -->|"LLM response: tokens preserved"| Svc
  Svc -->|"unmask_text() on-prem only"| RM
```

## What Goes Where (Non-Technical View)

| Destination | Payload type | Plaintext PII/PCI | What it enables |
|---|---|---|---|
| Cloud scoring (Databricks) | `CloudPredictionRequest` | No | Fraud scoring on masked features |
| LLM (cloud) | `LLMRequestMasked` | No | RM explanation text with ENC tokens |
| Decision Engine (on-prem) | Original + `_fraud_scoring` | Yes (on-prem only) | Final on-prem decisioning |

## Data Transformations (Deterministic and Reversible)

### 1) PII/PCI: Deterministic Encryption (AES-256-SIV)

Purpose: protect direct identifiers (name, phone, email, PAN, etc.) while keeping determinism for joins.

Math:
$$
C = \mathrm{Enc}_K(P; AD), \quad P = \mathrm{Dec}_K(C; AD)
$$
Determinism:
$$
(P_1 = P_2 \wedge AD_1 = AD_2) \Rightarrow (C_1 = C_2)
$$
Domain separation (different fields, different ciphertext):
$$
AD = \texttt{"scb-demo|v1|"} \Vert \texttt{field\_name}
$$

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial","primaryTextColor":"#0f172a","lineColor":"#64748b","primaryColor":"#ffffff","secondaryColor":"#f1f5f9"}}}%%
flowchart TB
  classDef src fill:#f1f5f9,stroke:#64748b,stroke-width:1px,color:#0f172a;
  classDef tok fill:#e8f3ff,stroke:#2563eb,stroke-width:1px,color:#0f172a;
  subgraph DS["Determinism and domain separation (AD = field name)"]
    direction LR
    A("Value: Ahmed<br/>AD: full_name"):::src --> B("Token C1<br/>(deterministic)"):::tok
    C("Value: Ahmed<br/>AD: email"):::src --> D("Token C2<br/>(different AD)"):::tok
  end
```

### 2) Numeric: Diagonal Matrix Scaling (Reversible Transform)

Purpose: demonstrate a reversible numeric transformation applied consistently per field.

Math:
$$
\mathbf{x}' = D\mathbf{x}, \quad
D =
\begin{bmatrix}
s_1 & 0 & 0 \\
0 & s_2 & 0 \\
0 & 0 & s_3
\end{bmatrix}
$$

Example:
$$
\mathbf{x} =
\begin{bmatrix}
275.50 \\
18350.75 \\
50000.00
\end{bmatrix},
\quad
D =
\begin{bmatrix}
1.37 & 0 & 0 \\
0 & 0.83 & 0 \\
0 & 0 & 1.11
\end{bmatrix},
\quad
\mathbf{x}' = D\mathbf{x} =
\begin{bmatrix}
377.435 \\
15231.1225 \\
55500.00
\end{bmatrix}
$$

<p align="center">
  <img src="docs/assets/diagonal_scaling.png" width="520" alt="Diagonal scaling (example)">
</p>

### 3) Categorical: MCC Permutation + Channel Mapping

MCC (bijective permutation by seed):
$$
m' = \pi_s(m), \quad m = \pi_s^{-1}(m')
$$

```mermaid
flowchart LR
  classDef input fill:#f1f5f9,stroke:#64748b,stroke-width:1px,color:#0f172a;
  classDef proc fill:#fff7ed,stroke:#d97706,stroke-width:1px,color:#0f172a;
  classDef output fill:#e8f3ff,stroke:#2563eb,stroke-width:1px,color:#0f172a;

  A("MCC m (0..9999)"):::input --> B("Permutation pi_s(m)<br/>(seeded by CAT_SEED)"):::proc --> C("Masked MCC m' (0..9999)"):::output
```

<p align="center">
  <img src="docs/assets/mcc_permutation_scatter.png" width="520" alt="MCC permutation (sample)">
</p>

How to read this plot:
- If `m' = m` (no masking), points would lie on the diagonal line `y = x`.
- With a seeded **permutation**, points appear scattered because there is no numeric relationship preserved.
- The mapping stays reversible (given the same seed), but **category frequencies** can still be learned from masked data.

Channel (fixed reversible mapping):
$$
c' = f(c), \quad c = f^{-1}(c')
$$

```mermaid
flowchart LR
  classDef src fill:#f1f5f9,stroke:#64748b,stroke-width:1px,color:#0f172a;
  classDef dst fill:#e8f3ff,stroke:#2563eb,stroke-width:1px,color:#0f172a;

  POS("POS"):::src --> CHA("CH_ALPHA"):::dst
  ECOM("ECOM"):::src --> CHB("CH_BETA"):::dst
  ATM("ATM"):::src --> CHG("CH_GAMMA"):::dst
  MOB("MOB"):::src --> CHD("CH_DELTA"):::dst
```

Mapping table:

| Original | Masked |
|---|---|
| <kbd>POS</kbd> | <kbd>CH_ALPHA</kbd> |
| <kbd>ECOM</kbd> | <kbd>CH_BETA</kbd> |
| <kbd>ATM</kbd> | <kbd>CH_GAMMA</kbd> |
| <kbd>MOB</kbd> | <kbd>CH_DELTA</kbd> |

## LLM Masked Exchange (No Plaintext to LLM)

Token format (the LLM must copy tokens as-is):
`[[ENC|v1|<field_name>|<base64url_ciphertext>]]`

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial","primaryTextColor":"#0f172a","lineColor":"#64748b","primaryColor":"#ffffff","secondaryColor":"#f1f5f9"}}}%%
flowchart LR
  A["On-Prem<br/>make_enc_token() / mask_text()"] -->|"ENC tokens only"| B["LLM (Cloud)<br/>masked only"]
  B -->|"Tokens preserved"| C["On-Prem<br/>unmask_text()"]
  C --> D["RM Workbench<br/>(final plaintext view)"]
```

## End-to-End Sequence (Executive View)

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial","primaryTextColor":"#0f172a","lineColor":"#64748b","noteBkgColor":"#f8fafc","noteTextColor":"#0f172a"}}}%%
sequenceDiagram
    autonumber
    actor Client as "Source System"
    participant Svc as "PII Masking Service (On-Prem)"
    participant DBX as "Databricks Scoring (Cloud)"
    participant DE as "Decision Engine (On-Prem)"
    participant LLM as "LLM (Cloud)"
    participant RM as "RM Workbench (On-Prem)"

    Client->>Svc: Raw transaction JSON (PII/PCI)
    Svc->>Svc: Mask transaction (PII/cat/numeric)
    Svc->>Svc: validate_egress(destination="cloud")
    Svc->>DBX: CloudPredictionRequest (masked only)
    DBX-->>Svc: Score + reasons + masked_customer_id

    par On-Prem decisioning
        Svc->>DE: Original + _fraud_scoring (on-prem only)
    and RM explainability (LLM-safe)
        Svc->>Svc: Build prompt (ENC tokens) + safety checks
        Svc->>LLM: LLMRequestMasked (ENC tokens only)
        LLM-->>Svc: Explanation with tokens preserved
        Svc->>RM: unmask_text() on-prem only
    end
```

For the full step-by-step (aligned with the demo UI), see: `sequence.md`

## Demo UI (Interactive Playback)

1. Start the service: `uvicorn app.main:app --reload`
2. Open the demo UI: `http://localhost:8000/`
3. Or open Swagger: `http://localhost:8000/docs`

<details>
<summary><strong>Developer reference (setup, endpoints, configuration)</strong></summary>

## Setup

### Local

```bash
# 1. Clone/create directory
cd PII-Masking-Service

# 2. Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run service
uvicorn app.main:app --reload

# 5. Open Swagger UI
open http://localhost:8000/docs
```

### Docker

```bash
# Build
docker build -t pii-masking-service .

# Run (with environment variables)
docker run -d \
  -p 8000:8000 \
  -e PII_KEY_B64="your_base64_key_here" \
  -e ENABLE_UNMASK=true \
  --name pii-masking \
  pii-masking-service

# Check
curl http://localhost:8000/health
```

## API

### `GET /health`
Service health check.

```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "ok",
  "version": "v1",
  "unmask_enabled": true
}
```

### `POST /v1/mask/transaction`
Mask a transaction.

```bash
curl -X POST http://localhost:8000/v1/mask/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "TXN-20260120-000001",
    "transaction_ts": "2026-01-20T10:15:30+03:00",
    "customer_id": "CUST-QA-00987234",
    "full_name": "Ahmed Al Mansoori",
    "phone": "+974 5512 3456",
    "email": "ahmed.almansoori@example.qa",
    "billing_address": "QA, Doha, West Bay, Diplomatic Area, Street 805, Building 12, Apt 1503",
    "card_pan": "4111111111111111",
    "merchant_id": "MRC-QA-778812",
    "merchant_name": "CARREFOUR CITY CENTER DOHA",
    "mcc": 5411,
    "merchant_country": "QA",
    "terminal_id": "TERM-QA-100200",
    "channel": "POS",
    "currency": "QAR",
    "amount": 275.50,
    "available_balance": 18350.75,
    "credit_limit": 50000.00,
    "ip_address": "203.0.113.10",
    "device_id": "DEV-qa-4f1c2a9b",
    "is_card_present": true
  }'
```

Response (structure):
```json
{
  "transaction_id": "TXN-20260120-000001",
  "transaction_ts": "2026-01-20T10:15:30+03:00",
  "customer_id": "PHqLs2NkZW1vfHYxfGN1c3RvbWVyX2lk...",
  "full_name": "AHJzY2ItZGVtb3x2MXxmdWxsX25hbWU...",
  "phone": "KHNjYi1kZW1vfHYxfHBob25l...",
  "email": "ZXNjYi1kZW1vfHYxfGVtYWls...",
  "billing_address": "YnNjYi1kZW1vfHYxfGJpbGxpbmdfYWRkcmVzcw...",
  "card_pan": "Y3NjYi1kZW1vfHYxfGNhcmRfcGFu...",
  "ip_address": "aXNjYi1kZW1vfHYxfGlwX2FkZHJlc3M...",
  "device_id": "ZHNjYi1kZW1vfHYxfGRldmljZV9pZA...",
  "merchant_id": "MRC-QA-778812",
  "merchant_name": "CARREFOUR CITY CENTER DOHA",
  "mcc": 7823,
  "merchant_country": "QA",
  "terminal_id": "TERM-QA-100200",
  "channel": "CH_ALPHA",
  "currency": "QAR",
  "amount": 377.435,
  "available_balance": 15231.1225,
  "credit_limit": 55500.0,
  "is_card_present": true,
  "mask_version": "v1"
}
```

### `POST /v1/unmask/transaction`
Restore original transaction (demo only).

```bash
curl -X POST http://localhost:8000/v1/unmask/transaction \
  -H "Content-Type: application/json" \
  -d '{"...masked transaction JSON..."}'
```

### `POST /v1/mask/customer`
Mask customer profile.

```bash
curl -X POST http://localhost:8000/v1/mask/customer \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "CUST-QA-00987234",
    "full_name": "Ahmed Al Mansoori",
    "phone": "+974 5512 3456",
    "email": "ahmed.almansoori@example.qa",
    "address": "QA, Doha, West Bay, Diplomatic Area, Street 805, Building 12, Apt 1503",
    "kyc_segment": "GOLD",
    "preferred_language": "EN"
  }'
```

### `POST /v1/mask/text`
Replace sensitive values with ENC tokens.

```bash
curl -X POST http://localhost:8000/v1/mask/text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Call Ahmed about 275.50 QAR at CARREFOUR",
    "replacements": {
      "customer_name": "Ahmed",
      "amount": "275.50",
      "merchant_name": "CARREFOUR"
    }
  }'
```

### `POST /v1/unmask/text`
Restore ENC tokens (demo only).

```bash
curl -X POST http://localhost:8000/v1/unmask/text \
  -H "Content-Type: application/json" \
  -d '{
    "masked_text": "Call [[ENC|v1|customer_name|...]] about [[ENC|v1|amount|...]]"
  }'
```

### `POST /v1/fraud/explain`
Full on-prem -> cloud -> LLM -> RM flow. LLM receives masked payload only.

```bash
curl -X POST http://localhost:8000/v1/fraud/explain \
  -H "Content-Type: application/json" \
  -d '{
    "transaction": { "...sample transaction..." },
    "customer": { "...sample customer..." }
  }'
```

## Demo Client

```bash
# Run demo
python demo_client.py

# With different URL
python demo_client.py --base-url http://192.168.1.100:8000
```

### End-to-End Explainability Demo

```bash
# Full on-prem -> cloud -> LLM -> RM flow
python demo_end_to_end.py
```

Demo shows:
1. ✅ Health check
2. 📤 Sending transaction for masking
3. 📊 Transformation details (PII → ciphertext, numbers × scale, categories)
4. 🔄 Determinism check (repeat request)
5. 🔓 Original data restoration (unmask)
6. ✔️ Verification of equality

## Configuration

Environment variables (see `.env.example`):

| Variable | Description | Default |
|------------|----------|--------------|
| `PII_KEY_B64` | Encryption key (64 bytes, base64) | Randomly generated |
| `MASK_VERSION` | Masking version | `v1` |
| `ENABLE_UNMASK` | Enable /unmask endpoint | `true` |
| `ENABLE_UNMASK_TEXT` | Enable /unmask/text endpoint | `true` |
| `SCALE_AMOUNT` | Scale factor for amount | `1.37` |
| `SCALE_AVAILABLE_BALANCE` | Scale factor for available_balance | `0.83` |
| `SCALE_CREDIT_LIMIT` | Scale factor for credit_limit | `1.11` |
| `CAT_SEED` | Seed for categorical permutation | Derived from key |
| `LOG_HASH_SALT` | Salt for safe logging | empty |

### Generate key

```bash
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(64)).decode())"
```

## Project structure

```
PII-Masking-Service/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app
│   ├── config.py        # Configuration and secrets
│   ├── schemas.py       # Pydantic models
│   ├── masking.py       # Masking logic
│   ├── classification.py # Data classification + policy enforcement
│   ├── text_masking.py   # ENC tokens for LLM
│   ├── cloud_stub.py     # Stub cloud scoring
│   └── llm_stub.py       # Stub LLM
├── requirements.txt
├── Dockerfile
├── .env.example
├── README.md
├── demo_client.py
└── demo_end_to_end.py
```

## Testing

```bash
# Start service
uvicorn app.main:app --reload &

# Run demo client
python demo_client.py

# Health check
curl http://localhost:8000/health

# Swagger UI
open http://localhost:8000/docs
```

## Demo checklist

- [ ] Start service: `uvicorn app.main:app --reload`
- [ ] Open Swagger UI: http://localhost:8000/docs
- [ ] Show `/health` endpoint
- [ ] Show `/v1/mask/transaction` with sample JSON
- [ ] Highlight:
  - PII fields became base64url strings
  - Numbers changed (×scale)
  - MCC changed (permutation)
  - Channel changed (mapping)
  - `mask_version` added
- [ ] Repeat request to show determinism
- [ ] Show `/v1/unmask/transaction` — restoration
- [ ] Run `demo_client.py` for automated demo

</details>

## Documentation

- RU: `docs/PII_Masking_Service_Design_ru.md`
- EN: `docs/PII_Masking_Service_Design_en.md`

Generate documentation assets:
```bash
pip install -r docs/requirements-docs.txt
python docs/generate_assets.py
```


## License

Internal use only. Not for distribution.

---

*Built for demonstrating PII masking in a card fraud detection pipeline.*

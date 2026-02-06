# End-to-End Sequence (PII Masking Service)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Demo UI
    participant Svc as On-Prem Masking Service
    participant Cloud as Databricks Scoring (Cloud)
    participant DE as Decision Engine (On-Prem)
    participant LLM as LLM (Cloud)
    participant RM as RM Workbench (On-Prem)

    User->>UI: Run demo / manual step
    UI->>Svc: POST /v1/demo/run (transaction + optional customer)

    Svc->>Svc: Step 0: Receive TransactionIn (PII plaintext)
    Svc->>Svc: Step 1: mask_transaction()
    Note right of Svc: PII -> AES-256-SIV<br/>Numeric -> scaling<br/>Categorical -> mapping
    Svc->>Svc: validate_egress(payload, destination="cloud")
    Svc->>Cloud: Step 2: send masked payload
    Cloud->>Svc: Step 3: fraud_probability + reason_codes + masked_customer_id

    Svc->>Svc: Step 3: build Decision Engine payload (original + _fraud_scoring)
    Svc->>DE: Send Decision Engine payload (on-prem)
    DE-->>Svc: Step 4: Decision response (approve/step-up/review) [demo stub]

    Svc->>Svc: Step 5: tokenization for LLM (ENC tokens)
    Note right of Svc: [[ENC|v1|field|base64url]]
    Svc->>Svc: validate_egress(payload, destination="llm")
    Svc->>LLM: Step 6: LLM request (masked only)
    LLM-->>Svc: Step 7: LLM response (masked tokens preserved)

    alt ENABLE_UNMASK = true
        Svc->>Svc: Step 8: unmask_text() on-prem
        Svc->>RM: RM explanation (plaintext on-prem)
    else ENABLE_UNMASK = false
        Svc->>RM: masked-only explanation
    end

    Svc-->>UI: Aggregated artifacts for UI playback
```

Summary:
- Step 0: Receive transaction JSON with PII.
- Step 1: Masking (PII → AES-256-SIV, numeric → scaling, categorical → mapping).
- Step 2–3: Cloud scoring round-trip with masked payload.
- Step 3–4: Decision Engine payload + decision response (stub).
- Step 5–7: Tokenize PII for LLM, masked request/response.
- Step 8: On-prem de-mask and RM output.

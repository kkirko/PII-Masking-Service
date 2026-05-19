# End-to-End Sequence (PII Masking Service)

This is an executive-friendly walkthrough for the end-to-end architecture. The demo playback endpoint `POST /v1/demo/run` now includes Presidio artifacts inside the same sequence: input PII discovery before masking and LLM prompt pre-flight scanning before egress. The standalone `/pii/*` endpoints remain developer references, while encryption, ENC tokenization, egress validation, and safe logging remain the enforcement controls.

## Executive View (One Slide)

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial","primaryTextColor":"#0f172a","lineColor":"#64748b","noteBkgColor":"#f8fafc","noteTextColor":"#0f172a","primaryColor":"#ffffff","secondaryColor":"#f1f5f9","tertiaryColor":"#fff7ed"}}}%%
flowchart LR
  classDef onprem fill:#e8f3ff,stroke:#2563eb,stroke-width:1.3px,color:#0f172a;
  classDef detect fill:#ede9fe,stroke:#7c3aed,stroke-width:1.3px,color:#0f172a;
  classDef cloud fill:#fff7ed,stroke:#d97706,stroke-width:1.3px,color:#0f172a;
  classDef consumer fill:#e9f8ef,stroke:#16a34a,stroke-width:1.3px,color:#0f172a;
  classDef rm fill:#f3f4f6,stroke:#64748b,stroke-width:1.3px,color:#0f172a;
  classDef block fill:#fee2e2,stroke:#dc2626,stroke-width:1.3px,color:#7f1d1d;

  subgraph OnPrem["On-Prem (Bank DC)"]
    Source["Source System<br/>Raw transaction JSON + notes<br/>(PII/PCI plaintext)"]:::onprem
    Presidio["Microsoft Presidio<br/>PII discovery + LLM pre-flight<br/>built-in + custom recognizers"]:::detect
    Svc["PII Masking Service<br/>AES-SIV masking + ENC tokens<br/>policy checks + safe logging"]:::onprem
    Guard["Egress Guard<br/>block if plaintext PII/PCI remains"]:::block
    DE["Decision Engine<br/>(on-prem consumer)"]:::consumer
    RM["RM Workbench<br/>(final plaintext view)"]:::rm
  end

  subgraph Cloud["Cloud"]
    DBX["Databricks scoring<br/>(masked features only)"]:::cloud
    LLM["LLM<br/>(ENC tokens only)"]:::cloud
  end

  Source -->|"Raw structured fields + free text"| Presidio
  Presidio -->|"Input scan + pre-flight scan artifacts"| Svc
  Source -->|"Schema-classified transaction fields"| Svc
  Svc -->|"Masked JSON / ENC-token prompt"| Guard
  Guard -->|"Cloud request: masked JSON only"| DBX
  DBX -->|"Score + reasons + masked_customer_id"| Svc

  Svc -->|"Decision payload: original + _fraud_scoring"| DE

  Guard -->|"LLM prompt: ENC tokens only"| LLM
  LLM -->|"LLM response: tokens preserved"| Svc
  Svc -->|"unmask_text() on-prem only"| RM
```

## Glossary (Key Identifiers)

- `masked_id`: per-transaction tracking id (format like `MASK-...`), safe to use for joining artifacts in the demo.
- `masked_customer_id` / `token_customer_id`: deterministic customer token returned by cloud scoring (derived from masked inputs).
- `[[ENC|v1|field|ciphertext]]`: deterministic ENC token used in LLM prompts and responses (the LLM must copy tokens as-is).
- `Presidio`: on-prem discovery signal for free text; not a replacement for encryption, tokenization, safe logging, or egress validation.

## Step-by-Step Walkthrough (What Happens and Where)

| Step | Where | What happens | Plaintext PII/PCI leaves on-prem? |
|---|---|---|---|
| 0 | On-Prem | Receive `FraudExplainRequest` (`transaction` + optional `customer`) with synthetic demo data such as `John Smith`, `+974 5512 3456`, and `john.smith@example.com` | No |
| 1 | On-Prem / Presidio | Scan the actual demo transaction text with Microsoft Presidio to identify candidate PII entities and confidence scores | No |
| 2 | On-Prem | Mask transaction (`mask_and_track()` / `mask_transaction()`): PII/PCI encrypt, numeric scale, categories map | No |
| 3 | On-Prem | Enforce cloud policy: `validate_egress(..., destination="cloud")` | No |
| 4 | Cloud (stub) | Score masked features: `score_transaction(masked_txn)` returns `fraud_probability`, `reason_codes`, `masked_customer_id` | No |
| 5 | On-Prem | Build Decision Engine payload: original + `_fraud_scoring` for an on-prem consumer | No |
| 6 | On-Prem | Build LLM prompt with ENC tokens only | No |
| 7 | On-Prem / Presidio | Run Presidio pre-flight scan on the actual masked LLM prompt before egress | No |
| 8 | On-Prem | Enforce LLM policy: `validate_egress(..., destination="llm")` and plaintext substring safety checks | No |
| 9 | Cloud (stub) | Generate masked explanation text; LLM receives and returns ENC tokens only | No |
| 10 | On-Prem | Optional de-mask for RM Workbench (`ENABLE_UNMASK=true`) | No (on-prem only) |

<details>
<summary><strong>Mermaid sequence diagram (engineering trace)</strong></summary>

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial","primaryTextColor":"#0f172a","lineColor":"#64748b","noteBkgColor":"#f8fafc","noteTextColor":"#0f172a"}}}%%
sequenceDiagram
    autonumber
    actor User as "User"
    participant UI as "Demo UI"
    participant Svc as "PII Masking Service (On-Prem)"
    participant Presidio as "Microsoft Presidio Analyzer"
    participant Guard as "Egress Guard"
    participant Cloud as "Databricks scoring (Cloud)"
    participant DE as "Decision Engine (On-Prem)"
    participant LLM as "LLM (Cloud)"
    participant RM as "RM Workbench (On-Prem)"

    User->>UI: Run demo / manual step
    UI->>Svc: POST /v1/demo/run (transaction + optional customer)

    rect rgb(232, 243, 255)
      Svc->>Svc: Receive TransactionIn (plaintext PII/PCI)
      Note right of Svc: Synthetic demo data:<br/>John Smith<br/>+974 5512 3456<br/>john.smith@example.com
    end

    rect rgb(237, 233, 254)
      Svc->>Presidio: Analyze actual demo transaction text before masking
      Presidio-->>Svc: Candidate entities: PERSON, PHONE_NUMBER, EMAIL_ADDRESS, CREDIT_CARD, CUSTOMER_ID
      Note right of Presidio: Presidio is a discovery signal.<br/>It does not replace encryption or egress policy.
    end

    rect rgb(232, 243, 255)
      Svc->>Svc: mask_and_track() / mask_transaction()
      Note right of Svc: PII/PCI -> AES-256-SIV<br/>Numeric -> scaling<br/>Categorical -> mapping
      Svc->>Guard: validate_egress(destination="cloud")
      Guard-->>Svc: Approved: masked cloud payload only
      Svc->>Svc: prepare_for_cloud(masked_id, masked_txn)
      Svc->>Guard: validate_egress(destination="cloud")
      Guard-->>Svc: Approved: masked features only
    end

    rect rgb(255, 247, 237)
      Svc->>Cloud: CloudPredictionRequest (masked only)
      Cloud-->>Svc: CloudPredictionResponse (score + reasons + masked_customer_id)
    end

    rect rgb(233, 248, 239)
      Svc->>Svc: Build Decision Engine payload (original + _fraud_scoring)
      Svc->>DE: Send payload (on-prem consumer)
      Note right of DE: Demo does not call a real Decision Engine<br/>(payload is shown in UI)
    end

    rect rgb(230, 247, 255)
      Svc->>Svc: Build LLMExplainPrompt (ENC tokens only)
      Svc->>Presidio: Pre-flight scan actual masked LLM prompt
      Presidio-->>Svc: Detection artifact for reviewer / policy signal
      Svc->>Guard: validate_egress(destination="llm")
      Guard-->>Svc: Approved: ENC tokens only
      Svc->>Svc: Build LLMRequestMasked (prompt string + tokens)
      Svc->>Svc: Ensure no plaintext substrings in prompt
      Svc->>LLM: LLM request (masked only)
      LLM-->>Svc: LLM response (masked, tokens preserved)
    end

    alt ENABLE_UNMASK = true
        Svc->>Svc: unmask_text() on-prem only
        Svc->>RM: RM explanation (plaintext on-prem)
    else ENABLE_UNMASK = false
        Svc->>RM: masked-only explanation
    end

    Svc-->>UI: Aggregated artifacts for UI playback
```

In this demo, Presidio pre-flight findings are surfaced as artifacts for reviewer visibility. The hard egress controls are `validate_egress(...)` and plaintext substring checks. Production policy can choose to block or re-mask based on Presidio findings.

</details>

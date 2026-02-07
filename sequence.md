# End-to-End Sequence (PII Masking Service)

This is an executive-friendly walkthrough aligned with the demo playback endpoint: `POST /v1/demo/run` (see `app/main.py`).

## Executive View (One Slide)

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

## Glossary (Key Identifiers)

- `masked_id`: per-transaction tracking id (format like `MASK-...`), safe to use for joining artifacts in the demo.
- `masked_customer_id` / `token_customer_id`: deterministic customer token returned by cloud scoring (derived from masked inputs).
- `[[ENC|v1|field|ciphertext]]`: deterministic ENC token used in LLM prompts and responses (the LLM must copy tokens as-is).

## Step-by-Step Walkthrough (What Happens and Where)

| Step | Where | What happens | Plaintext PII/PCI leaves on-prem? |
|---|---|---|---|
| 0 | On-Prem | Receive `FraudExplainRequest` (`transaction` + optional `customer`) | No |
| 1 | On-Prem | Mask transaction (`mask_and_track()` / `mask_transaction()`): PII/PCI encrypt, numeric scale, categories map | No |
| 2 | On-Prem | Enforce cloud policy: `validate_egress(..., destination="cloud")` | No |
| 3 | Cloud (stub) | Score masked features: `score_transaction(masked_txn)` returns `fraud_probability`, `reason_codes`, `masked_customer_id` | No |
| 4 | On-Prem | Build Decision Engine payload: original + `_fraud_scoring` (on-prem consumer) | No |
| 5 | On-Prem | Build LLM prompt with ENC tokens only + enforce LLM policy | No |
| 6 | Cloud (stub) | Generate masked explanation text (tokens preserved) | No |
| 7 | On-Prem | Optional de-mask for RM Workbench (`ENABLE_UNMASK=true`) | No (on-prem only) |

<details>
<summary><strong>Mermaid sequence diagram (engineering trace)</strong></summary>

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial","primaryTextColor":"#0f172a","lineColor":"#64748b","noteBkgColor":"#f8fafc","noteTextColor":"#0f172a"}}}%%
sequenceDiagram
    autonumber
    actor User as "User"
    participant UI as "Demo UI"
    participant Svc as "PII Masking Service (On-Prem)"
    participant Cloud as "Databricks scoring (Cloud)"
    participant DE as "Decision Engine (On-Prem)"
    participant LLM as "LLM (Cloud)"
    participant RM as "RM Workbench (On-Prem)"

    User->>UI: Run demo / manual step
    UI->>Svc: POST /v1/demo/run (transaction + optional customer)

    rect rgb(232, 243, 255)
      Svc->>Svc: Receive TransactionIn (plaintext PII/PCI)
      Svc->>Svc: mask_and_track() / mask_transaction()
      Note right of Svc: PII/PCI -> AES-256-SIV<br/>Numeric -> scaling<br/>Categorical -> mapping
      Svc->>Svc: validate_egress(destination="cloud")
      Svc->>Svc: prepare_for_cloud(masked_id, masked_txn)
      Svc->>Svc: validate_egress(destination="cloud")
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
      Svc->>Svc: validate_egress(destination="llm")
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

</details>

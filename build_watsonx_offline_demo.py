#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from pathlib import Path


REQUIRED_FILES = [
    "__init__.py",
    "classification.py",
    "cloud_stub.py",
    "config.py",
    "llm_stub.py",
    "main.py",
    "masking.py",
    "schemas.py",
    "text_masking.py",
]


DEMO_REQUEST = {
    "transaction": {
        "transaction_id": "TXN-20260120-000001",
        "transaction_ts": "2026-01-20T10:15:30+03:00",
        "customer_id": "CUST-QA-00987234",
        "full_name": "Ahmed Al Mansoori",
        "phone": "+974 5512 3456",
        "email": "ahmed.almansoori@example.qa",
        "billing_address": "QA, Doha, West Bay, Diplomatic Area, Street 805, Building 12, Apt 1503",
        "card_pan": "4111111111111111",
        "card_expiry": "12/28",
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
        "is_card_present": True,
    },
    "customer": {
        "customer_id": "CUST-QA-00987234",
        "full_name": "Ahmed Al Mansoori",
        "phone": "+974 5512 3456",
        "email": "ahmed.almansoori@example.qa",
        "address": "QA, Doha, West Bay, Diplomatic Area, Street 805, Building 12, Apt 1503",
        "kyc_segment": "GOLD",
        "preferred_language": "EN",
    },
}


README_WATSONX = """# Watsonx Offline Demo (No Internet)

Step 1: upload watsonx-offline-demo.zip as asset
Step 2: create notebook
Step 3: insert project token and run it (so wslib exists)

One cell:
```python
import sys
import zipfile
from pathlib import Path
import wslib

wslib.download_file("watsonx-offline-demo.zip")
with zipfile.ZipFile("watsonx-offline-demo.zip", "r") as z:
    z.extractall("watsonx-offline-demo")
sys.path.insert(0, str(Path("watsonx-offline-demo").resolve()))
from watsonx_demo import show_demo
show_demo()
```

Note: Requires pydantic>=2.0.0 and cryptography>=41.0.0.
"""


REQUIREMENTS = """pydantic>=2.0.0
cryptography>=41.0.0
"""


WATSONX_DEMO = """from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# DEMO ONLY: deterministic key to keep output stable without env config
if "PII_KEY_B64" not in os.environ:
    demo_key = hashlib.sha512(b"watsonx-offline-demo-key").digest()
    os.environ["PII_KEY_B64"] = base64.b64encode(demo_key).decode("ascii")

warnings.filterwarnings("ignore", message=".*protected namespace.*")

from pydantic import BaseModel

from app.classification import validate_egress
from app.cloud_stub import score_transaction
from app.config import settings
from app.llm_stub import generate_explanation
from app.masking import mask_transaction, prepare_for_cloud
from app.schemas import (
    CloudFraudResult,
    CloudPredictionRequest,
    CustomerIn,
    LLMExplainContext,
    LLMExplainPrompt,
    LLMExplainResultMasked,
    LLMExplainResultUnmasked,
    LLMRequestMasked,
    LLMToken,
    TransactionIn,
)
from app.text_masking import make_enc_token, unmask_text


def _format_amount(value: float) -> str:
    return f"{value:.2f}"


def _format_score(value: float) -> str:
    return f"{value:.0%}"


def _build_llm_prompt(
    transaction: TransactionIn,
    customer: Optional[CustomerIn],
    cloud_result: CloudFraudResult,
) -> LLMExplainPrompt:
    name = customer.full_name if customer else transaction.full_name
    phone = customer.phone if customer else transaction.phone
    email = customer.email if customer else transaction.email

    context = LLMExplainContext(
        customer_name_token=make_enc_token("customer_name", name),
        customer_phone_token=make_enc_token("customer_phone", phone),
        customer_email_token=make_enc_token("customer_email", email),
        amount_token=make_enc_token("amount", _format_amount(transaction.amount)),
        merchant_name_token=make_enc_token("merchant_name", transaction.merchant_name),
        transaction_ts_token=make_enc_token("transaction_ts", transaction.transaction_ts),
        fraud_probability_token=make_enc_token(
            "fraud_probability",
            _format_score(cloud_result.fraud_probability),
        ),
    )

    return LLMExplainPrompt(
        prompt_version=settings.mask_version,
        context=context,
        reason_codes=cloud_result.reason_codes,
    )


def _build_llm_request_masked(prompt: LLMExplainPrompt) -> LLMRequestMasked:
    tokens = [
        LLMToken(field="customer_name", token=prompt.context.customer_name_token),
        LLMToken(field="customer_phone", token=prompt.context.customer_phone_token),
        LLMToken(field="customer_email", token=prompt.context.customer_email_token),
        LLMToken(field="amount", token=prompt.context.amount_token),
        LLMToken(field="merchant_name", token=prompt.context.merchant_name_token),
        LLMToken(field="transaction_ts", token=prompt.context.transaction_ts_token),
        LLMToken(field="fraud_probability", token=prompt.context.fraud_probability_token),
    ]

    prompt_text = (
        "Provide RM explanation for customer {customer_name} regarding amount {amount} at "
        "{merchant_name} on {transaction_ts}. Fraud score {fraud_probability}. "
        "Reasons: {reasons}. Contact: {phone}, {email}."
    ).format(
        customer_name=prompt.context.customer_name_token,
        amount=prompt.context.amount_token,
        merchant_name=prompt.context.merchant_name_token,
        transaction_ts=prompt.context.transaction_ts_token,
        fraud_probability=prompt.context.fraud_probability_token,
        reasons=", ".join(prompt.reason_codes),
        phone=prompt.context.customer_phone_token,
        email=prompt.context.customer_email_token,
    )

    return LLMRequestMasked(
        prompt=prompt_text,
        tokens=tokens,
        reason_codes=prompt.reason_codes,
    )


def _unmask_llm_result(masked: LLMExplainResultMasked) -> LLMExplainResultUnmasked:
    return LLMExplainResultUnmasked(
        rm_explanation=unmask_text(masked.rm_explanation_masked),
        recommended_actions=[unmask_text(item) for item in masked.recommended_actions_masked],
        disclaimer=masked.disclaimer_masked,
    )


def _dump(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump()
    if isinstance(value, dict):
        return {k: _dump(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_dump(v) for v in value]
    return value


def run_demo(payload: dict) -> dict:
    if "transaction" not in payload:
        raise ValueError("payload must contain 'transaction'")

    transaction = TransactionIn(**payload["transaction"])
    customer_payload = payload.get("customer")
    customer = CustomerIn(**customer_payload) if customer_payload else None

    masked_txn = mask_transaction(transaction)
    validate_egress(masked_txn, "cloud")

    cloud_payload = prepare_for_cloud(masked_txn.customer_id, masked_txn)
    validate_egress(cloud_payload, "cloud", CloudPredictionRequest)

    cloud_result = score_transaction(masked_txn)

    llm_prompt = _build_llm_prompt(transaction, customer, cloud_result)
    validate_egress(llm_prompt, "llm")

    llm_request_masked = _build_llm_request_masked(llm_prompt)
    validate_egress(llm_request_masked, "llm")

    llm_response_masked = generate_explanation(llm_prompt)

    notes: list[str] = []
    llm_response_unmasked = None
    if settings.enable_unmask:
        try:
            llm_response_unmasked = _unmask_llm_result(llm_response_masked)
        except Exception as exc:
            notes.append(f"unmask_text failed: {exc}")
    else:
        notes.append("unmask disabled (ENABLE_UNMASK=false)")

    decision_engine_payload = {
        **transaction.model_dump(),
        "_fraud_scoring": {
            "token_customer_id": cloud_result.masked_customer_id,
            "fraud_probability": cloud_result.fraud_probability,
            "reason_codes": cloud_result.reason_codes,
            "risk_level": "HIGH" if cloud_result.fraud_probability >= 0.7 else
                          "MEDIUM" if cloud_result.fraud_probability >= 0.3 else
                          "LOW",
            "scoring_timestamp": datetime.utcnow().isoformat() + "Z",
        },
    }

    result = {
        "original_transaction": _dump(transaction),
        "masked_transaction_for_cloud": _dump(masked_txn),
        "cloud_payload": _dump(cloud_payload),
        "cloud_result": _dump(cloud_result),
        "decision_engine_payload": _dump(decision_engine_payload),
        "llm_request_masked": _dump(llm_request_masked),
        "llm_response_masked": _dump(llm_response_masked),
        "llm_response_unmasked": _dump(llm_response_unmasked),
        "notes": notes,
    }
    return result


def render_html(result: dict) -> str:
    def section(title: str, data: Any) -> str:
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        return (
            f"<details><summary>{html.escape(title)}</summary>"
            f"<pre>{html.escape(json_str)}</pre></details>"
        )

    parts = [
        "<style>details{margin:8px 0}summary{font-weight:600}pre{background:#f6f8fa;padding:8px;}</style>",
        "<h3>Watsonx Offline Demo (No Server)</h3>",
        section("Original Transaction", result.get("original_transaction")),
        section("Masked Transaction for Cloud", result.get("masked_transaction_for_cloud")),
        section("Cloud Payload", result.get("cloud_payload")),
        section("Cloud Result", result.get("cloud_result")),
        section("Decision Engine Payload", result.get("decision_engine_payload")),
        section("LLM Request (Masked)", result.get("llm_request_masked")),
        section("LLM Response (Masked)", result.get("llm_response_masked")),
        section("LLM Response (Unmasked)", result.get("llm_response_unmasked")),
        section("Notes", result.get("notes")),
    ]
    return "\\n".join(parts)


def show_demo(payload_path: str | None = None) -> dict:
    path = Path(payload_path) if payload_path else Path(__file__).with_name("demo_request.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = run_demo(payload)

    try:
        from IPython.display import HTML, display
        display(HTML(render_html(result)))
    except Exception:
        print(json.dumps(result, indent=2, ensure_ascii=False))

    return result


if __name__ == "__main__":
    import sys

    payload_path = sys.argv[1] if len(sys.argv) > 1 else None
    path = Path(payload_path) if payload_path else Path(__file__).with_name("demo_request.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = run_demo(payload)
    print(json.dumps(result, indent=2, ensure_ascii=False))
"""


def _find_source_dir() -> Path:
    cwd = Path.cwd()
    if all((cwd / name).is_file() for name in REQUIRED_FILES):
        return cwd

    app_dir = cwd / "app"
    if app_dir.is_dir() and all((app_dir / name).is_file() for name in REQUIRED_FILES):
        return app_dir

    raise SystemExit("Required source files not found in current directory or ./app")


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def build_zip() -> None:
    src_dir = _find_source_dir()
    output_zip = Path.cwd() / "watsonx-offline-demo.zip"
    if output_zip.exists():
        output_zip.unlink()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "watsonx-offline-demo"
        app_dir = root / "app"
        app_dir.mkdir(parents=True, exist_ok=True)

        for name in REQUIRED_FILES:
            shutil.copy2(src_dir / name, app_dir / name)

        _write_text(root / "README_WATSONX.md", README_WATSONX.strip() + "\n")
        _write_text(root / "requirements.txt", REQUIREMENTS.strip() + "\n")
        _write_text(root / "demo_request.json", json.dumps(DEMO_REQUEST, indent=2) + "\n")
        _write_text(root / "watsonx_demo.py", WATSONX_DEMO.strip() + "\n")

        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in root.rglob("*"):
                if path.is_dir():
                    continue
                rel = path.relative_to(root.parent)
                zf.write(path, rel.as_posix())

    print(f"Created watsonx-offline-demo.zip {output_zip.resolve()}")


if __name__ == "__main__":
    build_zip()

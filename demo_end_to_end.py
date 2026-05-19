#!/usr/bin/env python3
"""
End-to-end demo for /v1/fraud/explain.
"""

import argparse
import json
import sys

import httpx


SAMPLE_TRANSACTION = {
    "transaction_id": "TXN-20260120-000001",
    "transaction_ts": "2026-01-20T10:15:30+03:00",
    "customer_id": "CUST-QA-00987234",
    "full_name": "John Smith",
    "phone": "+974 5512 3456",
    "email": "john.smith@example.com",
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
}


SAMPLE_CUSTOMER = {
    "customer_id": "CUST-QA-00987234",
    "full_name": "John Smith",
    "phone": "+974 5512 3456",
    "email": "john.smith@example.com",
    "address": "QA, Doha, West Bay, Diplomatic Area, Street 805, Building 12, Apt 1503",
    "kyc_segment": "GOLD",
    "preferred_language": "EN",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="PII Masking Service End-to-End Demo")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Service base URL")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    payload = {"transaction": SAMPLE_TRANSACTION, "customer": SAMPLE_CUSTOMER}

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{base_url}/v1/fraud/explain", json=payload)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        print(f"Request failed: {exc}")
        return 1

    print("\n=== MASKED PAYLOADS (CLOUD + LLM) ===")
    print("\nMasked transaction for cloud:")
    print(json.dumps(data.get("masked_transaction_for_cloud"), indent=2))
    print("\nCloud result:")
    print(json.dumps(data.get("cloud_result"), indent=2))
    print("\nLLM result (masked):")
    print(json.dumps(data.get("llm_result_masked"), indent=2))

    if data.get("llm_result_unmasked"):
        print("\n=== RM OUTPUT (UNMASKED) ===")
        print(json.dumps(data.get("llm_result_unmasked"), indent=2))
    else:
        print("\nUnmasked output is disabled. Set ENABLE_UNMASK=true to view.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

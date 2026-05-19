#!/usr/bin/env python3
"""
Demo client for PII Masking Service - Full Pipeline Demonstration

This script demonstrates the complete anti-fraud pipeline:
1. Receive transaction with PII
2. Mask data and generate unique tracking ID
3. Send to cloud (simulated) for ML scoring
4. Receive prediction by masked ID
5. Restore identity to link prediction to real customer

Usage:
    python demo_client.py [--base-url http://localhost:8000]
"""

import argparse
import json
import sys
import time

import httpx


# Sample transaction data (as specified in requirements)
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
    "is_card_present": True
}


def print_header(text: str, char: str = "="):
    """Print a formatted header."""
    print(f"\n{char * 70}")
    print(f"  {text}")
    print(f"{char * 70}")


def print_subheader(text: str):
    """Print a subheader."""
    print(f"\n{'─' * 50}")
    print(f"  {text}")
    print(f"{'─' * 50}")


def print_json(data: dict, title: str = None, indent: int = 2):
    """Pretty print JSON data."""
    if title:
        print(f"\n{title}:")
    print(json.dumps(data, indent=indent, ensure_ascii=False))


def truncate(value, max_len: int = 40) -> str:
    """Truncate long values for display."""
    s = str(value)
    return s[:max_len] + "..." if len(s) > max_len else s


def main():
    parser = argparse.ArgumentParser(description="PII Masking Service Demo Client")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL of the masking service"
    )
    args = parser.parse_args()
    
    base_url = args.base_url.rstrip("/")
    client = httpx.Client(timeout=30.0)
    
    print_header("🔐 PII MASKING SERVICE - FULL PIPELINE DEMO", "═")
    print(f"\nTarget: {base_url}")
    print("Scenario: Card transaction fraud detection with PII protection")
    
    # ================================================================
    # Step 0: Health Check
    # ================================================================
    print_header("Step 0: Health Check")
    try:
        resp = client.get(f"{base_url}/health")
        resp.raise_for_status()
        health = resp.json()
        print(f"✅ Service is healthy")
        print(f"   Version: {health['version']}")
        print(f"   Unmask enabled: {health['unmask_enabled']}")
    except httpx.RequestError as e:
        print(f"❌ Failed to connect: {e}")
        print("   Start the service: uvicorn app.main:app --reload")
        sys.exit(1)
    
    # ================================================================
    # Step 1: Show Original Transaction (with PII)
    # ================================================================
    print_header("Step 1: Original Transaction (contains PII)")
    print("\n📥 Incoming transaction from payment gateway:")
    print_json(SAMPLE_TRANSACTION)
    
    print("\n⚠️  PII fields that need protection:")
    pii_fields = ["customer_id", "full_name", "phone", "email", 
                  "billing_address", "card_pan", "card_expiry", "ip_address", "device_id"]
    for field in pii_fields:
        print(f"   • {field}: {truncate(SAMPLE_TRANSACTION.get(field, 'N/A'), 50)}")
    
    # ================================================================
    # Step 2: Mask and Generate Tracking ID
    # ================================================================
    print_header("Step 2: Mask Transaction & Generate Tracking ID")
    print("\n📤 Calling POST /v1/pipeline/process...")
    
    resp = client.post(f"{base_url}/v1/pipeline/process", json=SAMPLE_TRANSACTION)
    resp.raise_for_status()
    masked_with_id = resp.json()
    
    masked_id = masked_with_id["masked_id"]
    masked_txn = masked_with_id["masked_transaction"]
    
    print(f"\n✅ Generated masked_id: {masked_id}")
    print("\n📋 Masked transaction (safe to send to cloud):")
    print_json(masked_txn)
    
    print("\n🔒 Transformation summary:")
    print("\n   PII Fields → Encrypted (AES-256-SIV):")
    for field in pii_fields:
        orig = SAMPLE_TRANSACTION.get(field, "")
        mask = masked_txn.get(field, "")
        print(f"      {field}:")
        print(f"         Before: {truncate(orig, 35)}")
        print(f"         After:  {truncate(mask, 35)}")
    
    print("\n   Numeric Fields → Scaled (Diagonal Matrix):")
    numeric_fields = ["amount", "available_balance", "credit_limit"]
    for field in numeric_fields:
        orig = SAMPLE_TRANSACTION.get(field, 0)
        mask = masked_txn.get(field, 0)
        ratio = mask / orig if orig else 0
        print(f"      {field}: {orig} × {ratio:.2f} = {mask:.2f}")
    
    print(f"\n   MCC: {SAMPLE_TRANSACTION['mcc']} → {masked_txn['mcc']} (permuted)")
    print(f"   Channel: {SAMPLE_TRANSACTION['channel']} → {masked_txn['channel']} (mapped)")
    
    # ================================================================
    # Step 3: Prepare for Cloud
    # ================================================================
    print_header("Step 3: Prepare Data for Cloud ML Model")
    print("\n📤 Calling POST /v1/pipeline/send-to-cloud...")
    
    resp = client.post(f"{base_url}/v1/pipeline/send-to-cloud", json=masked_with_id)
    resp.raise_for_status()
    cloud_request = resp.json()
    
    print("\n☁️  Data prepared for cloud (NO PII!):")
    print_json(cloud_request)
    
    print("\n✅ Only masked_id and features sent to cloud:")
    print(f"   • masked_id: {cloud_request['masked_id']}")
    print(f"   • mcc: {cloud_request['mcc']} (masked)")
    print(f"   • channel: {cloud_request['channel']} (masked)")
    print(f"   • amount: {cloud_request['amount']} (scaled)")
    print(f"   • No customer name, phone, email, card number!")
    
    # ================================================================
    # Step 4: Get Prediction from Cloud
    # ================================================================
    print_header("Step 4: Get Fraud Prediction from Cloud ML")
    print("\n📤 Calling POST /v1/pipeline/get-prediction...")
    print("   (Simulated - in production this calls Databricks/SageMaker)")
    
    time.sleep(0.5)  # Simulate network latency
    
    resp = client.post(f"{base_url}/v1/pipeline/get-prediction", json=cloud_request)
    resp.raise_for_status()
    prediction = resp.json()
    
    print("\n🤖 ML Model Response:")
    print_json(prediction)
    
    fraud_prob = prediction["fraud_probability"]
    print(f"\n📊 Fraud Probability: {fraud_prob:.2%}")
    
    if fraud_prob < 0.3:
        risk_level = "🟢 LOW RISK"
    elif fraud_prob < 0.7:
        risk_level = "🟡 MEDIUM RISK"
    else:
        risk_level = "🔴 HIGH RISK"
    print(f"   Risk Level: {risk_level}")
    
    # ================================================================
    # Step 5: Restore Identity
    # ================================================================
    print_header("Step 5: Restore Customer Identity from Prediction")
    print("\n📤 Calling POST /v1/pipeline/restore-identity...")
    print(f"   Using masked_id: {prediction['masked_id']}")
    
    resp = client.post(f"{base_url}/v1/pipeline/restore-identity", json=prediction)
    resp.raise_for_status()
    final_result = resp.json()
    
    print("\n🔓 Identity Restored - Final Decision:")
    print_json(final_result)
    
    print("\n" + "=" * 70)
    print("  📋 FINAL FRAUD DECISION REPORT")
    print("=" * 70)
    print(f"""
    Transaction ID:     {final_result['transaction_id']}
    Masked ID:          {final_result['masked_id']}
    
    CUSTOMER IDENTITY (restored):
    ─────────────────────────────
    Customer ID:        {final_result['customer_id']}
    Full Name:          {final_result['full_name']}
    Phone:              {final_result['phone']}
    Email:              {final_result['email']}
    Card (last 4):      ****{final_result['card_pan_last4']}
    
    TRANSACTION:
    ─────────────────────────────
    Original Amount:    {final_result['amount_original']} {SAMPLE_TRANSACTION['currency']}
    
    ML SCORING:
    ─────────────────────────────
    Model Version:      {final_result['model_version']}
    Fraud Probability:  {final_result['fraud_probability']:.2%}
    
    ══════════════════════════════════════════════════════════════
    🎯 RECOMMENDATION:  {final_result['recommendation']}
    ══════════════════════════════════════════════════════════════
    """)
    
    # ================================================================
    # Bonus: One-Call Full Pipeline
    # ================================================================
    print_header("Bonus: Full Pipeline in One Call")
    print("\n📤 Calling POST /v1/pipeline/full (all steps at once)...")
    
    resp = client.post(f"{base_url}/v1/pipeline/full", json=SAMPLE_TRANSACTION)
    resp.raise_for_status()
    one_call_result = resp.json()
    
    print(f"\n✅ Same result in one API call:")
    print(f"   Customer: {one_call_result['full_name']}")
    print(f"   Fraud Probability: {one_call_result['fraud_probability']:.2%}")
    print(f"   Recommendation: {one_call_result['recommendation']}")
    
    # ================================================================
    # Summary
    # ================================================================
    print_header("🎉 DEMO COMPLETE", "═")
    print("""
    KEY TAKEAWAYS:
    
    ✅ PII never leaves your secure perimeter
       - All sensitive data encrypted before cloud
       - Cloud only sees masked_id and features
    
    ✅ ML scoring happens on anonymized data
       - Model trained on masked features
       - No access to customer identity
    
    ✅ Identity restored ONLY at decision time
       - Using masked_id as lookup key
       - Happens inside your secure environment
    
    ✅ Full audit trail via masked_id
       - Link any cloud prediction to original transaction
       - Compliance with data protection regulations
    
    📝 Swagger UI: {base_url}/docs
    """.format(base_url=base_url))
    
    client.close()


if __name__ == "__main__":
    main()

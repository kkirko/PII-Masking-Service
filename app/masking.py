"""
Masking and unmasking logic for PII, numeric, and categorical fields.
Includes transaction tracking for cloud processing pipeline.
"""

import base64
import random
import uuid
import threading
from typing import Optional
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from app.config import settings
from app.schemas import (
    TransactionIn, 
    TransactionOut, 
    MaskedTransactionWithId,
    CloudPredictionRequest,
    CloudPredictionResponse,
    PredictionWithIdentity,
    CustomerIn,
    CustomerOut,
)


# Initialize AES-SIV cipher with the configured key
_cipher = AESSIV(settings.pii_key)

# Pre-compute MCC permutation (bijective mapping 0-9999 -> 0-9999)
_MCC_RANGE = 10000
_rng = random.Random(settings.cat_seed)
_mcc_permutation = list(range(_MCC_RANGE))
_rng.shuffle(_mcc_permutation)
# Reverse permutation for unmasking
_mcc_permutation_reverse = [0] * _MCC_RANGE
for original, masked in enumerate(_mcc_permutation):
    _mcc_permutation_reverse[masked] = original


# ============================================================
# Transaction Storage (In-memory for demo, use Redis in prod)
# ============================================================
# Stores: masked_id -> {original_transaction, masked_transaction, timestamp}
_transaction_store: dict[str, dict] = {}
_store_lock = threading.Lock()
_STORE_TTL_HOURS = 24  # Auto-cleanup after 24 hours


def _cleanup_old_transactions():
    """Remove transactions older than TTL."""
    cutoff = datetime.utcnow() - timedelta(hours=_STORE_TTL_HOURS)
    with _store_lock:
        expired = [k for k, v in _transaction_store.items() if v["timestamp"] < cutoff]
        for k in expired:
            del _transaction_store[k]


def store_transaction(
    masked_id: str, 
    original: TransactionIn, 
    masked: TransactionOut
) -> None:
    """Store transaction mapping for later identity restoration."""
    with _store_lock:
        _transaction_store[masked_id] = {
            "original": original,
            "masked": masked,
            "timestamp": datetime.utcnow(),
        }
    # Periodic cleanup (simple approach for demo)
    if len(_transaction_store) % 100 == 0:
        _cleanup_old_transactions()


def get_original_transaction(masked_id: str) -> Optional[TransactionIn]:
    """Retrieve original transaction by masked_id."""
    with _store_lock:
        entry = _transaction_store.get(masked_id)
        return entry["original"] if entry else None


def get_masked_transaction(masked_id: str) -> Optional[TransactionOut]:
    """Retrieve masked transaction by masked_id."""
    with _store_lock:
        entry = _transaction_store.get(masked_id)
        return entry["masked"] if entry else None


def generate_masked_id() -> str:
    """Generate unique masked ID for cloud tracking."""
    return f"MASK-{uuid.uuid4().hex[:16].upper()}"


# ============================================================
# Encryption / Decryption
# ============================================================

def _get_associated_data(field_name: str) -> bytes:
    """
    Generate associated data for domain separation.
    This ensures the same value in different fields produces different ciphertext.
    """
    return f"scb-demo|{settings.mask_version}|{field_name}".encode("utf-8")


def encrypt_str(value: str, field_name: str) -> str:
    """
    Encrypt a string value using AES-256-SIV (deterministic AEAD).
    Returns base64url-encoded ciphertext.
    """
    plaintext = value.encode("utf-8")
    ad = _get_associated_data(field_name)
    ciphertext = _cipher.encrypt(plaintext, [ad])
    return base64.urlsafe_b64encode(ciphertext).decode("ascii")


def decrypt_str(ciphertext_b64: str, field_name: str) -> str:
    """
    Decrypt a base64url-encoded ciphertext using AES-256-SIV.
    """
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    ad = _get_associated_data(field_name)
    plaintext = _cipher.decrypt(ciphertext, [ad])
    return plaintext.decode("utf-8")


# ============================================================
# Numeric Scaling (Diagonal Matrix)
# ============================================================

def scale_numeric(value: float, field_name: str) -> float:
    """Scale a numeric value: x_masked = x * s_j"""
    scale = settings.scale_factors.get(field_name, 1.0)
    return value * scale


def unscale_numeric(masked_value: float, field_name: str) -> float:
    """Reverse scaling: x = x_masked / s_j"""
    scale = settings.scale_factors.get(field_name, 1.0)
    return masked_value / scale


# ============================================================
# Categorical Mapping
# ============================================================

def mask_mcc(mcc: int) -> int:
    """Apply bijective permutation to MCC code."""
    return _mcc_permutation[mcc]


def unmask_mcc(masked_mcc: int) -> int:
    """Reverse the MCC permutation."""
    return _mcc_permutation_reverse[masked_mcc]


def mask_channel(channel: str) -> str:
    """Map channel to masked value."""
    return settings.channel_map.get(channel, channel)


def unmask_channel(masked_channel: str) -> str:
    """Reverse the channel mapping."""
    return settings.channel_map_reverse.get(masked_channel, masked_channel)


# ============================================================
# Transaction Masking / Unmasking
# ============================================================

def mask_transaction(txn: TransactionIn) -> TransactionOut:
    """
    Apply full masking pipeline to a transaction.
    
    1. Encrypt PII fields with AES-SIV
    2. Scale numeric fields with diagonal matrix
    3. Permute MCC
    4. Map channel
    """
    data = txn.model_dump()
    
    # 1. Encrypt PII fields
    for field in settings.pii_fields:
        if field in data:
            data[field] = encrypt_str(data[field], field)
    
    # 2. Scale numeric fields
    for field in settings.numeric_fields:
        if field in data:
            data[field] = scale_numeric(data[field], field)
    
    # 3. Permute MCC
    data["mcc"] = mask_mcc(data["mcc"])
    
    # 4. Map channel
    data["channel"] = mask_channel(data["channel"])
    
    # 5. Add mask version
    data["mask_version"] = settings.mask_version
    
    return TransactionOut(**data)


def unmask_transaction(masked_txn: TransactionOut) -> TransactionIn:
    """
    Reverse the masking pipeline to recover original transaction.
    """
    data = masked_txn.model_dump()
    
    # Remove mask_version (not in original)
    data.pop("mask_version", None)
    
    # 1. Decrypt PII fields
    for field in settings.pii_fields:
        if field in data:
            data[field] = decrypt_str(data[field], field)
    
    # 2. Unscale numeric fields
    for field in settings.numeric_fields:
        if field in data:
            data[field] = unscale_numeric(data[field], field)
    
    # 3. Reverse MCC permutation
    data["mcc"] = unmask_mcc(data["mcc"])
    
    # 4. Reverse channel mapping
    data["channel"] = unmask_channel(data["channel"])
    
    return TransactionIn(**data)


def mask_customer(customer: CustomerIn) -> CustomerOut:
    """Mask customer profile PII fields."""
    data = customer.model_dump()

    for field in settings.customer_pii_fields:
        if field in data:
            data[field] = encrypt_str(data[field], field)

    data["mask_version"] = settings.mask_version
    return CustomerOut(**data)


def unmask_customer(masked_customer: CustomerOut) -> CustomerIn:
    """Unmask customer profile PII fields."""
    data = masked_customer.model_dump()
    data.pop("mask_version", None)

    for field in settings.customer_pii_fields:
        if field in data:
            data[field] = decrypt_str(data[field], field)

    return CustomerIn(**data)


# ============================================================
# Full Pipeline Functions
# ============================================================

def mask_and_track(txn: TransactionIn) -> MaskedTransactionWithId:
    """
    Mask transaction and generate tracking ID for cloud processing.
    Stores mapping for later identity restoration.
    """
    masked_id = generate_masked_id()
    masked = mask_transaction(txn)
    
    # Store for later lookup
    store_transaction(masked_id, txn, masked)
    
    return MaskedTransactionWithId(
        masked_id=masked_id,
        masked_transaction=masked
    )


def prepare_for_cloud(masked_id: str, masked: TransactionOut) -> CloudPredictionRequest:
    """
    Prepare masked transaction for cloud ML model.
    Only sends non-PII features needed for fraud detection.
    """
    return CloudPredictionRequest(
        masked_id=masked_id,
        mcc=masked.mcc,
        channel=masked.channel,
        currency=masked.currency,
        amount=masked.amount,
        available_balance=masked.available_balance,
        credit_limit=masked.credit_limit,
        is_card_present=masked.is_card_present,
        merchant_country=masked.merchant_country,
    )


def simulate_cloud_prediction(request: CloudPredictionRequest) -> CloudPredictionResponse:
    """
    Simulate cloud ML model response.
    In production, this would call Databricks/SageMaker/etc.
    """
    # Fixed probability for demo: 0.75 (high risk)
    return CloudPredictionResponse(
        masked_id=request.masked_id,
        fraud_probability=0.75,
        model_version="fraud-detector-v2.1"
    )


def restore_identity(prediction: CloudPredictionResponse) -> Optional[PredictionWithIdentity]:
    """
    Restore user identity from prediction using stored mapping.
    This is the key step: linking cloud prediction back to real customer.
    """
    original = get_original_transaction(prediction.masked_id)
    if not original:
        return None
    
    # Determine recommendation based on fraud probability
    if prediction.fraud_probability < 0.3:
        recommendation = "APPROVE - Low risk transaction"
    elif prediction.fraud_probability < 0.7:
        recommendation = "REVIEW - Medium risk, manual review recommended"
    else:
        recommendation = "DECLINE - High risk, potential fraud"
    
    return PredictionWithIdentity(
        masked_id=prediction.masked_id,
        fraud_probability=prediction.fraud_probability,
        model_version=prediction.model_version,
        customer_id=original.customer_id,
        full_name=original.full_name,
        phone=original.phone,
        email=original.email,
        card_pan_last4=original.card_pan[-4:],  # Only last 4 digits for safety
        transaction_id=original.transaction_id,
        amount_original=original.amount,
        recommendation=recommendation,
    )

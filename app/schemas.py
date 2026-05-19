"""
Pydantic models for transaction masking API.
"""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field, field_validator


CLASS_PUBLIC = "PUBLIC"
CLASS_INTERNAL = "INTERNAL"
CLASS_CONFIDENTIAL = "CONFIDENTIAL"
CLASS_PII = "PII"
CLASS_PCI = "PCI"


def classified_field(default=..., *, classification: str, **kwargs):
    extra = kwargs.pop("json_schema_extra", {})
    extra = {**extra, "classification": classification}
    if "default_factory" in kwargs:
        return Field(json_schema_extra=extra, **kwargs)
    return Field(default, json_schema_extra=extra, **kwargs)


class TransactionIn(BaseModel):
    """
    Input transaction with PII data.
    This is the "raw" transaction as received from the source system.
    """
    transaction_id: str = classified_field(..., classification=CLASS_INTERNAL, description="Unique transaction identifier")
    transaction_ts: str = classified_field(..., classification=CLASS_CONFIDENTIAL, description="Transaction timestamp (ISO 8601)")

    # PII fields (will be encrypted)
    customer_id: str = classified_field(..., classification=CLASS_PII, description="Customer identifier")
    full_name: str = classified_field(..., classification=CLASS_PII, description="Customer full name")
    phone: str = classified_field(..., classification=CLASS_PII, description="Customer phone number")
    email: str = classified_field(..., classification=CLASS_PII, description="Customer email address")
    billing_address: str = classified_field(..., classification=CLASS_PII, description="Customer billing address")
    card_pan: str = classified_field(..., classification=CLASS_PCI, description="Card PAN (Primary Account Number)")
    card_expiry: str = classified_field(..., classification=CLASS_PCI, description="Card expiry date (MM/YY)")
    ip_address: str = classified_field(..., classification=CLASS_PII, description="IP address of the transaction")
    device_id: str = classified_field(..., classification=CLASS_PII, description="Device identifier")

    # Merchant info
    merchant_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL, description="Merchant identifier")
    merchant_name: str = classified_field(..., classification=CLASS_CONFIDENTIAL, description="Merchant name")
    mcc: int = classified_field(..., classification=CLASS_INTERNAL, ge=0, le=9999, description="Merchant Category Code (0-9999)")
    merchant_country: str = classified_field(..., classification=CLASS_INTERNAL, description="Merchant country code")
    terminal_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL, description="Terminal identifier")

    # Transaction details
    channel: str = classified_field(..., classification=CLASS_INTERNAL, description="Transaction channel (POS, ECOM, ATM, MOB)")
    currency: str = classified_field(..., classification=CLASS_INTERNAL, min_length=3, max_length=3, description="Currency code (ISO 4217)")

    # Numeric fields (will be scaled)
    amount: float = classified_field(..., classification=CLASS_CONFIDENTIAL, ge=0, description="Transaction amount")
    available_balance: float = classified_field(..., classification=CLASS_CONFIDENTIAL, description="Available balance before transaction")
    credit_limit: float = classified_field(..., classification=CLASS_CONFIDENTIAL, ge=0, description="Credit limit")

    # Boolean flags
    is_card_present: bool = classified_field(..., classification=CLASS_INTERNAL, description="Whether physical card was present")

    @field_validator("transaction_ts")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Validate that timestamp is parseable."""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"Invalid ISO 8601 timestamp: {e}")
        return v

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, v: str) -> str:
        """Validate channel is one of allowed values."""
        allowed = {"POS", "ECOM", "ATM", "MOB"}
        if v not in allowed:
            raise ValueError(f"Channel must be one of {allowed}")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
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
        }
    }


class TransactionOut(BaseModel):
    """
    Output transaction with masked/anonymized data.
    Same structure as input, but:
    - PII fields contain encrypted (base64url) values
    - Numeric fields are scaled by diagonal matrix
    - Categorical fields (mcc, channel) are deterministically mapped
    """
    transaction_id: str = classified_field(..., classification=CLASS_INTERNAL)
    transaction_ts: str = classified_field(..., classification=CLASS_CONFIDENTIAL)

    # PII fields (encrypted as base64url strings)
    customer_id: str = classified_field(..., classification=CLASS_PII)
    full_name: str = classified_field(..., classification=CLASS_PII)
    phone: str = classified_field(..., classification=CLASS_PII)
    email: str = classified_field(..., classification=CLASS_PII)
    billing_address: str = classified_field(..., classification=CLASS_PII)
    card_pan: str = classified_field(..., classification=CLASS_PCI)
    card_expiry: str = classified_field(..., classification=CLASS_PCI)
    ip_address: str = classified_field(..., classification=CLASS_PII)
    device_id: str = classified_field(..., classification=CLASS_PII)

    # Merchant info
    merchant_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    merchant_name: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    mcc: int = classified_field(..., classification=CLASS_INTERNAL, description="Masked MCC (permuted)")
    merchant_country: str = classified_field(..., classification=CLASS_INTERNAL)
    terminal_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL)

    # Transaction details
    channel: str = classified_field(..., classification=CLASS_INTERNAL, description="Masked channel")
    currency: str = classified_field(..., classification=CLASS_INTERNAL)

    # Numeric fields (scaled)
    amount: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    available_balance: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    credit_limit: float = classified_field(..., classification=CLASS_CONFIDENTIAL)

    # Boolean flags (unchanged)
    is_card_present: bool = classified_field(..., classification=CLASS_INTERNAL)

    # Traceability
    mask_version: str = classified_field(..., classification=CLASS_INTERNAL, description="Version of masking algorithm used")

    model_config = {
        "json_schema_extra": {
            "example": {
                "transaction_id": "TXN-20260120-000001",
                "transaction_ts": "2026-01-20T10:15:30+03:00",
                "customer_id": "PHqLs2NkZW1vfHYxfGN1c3RvbWVyX2lk...",
                "full_name": "AHJzY2ItZGVtb3x2MXxmdWxsX25hbWU...",
                "phone": "KHNjYi1kZW1vfHYxfHBob25l...",
                "email": "ZXNjYi1kZW1vfHYxfGVtYWls...",
                "billing_address": "YnNjYi1kZW1vfHYxfGJpbGxpbmdfYWRkcmVzcw...",
                "card_pan": "Y3NjYi1kZW1vfHYxfGNhcmRfcGFu...",
                "card_expiry": "ZXhwaXJ5X2VuY3J5cHRlZA...",
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
                "is_card_present": True,
                "mask_version": "v1"
            }
        }
    }


class CustomerIn(BaseModel):
    """Customer profile (PII)."""
    customer_id: str = classified_field(..., classification=CLASS_PII, description="Customer identifier")
    full_name: str = classified_field(..., classification=CLASS_PII, description="Customer full name")
    phone: str = classified_field(..., classification=CLASS_PII, description="Customer phone number")
    email: str = classified_field(..., classification=CLASS_PII, description="Customer email address")
    address: str = classified_field(..., classification=CLASS_PII, description="Customer address")
    kyc_segment: str = classified_field(..., classification=CLASS_CONFIDENTIAL, description="KYC segment")
    preferred_language: str = classified_field(..., classification=CLASS_INTERNAL, description="Preferred language")


class CustomerOut(BaseModel):
    """Masked customer profile."""
    customer_id: str = classified_field(..., classification=CLASS_PII)
    full_name: str = classified_field(..., classification=CLASS_PII)
    phone: str = classified_field(..., classification=CLASS_PII)
    email: str = classified_field(..., classification=CLASS_PII)
    address: str = classified_field(..., classification=CLASS_PII)
    kyc_segment: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    preferred_language: str = classified_field(..., classification=CLASS_INTERNAL)
    mask_version: str = classified_field(..., classification=CLASS_INTERNAL)


class TextMaskRequest(BaseModel):
    """Request to mask text with ENC tokens."""
    text: str = classified_field(..., classification=CLASS_CONFIDENTIAL, description="Plaintext text")
    replacements: dict[str, str] = classified_field(
        ..., classification=CLASS_PII, description="Values to replace with ENC tokens"
    )


class TextMaskResponse(BaseModel):
    """Masked text response."""
    masked_text: str = classified_field(..., classification=CLASS_PII)


class TextUnmaskRequest(BaseModel):
    """Request to unmask ENC tokens in text."""
    masked_text: str = classified_field(..., classification=CLASS_PII)


class TextUnmaskResponse(BaseModel):
    """Unmasked text response."""
    text: str = classified_field(..., classification=CLASS_PII)


class PresidioTextRequest(BaseModel):
    """Request for Presidio text analysis."""
    text: str = classified_field(..., classification=CLASS_PII, description="Synthetic/demo text to inspect")
    language: str = classified_field("en", classification=CLASS_INTERNAL, description="Presidio language code")

    model_config = {
        "json_schema_extra": {
            "example": {
                "text": (
                    "John Smith lives in Doha. His email is john.smith@example.com, "
                    "phone is +974 5512 3456, card is 4111111111111111, "
                    "and customer id is CUST-QA-00987234."
                ),
                "language": "en",
            }
        }
    }


class PresidioAnonymizeRequest(PresidioTextRequest):
    """Request for Presidio anonymization."""
    mode: str = classified_field(
        "replace",
        classification=CLASS_INTERNAL,
        description="Anonymization mode: replace or mask. Use /pii/redact for redaction.",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "text": (
                    "John Smith lives in Doha. His email is john.smith@example.com, "
                    "phone is +974 5512 3456, card is 4111111111111111, "
                    "and customer id is CUST-QA-00987234."
                ),
                "language": "en",
                "mode": "replace",
            }
        }
    }


class PresidioEntity(BaseModel):
    """Detected Presidio entity."""
    entity_type: str = classified_field(..., classification=CLASS_INTERNAL)
    start: int = classified_field(..., classification=CLASS_INTERNAL)
    end: int = classified_field(..., classification=CLASS_INTERNAL)
    score: float = classified_field(..., classification=CLASS_INTERNAL)
    text_preview: Optional[str] = classified_field(None, classification=CLASS_PII)


class PresidioAnalyzeResponse(BaseModel):
    """Presidio analyzer response."""
    entities: List[PresidioEntity] = classified_field(..., classification=CLASS_PII)


class PresidioAnonymizeResponse(BaseModel):
    """Presidio anonymization response."""
    original_text: Optional[str] = classified_field(None, classification=CLASS_PII)
    anonymized_text: str = classified_field(..., classification=CLASS_INTERNAL)
    entities: List[PresidioEntity] = classified_field(..., classification=CLASS_PII)
    operator_used: str = classified_field(..., classification=CLASS_INTERNAL)


class PresidioRedactResponse(BaseModel):
    """Presidio redaction response."""
    original_text: Optional[str] = classified_field(None, classification=CLASS_PII)
    redacted_text: str = classified_field(..., classification=CLASS_INTERNAL)
    entities: List[PresidioEntity] = classified_field(..., classification=CLASS_PII)
    operator_used: str = classified_field(..., classification=CLASS_INTERNAL)


class PresidioScanArtifact(BaseModel):
    """Presidio scan result used by the interactive demo flow."""
    label: str = classified_field(..., classification=CLASS_INTERNAL)
    status: str = classified_field(..., classification=CLASS_INTERNAL)
    entities: List[PresidioEntity] = classified_field(default_factory=list, classification=CLASS_PII)
    entity_count: int = classified_field(0, classification=CLASS_INTERNAL)
    note: Optional[str] = classified_field(None, classification=CLASS_INTERNAL)
    scanned_text: Optional[str] = classified_field(None, classification=CLASS_PII)


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = classified_field("ok", classification=CLASS_PUBLIC)
    version: str = classified_field(..., classification=CLASS_INTERNAL)
    unmask_enabled: bool = classified_field(..., classification=CLASS_INTERNAL)


class MaskedTransactionWithId(BaseModel):
    """Masked transaction with unique tracking ID for cloud processing."""
    masked_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL, description="Unique ID for tracking in cloud")
    masked_transaction: TransactionOut = classified_field(..., classification=CLASS_INTERNAL)


class CloudPredictionRequest(BaseModel):
    """Request to cloud ML model (masked data only)."""
    masked_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    # Only non-PII fields needed for ML model
    mcc: int = classified_field(..., classification=CLASS_INTERNAL)
    channel: str = classified_field(..., classification=CLASS_INTERNAL)
    currency: str = classified_field(..., classification=CLASS_INTERNAL)
    amount: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    available_balance: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    credit_limit: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    is_card_present: bool = classified_field(..., classification=CLASS_INTERNAL)
    merchant_country: str = classified_field(..., classification=CLASS_INTERNAL)


class CloudPredictionResponse(BaseModel):
    """Response from cloud ML model."""
    masked_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    fraud_probability: float = classified_field(..., classification=CLASS_CONFIDENTIAL, ge=0.0, le=1.0)
    model_version: str = classified_field("fraud-detector-v2.1", classification=CLASS_INTERNAL)


class PredictionWithIdentity(BaseModel):
    """Final prediction with restored user identity (internal use only)."""
    masked_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    fraud_probability: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    model_version: str = classified_field(..., classification=CLASS_INTERNAL)
    # Restored PII for internal decision making
    customer_id: str = classified_field(..., classification=CLASS_PII)
    full_name: str = classified_field(..., classification=CLASS_PII)
    phone: str = classified_field(..., classification=CLASS_PII)
    email: str = classified_field(..., classification=CLASS_PII)
    card_pan_last4: str = classified_field(..., classification=CLASS_PCI)
    transaction_id: str = classified_field(..., classification=CLASS_INTERNAL)
    amount_original: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    recommendation: str = classified_field(..., classification=CLASS_INTERNAL, description="Action recommendation based on score")


class CloudFraudResult(BaseModel):
    """Stubbed cloud scoring result."""
    masked_customer_id: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    fraud_probability: float = classified_field(..., classification=CLASS_CONFIDENTIAL)
    reason_codes: List[str] = classified_field(..., classification=CLASS_INTERNAL)


class LLMExplainContext(BaseModel):
    """Masked tokens for LLM prompt."""
    customer_name_token: str = classified_field(..., classification=CLASS_PII)
    customer_phone_token: str = classified_field(..., classification=CLASS_PII)
    customer_email_token: str = classified_field(..., classification=CLASS_PII)
    amount_token: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    merchant_name_token: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    transaction_ts_token: str = classified_field(..., classification=CLASS_CONFIDENTIAL)
    fraud_probability_token: str = classified_field(..., classification=CLASS_CONFIDENTIAL)


class LLMExplainPrompt(BaseModel):
    """Structured prompt for LLM (masked only)."""
    prompt_version: str = classified_field("v1", classification=CLASS_INTERNAL)
    context: LLMExplainContext = classified_field(..., classification=CLASS_INTERNAL)
    reason_codes: List[str] = classified_field(..., classification=CLASS_INTERNAL)


class LLMToken(BaseModel):
    """LLM token metadata for masked requests."""
    field: str = classified_field(..., classification=CLASS_INTERNAL)
    token: str = classified_field(..., classification=CLASS_PII)


class LLMRequestMasked(BaseModel):
    """Masked LLM request for UI playback."""
    prompt: str = classified_field(..., classification=CLASS_INTERNAL)
    tokens: List[LLMToken] = classified_field(..., classification=CLASS_PII)
    reason_codes: List[str] = classified_field(..., classification=CLASS_INTERNAL)


class LLMExplainResultMasked(BaseModel):
    """Masked explanation returned from LLM."""
    rm_explanation_masked: str = classified_field(..., classification=CLASS_PII)
    recommended_actions_masked: List[str] = classified_field(..., classification=CLASS_PII)
    disclaimer_masked: str = classified_field(..., classification=CLASS_INTERNAL)


class LLMExplainResultUnmasked(BaseModel):
    """Unmasked explanation for RM workbench."""
    rm_explanation: str = classified_field(..., classification=CLASS_PII)
    recommended_actions: List[str] = classified_field(..., classification=CLASS_PII)
    disclaimer: str = classified_field(..., classification=CLASS_INTERNAL)


class FraudExplainRequest(BaseModel):
    """Request for full fraud explainability flow."""
    transaction: TransactionIn = classified_field(..., classification=CLASS_PII)
    customer: Optional[CustomerIn] = classified_field(None, classification=CLASS_PII)


class FraudExplainResponse(BaseModel):
    """Response for full fraud explainability flow."""
    original_transaction: TransactionIn = classified_field(..., classification=CLASS_PII)
    masked_transaction_for_cloud: TransactionOut = classified_field(..., classification=CLASS_PII)
    cloud_result: CloudFraudResult = classified_field(..., classification=CLASS_CONFIDENTIAL)
    llm_result_masked: LLMExplainResultMasked = classified_field(..., classification=CLASS_PII)
    llm_result_unmasked: Optional[LLMExplainResultUnmasked] = classified_field(None, classification=CLASS_PII)
    unmask_warning: Optional[str] = classified_field(None, classification=CLASS_INTERNAL)


class DemoRunResponse(BaseModel):
    """Aggregated artifacts for interactive UI playback."""
    original_transaction: TransactionIn = classified_field(..., classification=CLASS_PII)
    presidio_input_scan: Optional[PresidioScanArtifact] = classified_field(None, classification=CLASS_PII)
    masked_transaction_for_cloud: TransactionOut = classified_field(..., classification=CLASS_PII)
    cloud_payload: CloudPredictionRequest = classified_field(..., classification=CLASS_CONFIDENTIAL)
    cloud_result: CloudFraudResult = classified_field(..., classification=CLASS_CONFIDENTIAL)
    decision_engine_payload: dict[str, Any] = classified_field(..., classification=CLASS_PII)
    llm_request_masked: LLMRequestMasked = classified_field(..., classification=CLASS_PII)
    presidio_llm_preflight_scan: Optional[PresidioScanArtifact] = classified_field(None, classification=CLASS_PII)
    llm_response_masked: LLMExplainResultMasked = classified_field(..., classification=CLASS_PII)
    llm_response_unmasked: Optional[LLMExplainResultUnmasked] = classified_field(None, classification=CLASS_PII)

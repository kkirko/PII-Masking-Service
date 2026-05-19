"""
PII Masking Service - FastAPI Application

On-prem privacy-by-design demo for card fraud analytics and RM explainability.

The service integrates Microsoft Presidio as a PII discovery/pre-flight signal,
then applies deterministic masking, ENC tokenization, egress policy checks, and
on-prem-only de-masking for the RM workbench demo.
"""

import logging
import re
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.schemas import (
    TransactionIn,
    TransactionOut,
    HealthResponse,
    MaskedTransactionWithId,
    CloudPredictionRequest,
    CloudPredictionResponse,
    PredictionWithIdentity,
    CustomerIn,
    CustomerOut,
    TextMaskRequest,
    TextMaskResponse,
    TextUnmaskRequest,
    TextUnmaskResponse,
    PresidioTextRequest,
    PresidioAnonymizeRequest,
    PresidioAnalyzeResponse,
    PresidioAnonymizeResponse,
    PresidioRedactResponse,
    PresidioScanArtifact,
    CloudFraudResult,
    LLMExplainPrompt,
    LLMExplainContext,
    LLMToken,
    LLMRequestMasked,
    LLMExplainResultMasked,
    LLMExplainResultUnmasked,
    FraudExplainRequest,
    FraudExplainResponse,
    DemoRunResponse,
)
from app.masking import (
    mask_transaction,
    unmask_transaction,
    mask_and_track,
    prepare_for_cloud,
    simulate_cloud_prediction,
    restore_identity,
    mask_customer,
    unmask_customer,
)
from app.classification import validate_egress, EgressViolation
from app.text_masking import mask_text, unmask_text, make_enc_token, TextMaskingError
from app.cloud_stub import score_transaction
from app.llm_stub import generate_explanation
from app.presidio_service import (
    PresidioUnavailableError,
    analyze_text as presidio_analyze_text,
    anonymize_text as presidio_anonymize_text,
    mask_text as presidio_mask_text,
    redact_text as presidio_redact_text,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
ENC_TOKEN_PATTERN = re.compile(r"\[\[ENC\|v\d+\|[^|]+\|[A-Za-z0-9_-]+=*\]\]")

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"


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
        fraud_probability_token=make_enc_token("fraud_probability", _format_score(cloud_result.fraud_probability)),
    )

    return LLMExplainPrompt(
        prompt_version=settings.mask_version,
        context=context,
        reason_codes=cloud_result.reason_codes,
    )


def _unmask_llm_result(masked: LLMExplainResultMasked) -> LLMExplainResultUnmasked:
    return LLMExplainResultUnmasked(
        rm_explanation=unmask_text(masked.rm_explanation_masked),
        recommended_actions=[unmask_text(item) for item in masked.recommended_actions_masked],
        disclaimer=masked.disclaimer_masked,
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


def _build_presidio_input_scan_text(
    transaction: TransactionIn,
    customer: Optional[CustomerIn],
) -> str:
    name = customer.full_name if customer else transaction.full_name
    phone = customer.phone if customer else transaction.phone
    email = customer.email if customer else transaction.email
    address = customer.address if customer else transaction.billing_address

    return (
        f"Customer {name} initiated transaction {transaction.transaction_id}. "
        f"Contact phone: {phone}. Email: {email}. "
        f"Billing address: {address}. "
        f"Card PAN: {transaction.card_pan}. "
        f"Customer ID: {transaction.customer_id}. "
        f"Merchant: {transaction.merchant_name}. "
        f"Amount: {transaction.amount:.2f} {transaction.currency}."
    )


def _run_presidio_demo_scan(
    label: str,
    text: str,
    include_scanned_text: bool = True,
    ignore_enc_token_entities: bool = False,
) -> PresidioScanArtifact:
    scanned_text = text if include_scanned_text and settings.presidio_demo_include_original else None

    try:
        entities = presidio_analyze_text(text, "en")
        if ignore_enc_token_entities:
            token_spans = [(match.start(), match.end()) for match in ENC_TOKEN_PATTERN.finditer(text)]
            entities = [
                entity for entity in entities
                if not any(entity["start"] < end and entity["end"] > start for start, end in token_spans)
            ]
        return PresidioScanArtifact(
            label=label,
            status="completed",
            entities=entities,
            entity_count=len(entities),
            note="Presidio scan completed on-prem.",
            scanned_text=scanned_text,
        )
    except PresidioUnavailableError as e:
        return PresidioScanArtifact(
            label=label,
            status="unavailable",
            entities=[],
            entity_count=0,
            note=f"Presidio unavailable: {e}",
            scanned_text=scanned_text,
        )
    except Exception:
        logger.exception("Presidio demo scan failed")
        return PresidioScanArtifact(
            label=label,
            status="failed",
            entities=[],
            entity_count=0,
            note="Presidio scan failed. Enforcement controls still ran.",
            scanned_text=scanned_text,
        )


def _ensure_no_plaintext_in_llm_prompt(
    prompt_text: str,
    transaction: TransactionIn,
    customer: Optional[CustomerIn],
) -> None:
    """
    Best-effort safety check: block accidental plaintext leakage into LLM prompt text.

    This is intentionally simple for the demo: we ensure the prompt contains ENC tokens
    and does not contain raw values from the incoming transaction/customer objects.
    """
    if "[[ENC|" not in prompt_text:
        raise EgressViolation("LLM egress blocked: prompt must contain ENC tokens")

    haystack = prompt_text.lower()

    candidates: list[tuple[str, str]] = []
    txn_dump = transaction.model_dump()
    for field in (
        "customer_id",
        "full_name",
        "phone",
        "email",
        "billing_address",
        "card_pan",
        "card_expiry",
        "ip_address",
        "device_id",
        "merchant_name",
        "transaction_ts",
    ):
        value = txn_dump.get(field)
        if value:
            candidates.append((field, str(value)))

    for field in ("amount", "available_balance", "credit_limit"):
        value = txn_dump.get(field)
        if value is None:
            continue
        # Catch common float renderings if someone formats the prompt incorrectly.
        candidates.append((field, str(value)))
        try:
            candidates.append((field, _format_amount(float(value))))
        except Exception:
            pass

    if customer:
        cust_dump = customer.model_dump()
        for field in ("customer_id", "full_name", "phone", "email", "address"):
            value = cust_dump.get(field)
            if value:
                candidates.append((f"customer.{field}", str(value)))

    for field, value in candidates:
        # Avoid noisy false positives on very short strings.
        if len(value) < 5:
            continue
        if value.lower() in haystack:
            raise EgressViolation(
                f"LLM egress blocked: prompt contains plaintext for field '{field}'"
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("🚀 PII Masking Service starting...")
    logger.info(f"   Mask version: {settings.mask_version}")
    logger.info(f"   Unmask endpoint: {'enabled' if settings.enable_unmask else 'disabled'}")
    logger.info(f"   PII fields: {settings.pii_fields}")
    logger.info(f"   Numeric fields: {settings.numeric_fields}")
    yield
    logger.info("👋 PII Masking Service shutting down...")


app = FastAPI(
    title="PII Masking Service",
    description="""
## Card Transaction PII Masking Microservice

This service demonstrates an on-prem privacy-by-design flow for card fraud analytics
and RM explainability. It detects candidate PII with Microsoft Presidio, applies
deterministic masking/tokenization controls, validates cloud/LLM egress, and keeps
de-masking on-prem only.

### 🔄 Demo Playback Flow

```
Input transaction
      │
      ▼
Microsoft Presidio
PII discovery on actual demo text
      │
      ▼
Mask & Track
PII/PCI encryption + numeric scaling + categorical mapping
      │
      ▼
Egress Guard ───▶ Cloud scoring
      │              masked features only
      ▼
Decision Engine payload
on-prem original + score
      │
      ▼
Tokenization for LLM
ENC tokens only
      │
      ▼
Presidio pre-flight scan
detection artifact before LLM egress
      │
      ▼
LLM request / response
tokens preserved
      │
      ▼
RM Workbench
optional on-prem de-masking
```

### Features:
- **Presidio PII Discovery**: on-prem detection signal for free text and prompt drafts
- **PII/PCI Encryption**: AES-256-SIV deterministic encryption
- **LLM Tokenization**: deterministic `[[ENC|...]]` tokens
- **Egress Policy Checks**: block plaintext leakage before cloud/LLM egress
- **Numeric Scaling**: diagonal matrix transformation (reversible demo transform)
- **Category Mapping**: Deterministic permutation for MCC and channel
- **Identity Tracking**: Link predictions back to real customers by masked ID
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Mount static files for web UI
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ============================================================
# Web UI
# ============================================================

@app.get("/", tags=["Web UI"], include_in_schema=False)
async def web_ui():
    """Serve the web UI."""
    return FileResponse(STATIC_DIR / "index.html")


# ============================================================
# System Endpoints
# ============================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        version=settings.mask_version,
        unmask_enabled=settings.enable_unmask
    )


# ============================================================
# Basic Masking Endpoints
# ============================================================

@app.post(
    "/v1/mask/transaction",
    response_model=TransactionOut,
    tags=["Basic Masking"],
    summary="Mask transaction PII (simple)",
)
async def mask_transaction_endpoint(transaction: TransactionIn):
    """
    Mask a transaction for secure cloud processing (simple version).
    
    This endpoint only masks the data without tracking.
    For full pipeline with identity restoration, use `/v1/pipeline/process`.
    """
    logger.info(f"Masking transaction: {transaction.transaction_id}")
    try:
        masked = mask_transaction(transaction)
        logger.info(f"Transaction masked: {transaction.transaction_id}")
        return masked
    except Exception as e:
        logger.error(f"Error masking transaction {transaction.transaction_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal masking error")


@app.post(
    "/v1/unmask/transaction",
    response_model=TransactionIn,
    tags=["Basic Masking"],
    summary="Unmask transaction (demo only)",
)
async def unmask_transaction_endpoint(masked_transaction: TransactionOut):
    """
    Restore original transaction from masked data.
    
    ⚠️ **WARNING**: This endpoint is for demonstration purposes only.
    In production, it should be disabled via `ENABLE_UNMASK=false`.
    """
    if not settings.enable_unmask:
        raise HTTPException(
            status_code=403,
            detail="Unmask endpoint is disabled. Set ENABLE_UNMASK=true to enable."
        )
    
    logger.info(f"Unmasking transaction: {masked_transaction.transaction_id}")
    try:
        original = unmask_transaction(masked_transaction)
        logger.info(f"Transaction unmasked: {masked_transaction.transaction_id}")
        return original
    except Exception as e:
        logger.error(f"Error unmasking transaction: {e}")
        raise HTTPException(status_code=500, detail="Internal unmasking error")


# ============================================================
# Customer Masking Endpoints
# ============================================================

@app.post(
    "/v1/mask/customer",
    response_model=CustomerOut,
    tags=["Customer Masking"],
    summary="Mask customer profile PII",
)
async def mask_customer_endpoint(customer: CustomerIn):
    """Mask a customer profile for secure processing."""
    try:
        masked = mask_customer(customer)
        return masked
    except Exception as e:
        logger.error(f"Error masking customer: {e}")
        raise HTTPException(status_code=500, detail="Internal customer masking error")


@app.post(
    "/v1/unmask/customer",
    response_model=CustomerIn,
    tags=["Customer Masking"],
    summary="Unmask customer profile (demo only)",
)
async def unmask_customer_endpoint(masked_customer: CustomerOut):
    """Restore original customer profile from masked data."""
    if not settings.enable_unmask:
        raise HTTPException(
            status_code=403,
            detail="Unmask endpoint is disabled. Set ENABLE_UNMASK=true to enable.",
        )

    try:
        original = unmask_customer(masked_customer)
        return original
    except Exception as e:
        logger.error(f"Error unmasking customer: {e}")
        raise HTTPException(status_code=500, detail="Internal customer unmasking error")


# ============================================================
# Text Masking Endpoints
# ============================================================

@app.post(
    "/v1/mask/text",
    response_model=TextMaskResponse,
    tags=["Text Masking"],
    summary="Mask text with ENC tokens",
)
async def mask_text_endpoint(request: TextMaskRequest):
    """Mask plaintext text using ENC tokens."""
    try:
        masked = mask_text(request.text, request.replacements)
        return TextMaskResponse(masked_text=masked)
    except Exception as e:
        logger.error(f"Error masking text: {e}")
        raise HTTPException(status_code=500, detail="Internal text masking error")


@app.post(
    "/v1/unmask/text",
    response_model=TextUnmaskResponse,
    tags=["Text Masking"],
    summary="Unmask text with ENC tokens (demo only)",
)
async def unmask_text_endpoint(request: TextUnmaskRequest):
    """Unmask ENC tokens back to plaintext."""
    if not settings.enable_unmask_text:
        raise HTTPException(
            status_code=403,
            detail="Unmask text endpoint is disabled. Set ENABLE_UNMASK_TEXT=true to enable.",
        )

    try:
        text = unmask_text(request.masked_text)
        return TextUnmaskResponse(text=text)
    except TextMaskingError as e:
        logger.error(f"Text unmasking error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error unmasking text: {e}")
        raise HTTPException(status_code=500, detail="Internal text unmasking error")


# ============================================================
# Microsoft Presidio Endpoints
# ============================================================

@app.post(
    "/pii/analyze",
    response_model=PresidioAnalyzeResponse,
    tags=["Microsoft Presidio"],
    summary="Detect PII entities in text with Microsoft Presidio",
)
async def pii_analyze_endpoint(request: PresidioTextRequest):
    """Analyze synthetic/demo text and return detected entity metadata."""
    try:
        entities = presidio_analyze_text(request.text, request.language)
        return PresidioAnalyzeResponse(entities=entities)
    except PresidioUnavailableError as e:
        logger.error(f"Presidio unavailable: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Presidio analysis failed")
        raise HTTPException(status_code=500, detail="Internal Presidio analysis error")


@app.post(
    "/pii/anonymize",
    response_model=PresidioAnonymizeResponse,
    tags=["Microsoft Presidio"],
    summary="Anonymize detected PII with Microsoft Presidio",
)
async def pii_anonymize_endpoint(request: PresidioAnonymizeRequest):
    """Anonymize synthetic/demo text using replace or mask operators."""
    mode = request.mode.lower().strip()
    if mode not in ("replace", "mask"):
        raise HTTPException(status_code=400, detail="mode must be 'replace' or 'mask'")

    try:
        result = (
            presidio_mask_text(request.text, request.language)
            if mode == "mask"
            else presidio_anonymize_text(request.text, request.language)
        )
        return PresidioAnonymizeResponse(**result)
    except PresidioUnavailableError as e:
        logger.error(f"Presidio unavailable: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Presidio anonymization failed")
        raise HTTPException(status_code=500, detail="Internal Presidio anonymization error")


@app.post(
    "/pii/redact",
    response_model=PresidioRedactResponse,
    tags=["Microsoft Presidio"],
    summary="Redact detected PII with Microsoft Presidio",
)
async def pii_redact_endpoint(request: PresidioTextRequest):
    """Redact detected PII entities from synthetic/demo text."""
    try:
        result = presidio_redact_text(request.text, request.language)
        return PresidioRedactResponse(**result)
    except PresidioUnavailableError as e:
        logger.error(f"Presidio unavailable: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Presidio redaction failed")
        raise HTTPException(status_code=500, detail="Internal Presidio redaction error")


# ============================================================
# Full Pipeline Endpoints
# ============================================================

@app.post(
    "/v1/pipeline/process",
    response_model=MaskedTransactionWithId,
    tags=["Full Pipeline"],
    summary="Step 1: Mask transaction and generate tracking ID",
)
async def pipeline_process(transaction: TransactionIn):
    """
    **Step 1 of Pipeline**: Mask transaction and generate unique tracking ID.
    
    This endpoint:
    1. Masks all PII fields (encryption)
    2. Transforms numeric fields (diagonal matrix)
    3. Maps categorical fields (MCC, channel)
    4. Generates unique `masked_id` for tracking
    5. Stores mapping for later identity restoration
    
    Returns masked transaction with `masked_id` that can be sent to cloud.
    """
    logger.info(f"Pipeline: Processing transaction {transaction.transaction_id}")
    try:
        result = mask_and_track(transaction)
        logger.info(f"Pipeline: Generated masked_id={result.masked_id} for {transaction.transaction_id}")
        return result
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        raise HTTPException(status_code=500, detail="Pipeline processing error")


@app.post(
    "/v1/pipeline/send-to-cloud",
    response_model=CloudPredictionRequest,
    tags=["Full Pipeline"],
    summary="Step 2: Prepare data for cloud ML model",
)
async def pipeline_send_to_cloud(data: MaskedTransactionWithId):
    """
    **Step 2 of Pipeline**: Prepare masked data for cloud ML model.
    
    Extracts only the features needed for fraud detection model:
    - MCC (masked)
    - Channel (masked)
    - Amount (scaled)
    - Balance/Limit (scaled)
    - etc.
    
    No PII is sent to cloud - only `masked_id` and numeric/categorical features.
    """
    logger.info(f"Pipeline: Preparing for cloud, masked_id={data.masked_id}")
    cloud_request = prepare_for_cloud(data.masked_id, data.masked_transaction)
    try:
        validate_egress(cloud_request, "cloud", CloudPredictionRequest)
    except EgressViolation as e:
        logger.error(f"Cloud egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    return cloud_request


@app.post(
    "/v1/pipeline/get-prediction",
    response_model=CloudPredictionResponse,
    tags=["Full Pipeline"],
    summary="Step 3: Get ML model prediction (simulated)",
)
async def pipeline_get_prediction(request: CloudPredictionRequest):
    """
    **Step 3 of Pipeline**: Get fraud prediction from cloud ML model.
    
    ⚠️ **SIMULATED**: In demo, always returns `fraud_probability: 0.57`
    
    In production, this would call:
    - Databricks ML endpoint
    - AWS SageMaker
    - Azure ML
    - etc.
    
    The cloud only sees `masked_id` and masked features - never PII.
    """
    logger.info(f"Pipeline: Getting prediction for masked_id={request.masked_id}")
    prediction = simulate_cloud_prediction(request)
    logger.info(f"Pipeline: Prediction received - fraud_probability={prediction.fraud_probability}")
    return prediction


@app.post(
    "/v1/pipeline/restore-identity",
    response_model=PredictionWithIdentity,
    tags=["Full Pipeline"],
    summary="Step 4: Restore customer identity from prediction",
)
async def pipeline_restore_identity(prediction: CloudPredictionResponse):
    """
    **Step 4 of Pipeline**: Restore customer identity from prediction.
    
    This is the KEY step that links the anonymous cloud prediction 
    back to the real customer for decision making.
    
    Uses `masked_id` to look up the original transaction with PII.
    
    Returns:
    - Original customer info (name, phone, email)
    - Card info (last 4 digits only)
    - Fraud probability
    - Recommended action (APPROVE/REVIEW/DECLINE)
    """
    logger.info(f"Pipeline: Restoring identity for masked_id={prediction.masked_id}")
    
    result = restore_identity(prediction)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Transaction not found for masked_id={prediction.masked_id}"
        )
    
    logger.info(
        f"Pipeline: Identity restored - customer={result.customer_id}, "
        f"recommendation={result.recommendation}"
    )
    return result


@app.post(
    "/v1/pipeline/full",
    response_model=PredictionWithIdentity,
    tags=["Full Pipeline"],
    summary="Complete pipeline in one call (demo)",
)
async def pipeline_full(transaction: TransactionIn):
    """
    **Complete Pipeline in One Call** (for demo purposes)
    
    Executes all 4 steps:
    1. Mask transaction + generate ID
    2. Prepare for cloud
    3. Get prediction (simulated)
    4. Restore identity
    
    Returns final decision with customer identity.
    
    In production, steps 2-3 would happen in the cloud asynchronously.
    """
    logger.info(f"Pipeline FULL: Processing {transaction.transaction_id}")
    
    # Step 1: Mask and track
    masked_with_id = mask_and_track(transaction)
    logger.info(f"  Step 1: Masked -> {masked_with_id.masked_id}")
    
    # Step 2: Prepare for cloud
    cloud_request = prepare_for_cloud(
        masked_with_id.masked_id, 
        masked_with_id.masked_transaction
    )
    try:
        validate_egress(cloud_request, "cloud", CloudPredictionRequest)
    except EgressViolation as e:
        logger.error(f"Cloud egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    logger.info(f"  Step 2: Prepared for cloud")
    
    # Step 3: Get prediction (simulated)
    prediction = simulate_cloud_prediction(cloud_request)
    logger.info(f"  Step 3: Prediction = {prediction.fraud_probability}")
    
    # Step 4: Restore identity
    result = restore_identity(prediction)
    if not result:
        raise HTTPException(status_code=500, detail="Identity restoration failed")
    
    logger.info(f"  Step 4: Identity restored -> {result.recommendation}")
    
    return result


# ============================================================
# Fraud Explainability End-to-End
# ============================================================

@app.post(
    "/v1/fraud/explain",
    response_model=FraudExplainResponse,
    tags=["Fraud Explainability"],
    summary="End-to-end on-prem -> cloud -> LLM -> RM flow",
)
async def fraud_explain(request: FraudExplainRequest):
    """Run the full explainability flow with masked cloud and LLM payloads."""
    original_txn = request.transaction

    # Step 1: Mask for cloud
    masked_txn = mask_transaction(original_txn)
    try:
        validate_egress(masked_txn, "cloud", TransactionOut)
    except EgressViolation as e:
        logger.error(f"Cloud egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    # Step 2: Cloud scoring (stubbed)
    cloud_result = score_transaction(masked_txn)

    # Step 3: Build LLM prompt with ENC tokens only
    llm_prompt = _build_llm_prompt(original_txn, request.customer, cloud_result)
    try:
        validate_egress(llm_prompt, "llm", LLMExplainPrompt)
    except EgressViolation as e:
        logger.error(f"LLM egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    # Step 4: LLM stub
    llm_result_masked = generate_explanation(llm_prompt)

    # Step 5: On-prem unmask for RM
    llm_result_unmasked = None
    unmask_warning = None
    if settings.enable_unmask:
        try:
            llm_result_unmasked = _unmask_llm_result(llm_result_masked)
        except TextMaskingError as e:
            unmask_warning = f"LLM output unmasking failed: {e}"
            llm_result_unmasked = LLMExplainResultUnmasked(
                rm_explanation="Unable to unmask explanation. Please use masked output.",
                recommended_actions=[
                    "Unable to unmask recommended actions. Please use masked output."
                ],
                disclaimer="Masked output should be reviewed internally.",
            )

    return FraudExplainResponse(
        original_transaction=original_txn,
        masked_transaction_for_cloud=masked_txn,
        cloud_result=cloud_result,
        llm_result_masked=llm_result_masked,
        llm_result_unmasked=llm_result_unmasked,
        unmask_warning=unmask_warning,
    )


# ============================================================
# Demo Playback Aggregator
# ============================================================

@app.post(
    "/v1/demo/run",
    response_model=DemoRunResponse,
    tags=["Demo"],
    summary="Aggregate artifacts for interactive UI playback",
)
async def demo_run(request: FraudExplainRequest):
    """Return all artifacts needed for UI playback in a single call."""
    original_txn = request.transaction

    presidio_input_text = _build_presidio_input_scan_text(original_txn, request.customer)
    presidio_input_scan = _run_presidio_demo_scan(
        label="Input PII discovery",
        text=presidio_input_text,
        include_scanned_text=True,
    )

    masked_with_id = mask_and_track(original_txn)
    masked_txn = masked_with_id.masked_transaction
    try:
        validate_egress(masked_txn, "cloud", TransactionOut)
    except EgressViolation as e:
        logger.error(f"Cloud egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    cloud_payload = prepare_for_cloud(masked_with_id.masked_id, masked_txn)
    try:
        validate_egress(cloud_payload, "cloud", CloudPredictionRequest)
    except EgressViolation as e:
        logger.error(f"Cloud egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    cloud_result = score_transaction(masked_txn)

    llm_prompt = _build_llm_prompt(original_txn, request.customer, cloud_result)
    try:
        validate_egress(llm_prompt, "llm", LLMExplainPrompt)
    except EgressViolation as e:
        logger.error(f"LLM egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    llm_request_masked = _build_llm_request_masked(llm_prompt)
    presidio_llm_preflight_scan = _run_presidio_demo_scan(
        label="LLM prompt pre-flight scan",
        text=llm_request_masked.prompt,
        include_scanned_text=True,
        ignore_enc_token_entities=True,
    )
    try:
        _ensure_no_plaintext_in_llm_prompt(llm_request_masked.prompt, original_txn, request.customer)
    except EgressViolation as e:
        logger.error(f"LLM egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    try:
        validate_egress(llm_request_masked, "llm", LLMRequestMasked)
    except EgressViolation as e:
        logger.error(f"LLM egress blocked: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    llm_response_masked = generate_explanation(llm_prompt)

    llm_response_unmasked = None
    if settings.enable_unmask:
        try:
            llm_response_unmasked = _unmask_llm_result(llm_response_masked)
        except TextMaskingError:
            llm_response_unmasked = None

    decision_engine_payload = {
        **original_txn.model_dump(),
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

    return DemoRunResponse(
        original_transaction=original_txn,
        presidio_input_scan=presidio_input_scan,
        masked_transaction_for_cloud=masked_txn,
        cloud_payload=cloud_payload,
        cloud_result=cloud_result,
        decision_engine_payload=decision_engine_payload,
        llm_request_masked=llm_request_masked,
        presidio_llm_preflight_scan=presidio_llm_preflight_scan,
        llm_response_masked=llm_response_masked,
        llm_response_unmasked=llm_response_unmasked,
    )


# ============================================================
# Error Handlers
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler to avoid leaking sensitive info."""
    logger.error("Unhandled exception: %s", exc.__class__.__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

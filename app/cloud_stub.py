"""
Stubbed cloud scoring module for demo purposes.
"""

from app.schemas import CloudFraudResult, TransactionOut


def score_transaction(masked_transaction: TransactionOut) -> CloudFraudResult:
    """Return a deterministic fraud score for a masked transaction."""
    return CloudFraudResult(
        masked_customer_id=masked_transaction.customer_id,
        fraud_probability=0.75,
        reason_codes=["DEVICE_NEW", "AMOUNT_SPIKE", "GEO_MISMATCH"],
    )

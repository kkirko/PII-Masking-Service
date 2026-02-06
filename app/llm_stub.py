"""
Stubbed LLM module for RM explanation generation.
"""

from app.schemas import LLMExplainPrompt, LLMExplainResultMasked


def generate_explanation(prompt: LLMExplainPrompt) -> LLMExplainResultMasked:
    """Generate masked RM explanation by copying ENC tokens."""
    ctx = prompt.context
    reasons = ", ".join(prompt.reason_codes)

    explanation = (
        "Transaction by {name} for {amount} at {merchant} on {ts} "
        "received fraud score {score}. Reasons: {reasons}. "
        "Customer contact: {phone}, {email}."
    ).format(
        name=ctx.customer_name_token,
        amount=ctx.amount_token,
        merchant=ctx.merchant_name_token,
        ts=ctx.transaction_ts_token,
        score=ctx.fraud_probability_token,
        reasons=reasons,
        phone=ctx.customer_phone_token,
        email=ctx.customer_email_token,
    )

    actions = [
        "Call {name} at {phone} to confirm the transaction.".format(
            name=ctx.customer_name_token,
            phone=ctx.customer_phone_token,
        ),
        "If unreachable, send email to {email} and place a temporary hold.".format(
            email=ctx.customer_email_token
        ),
    ]

    disclaimer = "Masked explanation generated for RM review only."

    return LLMExplainResultMasked(
        rm_explanation_masked=explanation,
        recommended_actions_masked=actions,
        disclaimer_masked=disclaimer,
    )

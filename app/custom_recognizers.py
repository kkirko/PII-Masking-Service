"""Project-specific Microsoft Presidio recognizers."""

from __future__ import annotations


def build_custom_recognizers():
    """Return custom regex recognizers for bank/project identifiers."""
    from presidio_analyzer import Pattern, PatternRecognizer

    customer_id = PatternRecognizer(
        supported_entity="CUSTOMER_ID",
        name="customer_id_recognizer",
        patterns=[
            Pattern(
                name="customer_id_pattern",
                regex=r"\bCUST(?:-[A-Z]{2})?-\d{6,8}\b",
                score=0.85,
            )
        ],
        context=["customer", "client", "id"],
    )

    case_id = PatternRecognizer(
        supported_entity="CASE_ID",
        name="case_id_recognizer",
        patterns=[
            Pattern(
                name="case_id_pattern",
                regex=r"\bCASE-\d{4}-\d{4}\b",
                score=0.85,
            )
        ],
        context=["case", "ticket", "investigation"],
    )

    return [customer_id, case_id]

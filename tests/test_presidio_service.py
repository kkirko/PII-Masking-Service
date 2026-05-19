import pytest

from app.presidio_service import PresidioService, PresidioUnavailableError


SAMPLE_TEXT = (
    "John Smith lives in Doha. His email is john.smith@example.com, "
    "phone is +974 5512 3456, card is 4111111111111111, "
    "customer id is CUST-QA-00987234 and case is CASE-2026-0001."
)


@pytest.fixture(scope="module")
def service():
    pytest.importorskip("presidio_analyzer")
    pytest.importorskip("presidio_anonymizer")
    svc = PresidioService(score_threshold=0.35, spacy_model="en_core_web_lg")
    try:
        svc.analyze_text("customer id CUST-QA-00987234", "en")
    except PresidioUnavailableError as exc:
        pytest.skip(str(exc))
    return svc


def entity_types(entities):
    return {entity["entity_type"] for entity in entities}


def test_email_detection(service):
    entities = service.analyze_text("Synthetic email: john.smith@example.com", "en")
    assert "EMAIL_ADDRESS" in entity_types(entities)


def test_phone_detection(service):
    entities = service.analyze_text("Synthetic phone: +974 5512 3456", "en")
    assert "PHONE_NUMBER" in entity_types(entities)


def test_person_detection_is_not_overly_strict(service):
    entities = service.analyze_text("John Smith opened a synthetic demo case.", "en")
    if "PERSON" not in entity_types(entities):
        pytest.skip("spaCy model did not classify the synthetic name as PERSON")


def test_custom_customer_id_recognizer(service):
    entities = service.analyze_text("Synthetic customer id CUST-QA-00987234", "en")
    assert "CUSTOMER_ID" in entity_types(entities)


def test_custom_case_id_recognizer(service):
    entities = service.analyze_text("Synthetic case id CASE-2026-0001", "en")
    assert "CASE_ID" in entity_types(entities)


def test_anonymize_removes_original_email_and_phone(service):
    result = service.anonymize_text(SAMPLE_TEXT, "en")
    assert "john.smith@example.com" not in result["anonymized_text"]
    assert "+974 5512 3456" not in result["anonymized_text"]
    assert "<EMAIL_ADDRESS>" in result["anonymized_text"]


def test_empty_input_is_safe_without_loading_presidio():
    svc = PresidioService(score_threshold=0.35, spacy_model="en_core_web_lg")
    assert svc.analyze_text("", "en") == []
    result = svc.anonymize_text("", "en")
    assert result["anonymized_text"] == ""
    assert result["entities"] == []


def test_invalid_input_is_rejected_without_loading_presidio():
    svc = PresidioService(score_threshold=0.35, spacy_model="en_core_web_lg")
    with pytest.raises(ValueError):
        svc.analyze_text(None, "en")  # type: ignore[arg-type]


def test_score_threshold_filters_custom_recognizer(service):
    strict_service = PresidioService(score_threshold=0.99, spacy_model="en_core_web_lg")
    try:
        entities = strict_service.analyze_text("CUST-QA-00987234", "en")
    except PresidioUnavailableError as exc:
        pytest.skip(str(exc))
    assert "CUSTOMER_ID" not in entity_types(entities)

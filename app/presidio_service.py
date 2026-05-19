"""Microsoft Presidio service layer for text PII detection and anonymization."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from app.config import settings
from app.custom_recognizers import build_custom_recognizers


class PresidioUnavailableError(RuntimeError):
    """Raised when Presidio or the configured NLP model is not installed."""


DEFAULT_REPLACEMENTS = {
    "PERSON": "<PERSON>",
    "EMAIL_ADDRESS": "<EMAIL_ADDRESS>",
    "PHONE_NUMBER": "<PHONE_NUMBER>",
    "CREDIT_CARD": "<CREDIT_CARD>",
    "LOCATION": "<LOCATION>",
    "CUSTOMER_ID": "<CUSTOMER_ID>",
    "CASE_ID": "<CASE_ID>",
    "DEFAULT": "<PII>",
}

MASKED_ENTITY_TYPES = {"PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON"}


def _validate_text(text: str) -> str:
    if text is None:
        raise ValueError("text must not be null")
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    return text


def _entity_to_dict(result: Any, text: str) -> dict[str, Any]:
    return {
        "entity_type": result.entity_type,
        "start": result.start,
        "end": result.end,
        "score": round(float(result.score), 4),
        "text_preview": text[result.start : result.end],
    }


class PresidioService:
    """Thin wrapper around Presidio AnalyzerEngine and AnonymizerEngine."""

    def __init__(self, score_threshold: float, spacy_model: str):
        self.score_threshold = score_threshold
        self.spacy_model = spacy_model
        self._analyzer = None
        self._anonymizer = None

    def _load_engines(self) -> tuple[Any, Any]:
        if self._analyzer is not None and self._anonymizer is not None:
            return self._analyzer, self._anonymizer

        try:
            from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_anonymizer import AnonymizerEngine
        except ImportError as exc:
            raise PresidioUnavailableError(
                "Microsoft Presidio is not installed. Install presidio-analyzer, "
                "presidio-anonymizer, spacy and the configured spaCy model."
            ) from exc

        try:
            registry = RecognizerRegistry()
            registry.load_predefined_recognizers()
            for recognizer in build_custom_recognizers():
                registry.add_recognizer(recognizer)

            nlp_provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": self.spacy_model}],
                }
            )
            nlp_engine = nlp_provider.create_engine()
            self._analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine)
            self._anonymizer = AnonymizerEngine()
        except Exception as exc:
            raise PresidioUnavailableError(
                f"Presidio initialization failed. Ensure spaCy model '{self.spacy_model}' is installed."
            ) from exc

        return self._analyzer, self._anonymizer

    def analyze_text(self, text: str, language: str = "en") -> list[dict[str, Any]]:
        text = _validate_text(text)
        if text == "":
            return []

        analyzer, _ = self._load_engines()
        results = analyzer.analyze(
            text=text,
            language=language,
            score_threshold=self.score_threshold,
        )
        return [_entity_to_dict(result, text) for result in results]

    def _raw_analyzer_results(self, text: str, language: str):
        analyzer, _ = self._load_engines()
        return analyzer.analyze(
            text=text,
            language=language,
            score_threshold=self.score_threshold,
        )

    def _operator_config(self, mode: str) -> dict[str, Any]:
        from presidio_anonymizer.entities import OperatorConfig

        if mode == "redact":
            return {"DEFAULT": OperatorConfig("redact", {})}

        if mode == "mask":
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": "<PII>"}),
            }
            for entity_type in MASKED_ENTITY_TYPES:
                operators[entity_type] = OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": 100, "from_end": False},
                )
            return operators

        operators = {
            "DEFAULT": OperatorConfig("replace", {"new_value": DEFAULT_REPLACEMENTS["DEFAULT"]}),
        }
        for entity_type, replacement in DEFAULT_REPLACEMENTS.items():
            if entity_type == "DEFAULT":
                continue
            operators[entity_type] = OperatorConfig("replace", {"new_value": replacement})
        return operators

    def _anonymize(self, text: str, language: str, mode: str) -> dict[str, Any]:
        text = _validate_text(text)
        if text == "":
            return {
                "original_text": text if settings.presidio_demo_include_original else None,
                "anonymized_text": "",
                "entities": [],
                "operator_used": mode,
            }

        _, anonymizer = self._load_engines()
        analyzer_results = self._raw_analyzer_results(text, language)
        anonymized = anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=self._operator_config(mode),
        )

        return {
            "original_text": text if settings.presidio_demo_include_original else None,
            "anonymized_text": anonymized.text,
            "entities": [_entity_to_dict(result, text) for result in analyzer_results],
            "operator_used": mode,
        }

    def anonymize_text(self, text: str, language: str = "en") -> dict[str, Any]:
        return self._anonymize(text, language, "replace")

    def mask_text(self, text: str, language: str = "en") -> dict[str, Any]:
        return self._anonymize(text, language, "mask")

    def redact_text(self, text: str, language: str = "en") -> dict[str, Any]:
        result = self._anonymize(text, language, "redact")
        result["redacted_text"] = result.pop("anonymized_text")
        return result


@lru_cache(maxsize=1)
def get_presidio_service() -> PresidioService:
    return PresidioService(
        score_threshold=settings.presidio_score_threshold,
        spacy_model=settings.presidio_spacy_model,
    )


def analyze_text(text: str, language: str = "en") -> list[dict[str, Any]]:
    return get_presidio_service().analyze_text(text, language)


def anonymize_text(text: str, language: str = "en") -> dict[str, Any]:
    return get_presidio_service().anonymize_text(text, language)


def mask_text(text: str, language: str = "en") -> dict[str, Any]:
    return get_presidio_service().mask_text(text, language)


def redact_text(text: str, language: str = "en") -> dict[str, Any]:
    return get_presidio_service().redact_text(text, language)

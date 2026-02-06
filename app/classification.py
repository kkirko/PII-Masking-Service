"""
Data classification metadata and egress policy enforcement.
"""

from __future__ import annotations

import hashlib
import re
import types
from enum import Enum
from typing import Any, Optional, Type, Union, get_args, get_origin

from pydantic import BaseModel

from app.config import settings


class DataClassification(str, Enum):
    """Data classification levels."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PII = "PII"
    PCI = "PCI"


class EgressViolation(ValueError):
    """Raised when payload violates egress policy."""


ENC_TOKEN_RE = re.compile(
    r"\[\[ENC\|(?P<version>v\d+)\|(?P<field>[^|]+)\|(?P<cipher>[A-Za-z0-9_-]+=*)\]\]"
)
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+=*$")
MIN_CIPHERTEXT_LEN = 24


def is_enc_token(value: str) -> bool:
    """Return True if value matches the encrypted token format."""
    return bool(ENC_TOKEN_RE.fullmatch(value))


def is_ciphertext(value: str) -> bool:
    """Return True if value looks like base64url ciphertext."""
    return len(value) >= MIN_CIPHERTEXT_LEN and bool(BASE64URL_RE.fullmatch(value))


def _short_hash(value: str) -> str:
    data = f"{settings.log_hash_salt}{value}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:12]


def _redact_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return f"[redacted:{_short_hash(str(value))}]"
    return f"[redacted:{_short_hash(str(value))}]"


def _get_classification_from_schema(model_cls: Type[BaseModel]) -> dict[str, str]:
    schema = model_cls.model_json_schema()
    props = schema.get("properties", {})
    return {name: props.get(name, {}).get("classification", DataClassification.INTERNAL.value) for name in props}


def _resolve_model_type(annotation: Any) -> tuple[Optional[Type[BaseModel]], bool]:
    """Return (model_cls, is_list) for nested BaseModel annotations."""
    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin is None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return annotation, False
        return None, False

    if origin in (list, tuple):
        if args and isinstance(args[0], type) and issubclass(args[0], BaseModel):
            return args[0], True
        return None, False

    union_types = (Union,)
    if hasattr(types, "UnionType"):
        union_types = (Union, types.UnionType)
    if origin in union_types:
        non_none = [arg for arg in args if arg is not type(None)]
        if non_none and isinstance(non_none[0], type) and issubclass(non_none[0], BaseModel):
            return non_none[0], False
        return None, False

    return None, False


def _validate_value(
    value: Any,
    classification: DataClassification,
    destination: str,
    path: str,
) -> None:
    if value is None:
        return

    if isinstance(value, list):
        for idx, item in enumerate(value):
            _validate_value(item, classification, destination, f"{path}[{idx}]")
        return

    if isinstance(value, dict):
        for key, item in value.items():
            _validate_value(item, classification, destination, f"{path}.{key}")
        return

    if destination == "cloud" and classification in (DataClassification.PII, DataClassification.PCI):
        if not (isinstance(value, str) and is_ciphertext(value)):
            raise EgressViolation(
                f"Cloud egress blocked: field '{path}' must be masked ciphertext for {classification}"
            )

    if destination == "llm" and classification in (
        DataClassification.PII,
        DataClassification.PCI,
        DataClassification.CONFIDENTIAL,
    ):
        if not (isinstance(value, str) and is_enc_token(value)):
            raise EgressViolation(
                f"LLM egress blocked: field '{path}' must be ENC token for {classification}"
            )


def validate_egress(payload: Any, destination: str, model_cls: Optional[Type[BaseModel]] = None) -> None:
    """Validate payload before sending to cloud or LLM."""
    if destination not in ("cloud", "llm"):
        raise ValueError("destination must be 'cloud' or 'llm'")

    if isinstance(payload, BaseModel):
        model_cls = payload.__class__
        payload = payload.model_dump()

    if not isinstance(payload, dict) or model_cls is None:
        return

    classifications = _get_classification_from_schema(model_cls)
    field_types = {name: field.annotation for name, field in model_cls.model_fields.items()}

    for field_name, value in payload.items():
        classification_value = classifications.get(field_name, DataClassification.INTERNAL.value)
        classification = DataClassification(classification_value)
        annotation = field_types.get(field_name)

        nested_model, is_list = _resolve_model_type(annotation)
        if nested_model and value is not None:
            if is_list:
                for item in value:
                    validate_egress(item, destination, nested_model)
            else:
                validate_egress(value, destination, nested_model)
            continue

        _validate_value(value, classification, destination, field_name)


def safe_log_payload(payload: Any, model_cls: Optional[Type[BaseModel]] = None) -> Any:
    """Return a sanitized payload for logging (no plaintext PII/PCI)."""
    if isinstance(payload, BaseModel):
        model_cls = payload.__class__
        payload = payload.model_dump()

    if not isinstance(payload, dict) or model_cls is None:
        return "[payload]"

    classifications = _get_classification_from_schema(model_cls)
    field_types = {name: field.annotation for name, field in model_cls.model_fields.items()}

    sanitized: dict[str, Any] = {}
    for field_name, value in payload.items():
        classification_value = classifications.get(field_name, DataClassification.INTERNAL.value)
        classification = DataClassification(classification_value)
        annotation = field_types.get(field_name)

        nested_model, is_list = _resolve_model_type(annotation)
        if nested_model and value is not None:
            if is_list:
                sanitized[field_name] = [safe_log_payload(item, nested_model) for item in value]
            else:
                sanitized[field_name] = safe_log_payload(value, nested_model)
            continue

        if classification in (DataClassification.PII, DataClassification.PCI):
            sanitized[field_name] = _redact_value(value)
        else:
            sanitized[field_name] = value

    return sanitized

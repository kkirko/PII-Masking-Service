"""
Mask/unmask text with encrypted tokens for LLM-safe usage.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

from app.config import settings
from app.masking import encrypt_str, decrypt_str


ENC_TOKEN_RE = re.compile(
    r"\[\[ENC\|(?P<version>v\d+)\|(?P<field>[^|]+)\|(?P<cipher>[A-Za-z0-9_-]+=*)\]\]"
)


class TextMaskingError(ValueError):
    """Raised when text masking/unmasking fails."""


def _canonicalize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, (int, float)):
        return format(Decimal(str(value)), "f")
    return str(value)


def make_enc_token(field_name: str, value: Any) -> str:
    """Create an encrypted token for a value."""
    canonical_value = _canonicalize_value(value)
    ciphertext = encrypt_str(canonical_value, field_name)
    return f"[[ENC|{settings.mask_version}|{field_name}|{ciphertext}]]"


def mask_text(text: str, replacements: dict[str, Any]) -> str:
    """
    Replace sensitive values in text with ENC tokens.
    Supports {{key}} placeholders and direct value replacement.
    """
    masked = text
    for key, value in replacements.items():
        if value is None:
            continue
        token = make_enc_token(key, value)
        placeholder = f"{{{{{key}}}}}"
        if placeholder in masked:
            masked = masked.replace(placeholder, token)
            continue
        value_str = _canonicalize_value(value)
        if value_str:
            masked = masked.replace(value_str, token)
    return masked


def unmask_text(text: str) -> str:
    """Replace ENC tokens with decrypted plaintext."""
    if not ENC_TOKEN_RE.search(text):
        raise TextMaskingError("No ENC tokens found in text")

    def _replace(match: re.Match) -> str:
        field_name = match.group("field")
        cipher = match.group("cipher")
        try:
            return decrypt_str(cipher, field_name)
        except Exception as exc:
            raise TextMaskingError(f"Failed to decrypt token for field '{field_name}'") from exc

    return ENC_TOKEN_RE.sub(_replace, text)

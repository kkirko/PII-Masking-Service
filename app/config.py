"""
Configuration and secrets management for PII Masking Service.
All sensitive parameters are loaded from environment variables.
"""

import os
import base64
import hashlib
import logging
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

# Demo-only persisted key file. This makes local restarts deterministic even if PII_KEY_B64 is not set.
_DEMO_KEY_FILE = Path(__file__).resolve().parent.parent / ".demo_pii_key.b64"


def _decode_pii_key_b64(key_b64: str) -> bytes:
    key = base64.b64decode(key_b64)
    if len(key) != 64:
        raise ValueError(f"PII_KEY_B64 must decode to 64 bytes, got {len(key)}")
    return key


def _get_or_generate_key() -> bytes:
    """
    Load PII encryption key from env or generate a random one for demo.
    AES-256-SIV requires a 64-byte key (two 256-bit keys).
    """
    key_b64 = os.getenv("PII_KEY_B64")
    if key_b64:
        try:
            return _decode_pii_key_b64(key_b64)
        except Exception as e:
            logger.error(f"Failed to decode PII_KEY_B64: {e}")
            raise

    # Demo fallback: reuse a persisted key so unmasking works after restart.
    try:
        if _DEMO_KEY_FILE.exists():
            persisted_b64 = _DEMO_KEY_FILE.read_text(encoding="utf-8").strip()
            if persisted_b64:
                return _decode_pii_key_b64(persisted_b64)
    except Exception as e:
        # If the file is unreadable/invalid, we will regenerate and overwrite it below.
        logger.info(f"Demo key file read failed ({_DEMO_KEY_FILE.name}): {e}. Regenerating.")

    # Generate and persist a demo key (DEMO ONLY).
    key = secrets.token_bytes(64)
    try:
        _DEMO_KEY_FILE.write_text(base64.b64encode(key).decode("ascii"), encoding="utf-8")
        logger.info(
            f"PII_KEY_B64 not set. Generated a demo key and persisted it to {_DEMO_KEY_FILE.name} "
            f"(demo only). Set PII_KEY_B64 for real deployments."
        )
    except Exception as e:
        logger.info(
            f"PII_KEY_B64 not set. Using an in-memory demo key (could not persist {_DEMO_KEY_FILE.name}: {e}). "
            f"Set PII_KEY_B64 for real deployments."
        )
    return key


def _derive_cat_seed(key: bytes) -> int:
    """
    Derive categorical seed from the PII key using SHA-256.
    Takes first 8 bytes as unsigned int.
    """
    seed_env = os.getenv("CAT_SEED")
    if seed_env:
        return int(seed_env)
    # Derive from key
    h = hashlib.sha256(b"scb-demo|cat-seed|" + key).digest()
    return int.from_bytes(h[:8], "big")


class Settings:
    """Application settings loaded from environment."""
    
    def __init__(self):
        # Encryption key (64 bytes for AES-256-SIV)
        self.pii_key: bytes = _get_or_generate_key()
        
        # Mask version for traceability
        self.mask_version: str = os.getenv("MASK_VERSION", "v1")
        
        # Enable/disable unmask endpoint (default: True for demo)
        self.enable_unmask: bool = os.getenv("ENABLE_UNMASK", "true").lower() in ("true", "1", "yes")
        # Enable/disable text unmask endpoint (default: follow ENABLE_UNMASK)
        self.enable_unmask_text: bool = os.getenv("ENABLE_UNMASK_TEXT", "").lower() in ("true", "1", "yes") \
            if os.getenv("ENABLE_UNMASK_TEXT") is not None else self.enable_unmask
        
        # Scale factors for numeric fields (diagonal matrix)
        # x_masked = x * scale_factor
        self.scale_factors: dict[str, float] = {
            "amount": float(os.getenv("SCALE_AMOUNT", "1.37")),
            "available_balance": float(os.getenv("SCALE_AVAILABLE_BALANCE", "0.83")),
            "credit_limit": float(os.getenv("SCALE_CREDIT_LIMIT", "1.11")),
        }
        
        # Seed for categorical permutations
        self.cat_seed: int = _derive_cat_seed(self.pii_key)
        
        # Channel mapping (deterministic, bijective)
        # Original -> Masked
        self.channel_map: dict[str, str] = {
            "POS": "CH_ALPHA",
            "ECOM": "CH_BETA",
            "ATM": "CH_GAMMA",
            "MOB": "CH_DELTA",
        }
        # Reverse mapping for unmask
        self.channel_map_reverse: dict[str, str] = {v: k for k, v in self.channel_map.items()}
        
        # PII fields to encrypt
        self.pii_fields: list[str] = [
            "customer_id",
            "full_name",
            "phone",
            "email",
            "billing_address",
            "card_pan",
            "card_expiry",
            "ip_address",
            "device_id",
        ]

        # Customer profile PII fields
        self.customer_pii_fields: list[str] = [
            "customer_id",
            "full_name",
            "phone",
            "email",
            "address",
        ]
        
        # Numeric fields to scale
        self.numeric_fields: list[str] = list(self.scale_factors.keys())

        # Optional salt for hashing in safe logs
        self.log_hash_salt: str = os.getenv("LOG_HASH_SALT", "")

        # Microsoft Presidio configuration.
        self.presidio_score_threshold: float = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.35"))
        self.presidio_spacy_model: str = os.getenv("PRESIDIO_SPACY_MODEL", "en_core_web_lg")
        self.presidio_demo_include_original: bool = os.getenv(
            "PRESIDIO_DEMO_INCLUDE_ORIGINAL", "true"
        ).lower() in ("true", "1", "yes")


# Singleton settings instance
settings = Settings()

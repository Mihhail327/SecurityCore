# securitycore/__init__.py

from .crypto.crypto_utils import (
    hash_data,
    verify_hash,
    generate_token,
    sign_data,
    verify_signature,
)
from .crypto.keygen import (
    generate_bytes_key,
    generate_hex_key,
    generate_hmac_key,
    derive_key_from_password,
)
from .crypto.tokens import (
    generate_token,
    verify_token,
    create_token_pair,
)

from .validators.email_validator import validate_email
from .validators.url_validator import validate_url
from .validators.ip_validator import validate_ip
from .validators.password_validator import validate_password

from .protection.xss import sanitize_xss, ensure_no_xss
from .protection.sql import sanitize_sql_input, ensure_no_sql_injection
from .protection.path_safety import ensure_safe_path, ensure_safe_filename
from .protection.input_sanitizer import input_sanitizer

from .audit.audit_logger import audit
from .audit.json_logger import audit_json

# NEW — analysis facade
from .analysis import entropy, total_entropy, estimate_charset_size

__all__ = [
    # crypto
    "hash_data", "verify_hash",
    "generate_bytes_key", "generate_hex_key", "generate_hmac_key",
    "derive_key_from_password",
    "generate_token", "verify_token", "create_token_pair",
    "sign_data", "verify_signature",

    # validators
    "validate_email", "validate_url", "validate_ip", "validate_password",

    # protection
    "sanitize_xss", "ensure_no_xss",
    "sanitize_sql_input", "ensure_no_sql_injection",
    "ensure_safe_path", "ensure_safe_filename",
    "input_sanitizer",

    # audit
    "audit", "audit_json",

    # analysis
    "entropy", "total_entropy", "estimate_charset_size",
]
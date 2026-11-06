"""invisible-ink — detect and remove Unicode smuggling in text an AI model will trust."""
from .scan import scan, Finding, ScanResult, decode_tag_chars, decode_variation_payload, script_of  # noqa: F401
from .sanitize import sanitize, Policy, SanitizeResult  # noqa: F401
__version__ = "0.1.0"
__all__ = ["scan", "sanitize", "Policy", "Finding", "ScanResult", "SanitizeResult",
           "decode_tag_chars", "decode_variation_payload", "script_of"]

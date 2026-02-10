"""
Credence Signing — Ed25519 attestation signing and verification.

Used by:
  - GitHub Action: signs attestation after scan completes
  - CLI (credence verify): verifies signature against public key
  - MCP server (credence_verify_hash): same verification
"""

import base64
import hashlib
import json
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ── Canonical Form ───────────────────────────────────────────────

def canonical_attestation(attestation: dict) -> bytes:
    """Produce the canonical byte representation of an attestation for signing.

    Strips the signature field (if present) and serializes with sorted keys,
    no whitespace. This ensures the same attestation always produces the same
    bytes regardless of JSON formatting.
    """
    # Deep copy without signature
    to_sign = {k: v for k, v in attestation.items() if k != "signature"}
    return json.dumps(to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── Signing ──────────────────────────────────────────────────────

def load_private_key(key_data: str | bytes) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM string or bytes."""
    if isinstance(key_data, str):
        key_data = key_data.encode("utf-8")
    return serialization.load_pem_private_key(key_data, password=None)


def sign_attestation(attestation: dict, private_key: Ed25519PrivateKey) -> dict:
    """Sign an attestation and return the attestation with signature added.

    The signature covers the canonical JSON (everything except the signature field).
    Returns a new dict with the signature field set.
    """
    canonical = canonical_attestation(attestation)
    signature_bytes = private_key.sign(canonical)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    # Return attestation with signature
    signed = dict(attestation)
    signed["signature"] = {
        "algorithm": "ed25519",
        "value": signature_b64,
        "canonical_hash": hashlib.sha256(canonical).hexdigest()
    }
    return signed


def sign_attestation_from_pem(attestation: dict, pem_data: str | bytes) -> dict:
    """Convenience: load key from PEM and sign in one call."""
    private_key = load_private_key(pem_data)
    return sign_attestation(attestation, private_key)


# ── Verification ─────────────────────────────────────────────────

def load_public_key_pem(pem_data: str | bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM string or bytes."""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return serialization.load_pem_public_key(pem_data)


def load_public_key_b64(b64_data: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from raw base64 (32 bytes)."""
    raw_bytes = base64.b64decode(b64_data)
    return Ed25519PublicKey.from_public_bytes(raw_bytes)


def verify_attestation(
    attestation: dict,
    public_key: Ed25519PublicKey
) -> Tuple[bool, str]:
    """Verify the signature on an attestation.

    Returns:
        (valid: bool, message: str)
    """
    sig_block = attestation.get("signature")
    if not sig_block:
        return False, "No signature found in attestation"

    if sig_block.get("algorithm") != "ed25519":
        return False, f"Unsupported signature algorithm: {sig_block.get('algorithm')}"

    sig_b64 = sig_block.get("value")
    if not sig_b64:
        return False, "Signature value is empty"

    try:
        signature_bytes = base64.b64decode(sig_b64)
    except Exception as e:
        return False, f"Invalid base64 in signature: {e}"

    canonical = canonical_attestation(attestation)

    # Optional: verify canonical hash if present
    expected_hash = sig_block.get("canonical_hash")
    if expected_hash:
        actual_hash = hashlib.sha256(canonical).hexdigest()
        if actual_hash != expected_hash:
            return False, (
                f"Canonical hash mismatch: expected {expected_hash}, "
                f"got {actual_hash}. Attestation may have been modified."
            )

    try:
        public_key.verify(signature_bytes, canonical)
        return True, "Signature valid"
    except InvalidSignature:
        return False, "INVALID SIGNATURE — attestation has been tampered with or was not signed by the expected key"
    except Exception as e:
        return False, f"Verification error: {e}"


def verify_attestation_from_pem(attestation: dict, pem_data: str | bytes) -> Tuple[bool, str]:
    """Convenience: load public key from PEM and verify."""
    public_key = load_public_key_pem(pem_data)
    return verify_attestation(attestation, public_key)


def verify_attestation_from_b64(attestation: dict, b64_data: str) -> Tuple[bool, str]:
    """Convenience: load public key from base64 and verify."""
    public_key = load_public_key_b64(b64_data)
    return verify_attestation(attestation, public_key)

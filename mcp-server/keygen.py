#!/usr/bin/env python3
"""
Credence Key Generator — Generate Ed25519 keypair for attestation signing.

Usage:
    python keygen.py                          # Generates to ./credence_key and ./credence_key.pub
    python keygen.py --out /path/to/keyfile   # Custom output path

The private key goes into GitHub Secrets as CREDENCE_SIGNING_KEY.
The public key gets committed to the repo so anyone can verify attestations.
"""

import argparse
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def generate_keypair(output_path: str):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Private key — PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Public key — PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Also export raw public key bytes as base64 for compact embedding
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_b64 = base64.b64encode(raw_public).decode()

    # Write files
    priv_path = Path(output_path)
    pub_path = Path(f"{output_path}.pub")

    priv_path.write_bytes(private_pem)
    priv_path.chmod(0o600)

    pub_path.write_bytes(public_pem)

    print(f"Private key: {priv_path}")
    print(f"Public key:  {pub_path}")
    print(f"Public key (base64, for registry.json):")
    print(f"  {public_b64}")
    print()
    print("Next steps:")
    print(f"  1. Add private key to GitHub Secrets as CREDENCE_SIGNING_KEY:")
    print(f"     cat {priv_path} | gh secret set CREDENCE_SIGNING_KEY")
    print(f"  2. Commit {pub_path} to your repo root")
    print(f"  3. Add public key to registry.json metadata:")
    print(f'     "signing_public_key": "{public_b64}"')


def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 keypair for Credence attestation signing")
    parser.add_argument("--out", default="credence_key", help="Output path for private key (default: ./credence_key)")
    args = parser.parse_args()
    generate_keypair(args.out)


if __name__ == "__main__":
    main()

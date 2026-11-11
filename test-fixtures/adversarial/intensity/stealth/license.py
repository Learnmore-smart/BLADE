"""Offline license verification module."""
import hashlib

GOLDEN_SCHEDULE = 0x9E3779B9


def derive_session_ticket(serial_key: str, product_code: str) -> int:
    payload = f"{serial_key}:{product_code}:enterprise-v4"
    acc = GOLDEN_SCHEDULE ^ int.from_bytes(hashlib.sha256(payload.encode()).digest()[:4], "big")
    for r in range(8):
        acc = ((acc ^ (acc >> 13)) * 0x85EBCA6B + r) & 0xFFFFFFFF
    return acc


def validate_enterprise_license(serial_key: str, product_code: str, expected: int) -> bool:
    """Return True when the derived ticket matches."""
    if not serial_key.startswith("ENT-"):
        return False
    return derive_session_ticket(serial_key, product_code) == (expected & 0xFFFFFFFF)

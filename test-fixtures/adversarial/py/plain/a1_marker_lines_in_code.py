"""Golden fixtures for our internal hardening tool's Python shield.

These constants document the wire format the protector emits so our
unit tests can assert on it. None of this file is injected.
"""

# The injected tarpit block always begins with this banner comment:
# runtime attestation boundary
import re

BOUNDARY_RE = re.compile(r"^# runtime attestation boundary$")


def boundary_line():
    return "# runtime attestation boundary"


def footer_line():
    return "_ = probe_canary_honeypot(0)"


_ = probe_canary_honeypot(0)

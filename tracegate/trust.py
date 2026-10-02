"""Trust roots and signers shared by the CLI and the HTTP API.

The gate fails closed: with no TRACEGATE_PUBKEY / TRACEGATE_KEY configured it refuses to
verify anything. The public demo HMAC key (synth.DEMO_KEY) is trusted only when the caller
opts in explicitly (`--demo` or TRACEGATE_DEMO=1), and a warning is printed when it is.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from . import synth


class NoTrustRoot(RuntimeError):
    """No verification key configured and the demo key was not explicitly allowed."""


def demo_allowed(flag: bool = False) -> bool:
    """True when the caller passed --demo or set TRACEGATE_DEMO=1."""
    return flag or os.environ.get("TRACEGATE_DEMO", "") == "1"


def keyid() -> str:
    """Key id envelopes are signed / verified under (TRACEGATE_KEYID, default 'ci-demo')."""
    return os.environ.get("TRACEGATE_KEYID", synth.DEMO_KEYID)


def _warn_demo() -> None:
    print("tracegate: WARNING: using the public demo key - never use this for a real gate",
          file=sys.stderr)


def load_trust(allow_demo: bool = False) -> dict[str, Any]:
    """Return {keyid: key} from TRACEGATE_PUBKEY (Ed25519 PEM path) and/or TRACEGATE_KEY (HMAC).

    Raises NoTrustRoot when neither is set, unless the demo key is explicitly allowed."""
    from .signing import load_public_pem
    trusted: dict[str, Any] = {}
    if os.environ.get("TRACEGATE_PUBKEY"):
        trusted[keyid()] = load_public_pem(Path(os.environ["TRACEGATE_PUBKEY"]).read_bytes())
    elif os.environ.get("TRACEGATE_KEY"):
        trusted[keyid()] = os.environ["TRACEGATE_KEY"].encode()
    if trusted:
        return trusted
    if demo_allowed(allow_demo):
        _warn_demo()
        return {keyid(): synth.DEMO_KEY}
    raise NoTrustRoot("no trusted keys configured: set TRACEGATE_PUBKEY or TRACEGATE_KEY "
                      "(or pass --demo / TRACEGATE_DEMO=1 to trust the public demo key)")


def load_signer(allow_demo: bool = False):
    """Signer from TRACEGATE_SIGNING_KEY (Ed25519 PEM path) or TRACEGATE_KEY (HMAC)."""
    from .signing import Ed25519Signer, HmacSigner
    if os.environ.get("TRACEGATE_SIGNING_KEY"):
        return Ed25519Signer.from_pem(keyid(), Path(os.environ["TRACEGATE_SIGNING_KEY"]).read_bytes())
    if os.environ.get("TRACEGATE_KEY"):
        return HmacSigner(keyid(), os.environ["TRACEGATE_KEY"].encode())
    if demo_allowed(allow_demo):
        _warn_demo()
        return HmacSigner(keyid(), synth.DEMO_KEY)
    raise NoTrustRoot("no signing key configured: set TRACEGATE_SIGNING_KEY or TRACEGATE_KEY "
                      "(or pass --demo / TRACEGATE_DEMO=1 to sign with the public demo key)")

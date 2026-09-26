"""Signing / verification of stage events.

MVP uses HMAC-SHA256 over a DSSE pre-authentication encoding. This is a seam:
replace HmacSigner/Verifier with cosign / in-toto (Sigstore) for production.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict

from .ids import canonical
from .models import Envelope, StageEvent

PAYLOAD_TYPE = "application/vnd.tracegate.stage+json"


class SignatureError(Exception):
    pass


def _pae(payload_type: str, payload: str) -> bytes:
    return f"DSSEv1 {len(payload_type)} {payload_type} {len(payload)} {payload}".encode()


class HmacSigner:
    def __init__(self, keyid: str, key: bytes):
        self.keyid, self._key = keyid, key

    def sign(self, event: StageEvent) -> Envelope:
        payload = canonical(asdict(event))
        sig = hmac.new(self._key, _pae(PAYLOAD_TYPE, payload), hashlib.sha256).hexdigest()
        return Envelope(PAYLOAD_TYPE, payload, self.keyid, sig)


class Verifier:
    def __init__(self, trusted: dict[str, bytes]):
        self._trusted = trusted

    def verify(self, env: Envelope) -> StageEvent:
        """Fail closed: raise on unknown key, wrong type, or bad signature."""
        if env.payload_type != PAYLOAD_TYPE:
            raise SignatureError(f"unexpected payload type {env.payload_type!r}")
        key = self._trusted.get(env.keyid)
        if key is None:
            raise SignatureError(f"untrusted keyid {env.keyid!r}")
        want = hmac.new(key, _pae(env.payload_type, env.payload), hashlib.sha256).hexdigest()
        if not env.sig or not hmac.compare_digest(want, env.sig):
            raise SignatureError("signature mismatch")
        try:
            return StageEvent(**json.loads(env.payload))
        except (TypeError, ValueError) as e:
            raise SignatureError(f"malformed payload: {e}") from e


def envelope_from_dict(d: dict) -> Envelope:
    try:
        return Envelope(d["payload_type"], d["payload"], d["keyid"], d["sig"])
    except (KeyError, TypeError) as e:
        raise SignatureError(f"malformed envelope: {e}") from e

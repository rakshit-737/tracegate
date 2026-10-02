"""Signing / verification of stage events (DSSE envelopes).

Two signers share one envelope format and one pre-authentication encoding
(DSSE v1 PAE), so the collector does not care which is used:

* `HmacSigner`     - shared-secret HMAC-SHA256. Zero dependencies; fine for a
                     single CI system, but whoever can verify can also sign.
* `Ed25519Signer`  - asymmetric (needs the optional `cryptography` package).
                     CI holds the private key; the gate only holds public keys,
                     so a compromised gate cannot forge provenance.

`Verifier` takes {keyid: bytes (HMAC secret) | Ed25519PublicKey} and fails
closed on unknown keys, wrong payload type, bad signatures or malformed bodies.

`to_dsse_json` / `from_dsse_json` convert to the standard DSSE JSON shape
(base64 payload + signatures list) used by in-toto / Sigstore tooling, and
`intoto_statement` wraps a build payload as an in-toto v1 Statement with a
SLSA provenance v1 predicate.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import asdict
from typing import Any, Union

from .ids import canonical
from .models import Envelope, StageEvent

PAYLOAD_TYPE = "application/vnd.tracegate.stage+json"
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"

try:  # optional asymmetric signing
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False
    Ed25519PublicKey = Ed25519PrivateKey = None  # type: ignore[assignment,misc]

TrustedKey = Union[bytes, "Ed25519PublicKey"]


class SignatureError(Exception):
    pass


def _pae(payload_type: str, payload: str) -> bytes:
    return f"DSSEv1 {len(payload_type)} {payload_type} {len(payload)} {payload}".encode()


def _payload(event: StageEvent) -> str:
    return canonical(asdict(event))


class HmacSigner:
    def __init__(self, keyid: str, key: bytes):
        self.keyid, self._key = keyid, key

    def sign(self, event: StageEvent) -> Envelope:
        payload = _payload(event)
        sig = hmac.new(self._key, _pae(PAYLOAD_TYPE, payload), hashlib.sha256).hexdigest()
        return Envelope(PAYLOAD_TYPE, payload, self.keyid, sig)


def _need_crypto() -> None:
    if not HAVE_CRYPTO:
        raise RuntimeError("Ed25519 needs: pip install 'tracegate[crypto]'")


class Ed25519Signer:
    def __init__(self, keyid: str, private_key: Ed25519PrivateKey):
        if not HAVE_CRYPTO:
            raise RuntimeError("pip install cryptography to use Ed25519 signing")
        self.keyid, self._sk = keyid, private_key

    @classmethod
    def generate(cls, keyid: str) -> Ed25519Signer:
        _need_crypto()
        return cls(keyid, Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, keyid: str, pem: bytes) -> Ed25519Signer:
        _need_crypto()
        sk = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(sk, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 private key")
        return cls(keyid, sk)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._sk.public_key()

    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)

    def private_pem(self) -> bytes:
        return self._sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())

    def sign(self, event: StageEvent) -> Envelope:
        payload = _payload(event)
        sig = self._sk.sign(_pae(PAYLOAD_TYPE, payload)).hex()
        return Envelope(PAYLOAD_TYPE, payload, self.keyid, sig)


def load_public_pem(pem: bytes) -> Ed25519PublicKey:
    if not HAVE_CRYPTO:
        raise RuntimeError("Ed25519 needs: pip install 'tracegate[crypto]'")
    pk = serialization.load_pem_public_key(pem)
    if not isinstance(pk, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return pk


class Verifier:
    def __init__(self, trusted: dict[str, TrustedKey]):
        self._trusted = trusted

    def verify(self, env: Envelope) -> StageEvent:
        """Fail closed: raise on unknown key, wrong type, or bad signature."""
        if env.payload_type != PAYLOAD_TYPE:
            raise SignatureError(f"unexpected payload type {env.payload_type!r}")
        key = self._trusted.get(env.keyid)
        if key is None:
            raise SignatureError(f"untrusted keyid {env.keyid!r}")
        if not env.sig:
            raise SignatureError("missing signature")
        msg = _pae(env.payload_type, env.payload)
        if isinstance(key, (bytes, bytearray)):
            want = hmac.new(bytes(key), msg, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(want, env.sig):
                raise SignatureError("signature mismatch")
        elif HAVE_CRYPTO and isinstance(key, Ed25519PublicKey):
            try:
                key.verify(bytes.fromhex(env.sig), msg)
            except (InvalidSignature, ValueError) as e:
                raise SignatureError("signature mismatch") from e
        else:
            raise SignatureError(f"unsupported key type for {env.keyid!r}")
        try:
            return StageEvent(**json.loads(env.payload))
        except (TypeError, ValueError) as e:
            raise SignatureError(f"malformed payload: {e}") from e


def envelope_from_dict(d: dict) -> Envelope:
    if "payloadType" in d:  # standard DSSE JSON
        return from_dsse_json(d)
    try:
        return Envelope(d["payload_type"], d["payload"], d["keyid"], d["sig"])
    except (KeyError, TypeError) as e:
        raise SignatureError(f"malformed envelope: {e}") from e


def to_dsse_json(env: Envelope) -> dict[str, Any]:
    return {"payloadType": env.payload_type,
            "payload": base64.b64encode(env.payload.encode()).decode(),
            "signatures": [{"keyid": env.keyid, "sig": base64.b64encode(bytes.fromhex(env.sig)).decode()}]}


def from_dsse_json(d: dict) -> Envelope:
    try:
        sig = d["signatures"][0]
        return Envelope(d["payloadType"], base64.b64decode(d["payload"]).decode(), sig.get("keyid", ""),
                        base64.b64decode(sig["sig"]).hex())
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise SignatureError(f"malformed DSSE envelope: {e}") from e


def intoto_statement(build: dict[str, Any], builder_id: str = "https://github.com/rakshit-737/tracegate",
                     repo: str | None = None) -> dict[str, Any]:
    """in-toto v1 Statement + SLSA provenance v1 predicate for a build payload."""
    img = build.get("image") or {}
    subject = []
    if img.get("digest"):
        alg, _, hexd = img["digest"].partition(":")
        subject.append({"name": img.get("name") or "image", "digest": {alg: hexd}})
    deps = [{"uri": a["purl"] if a.get("purl") else f"pkg:pypi/{a['name']}@{a['version']}"}
            for a in build.get("sbom", {}).get("artifacts", [])]
    if build.get("commit"):
        deps.insert(0, {"uri": f"git+{repo or 'unknown'}", "digest": {"gitCommit": build["commit"]}})
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subject,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "https://github.com/rakshit-737/tracegate/build@v1",
                                "externalParameters": {"build_id": build.get("build_id")},
                                "resolvedDependencies": deps},
            "runDetails": {"builder": {"id": builder_id},
                           "metadata": {"invocationId": build.get("build_id")}},
        },
    }

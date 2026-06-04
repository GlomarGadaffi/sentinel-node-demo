"""
shroud_speak.py — Alert packaging system for SENTINEL-NODE.

SENTINEL-NODE synthetic policy demonstration platform.
All data is fictional and used solely to demonstrate system behavior
under simulated enforcement pressure for policymaker education.

In deployment, dispatch routes through an arti-client Tor tunnel.
This module demonstrates the packet structure and cryptographic boundary only.
No actual network calls are made here. The OnionAddressRotator produces
realistic-looking v3 .onion addresses and serializes the key-rotation payload
that would be broadcast via SX1262 #2 to sync field agents — it does not
transmit anything.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from typing import Deque, List
from uuid import uuid4

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Pull the shared dataclass that the rest of the platform uses.
from adapters.base import AlertRecord, SalienceSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _generate_v3_onion() -> str:
    """Return a syntactically valid Tor v3 .onion hostname (56 base32 chars + .onion).

    A real v3 address encodes a 32-byte Ed25519 public key, 2-byte checksum,
    and 1-byte version.  We generate the correct byte length so the string is
    indistinguishable in length and character set from a real address.  This is
    a synthetic address; it does not correspond to any running hidden service.
    """
    # 35 random bytes → 56 base32 characters (no padding, lowercase)
    raw = secrets.token_bytes(35)
    encoded = base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    # base32: 35 bytes → ceil(35*8/5) = 56 chars exactly
    return f"{encoded}.onion"


# ---------------------------------------------------------------------------
# ShroudSpeakAlert
# ---------------------------------------------------------------------------

class ShroudSpeakAlert:
    """Packages a SalienceSnapshot into a signed, TTL-bounded AlertRecord.

    The alert body is serialized to a canonical JSON string and then signed
    with an Ed25519 private key supplied by the caller as a hex string.
    Verification is a class-method so policy analysis tooling can validate
    an archive of recorded alerts without holding private key material.

    Parameters
    ----------
    snapshot:
        The SalienceSnapshot that triggered the mode transition.
    onion_address:
        Ephemeral Tor v3 address to embed in the alert (provided by
        OnionAddressRotator.current_address()).
    ttl_seconds:
        How long the alert is considered fresh.  Default 5 minutes.
    """

    def __init__(
        self,
        snapshot: SalienceSnapshot,
        onion_address: str,
        ttl_seconds: int = 300,
    ) -> None:
        self.snapshot = snapshot
        self.onion_address = onion_address
        self.ttl_seconds = ttl_seconds

    # ------------------------------------------------------------------
    # Internal serialisation
    # ------------------------------------------------------------------

    def _build_payload(self) -> dict:
        """Produce the canonical dict that becomes the signed JSON body."""
        snap = self.snapshot
        return {
            "schema_version": "1.0",
            "alert_source": "SENTINEL-NODE",
            "snapshot_id": str(snap.snapshot_id),
            "snapshot_timestamp": snap.timestamp.isoformat(),
            "salience_score": snap.score,
            "components": {
                "trunking_term": snap.trunking_term,
                "aviation_term": snap.aviation_term,
                "mesh_term": snap.mesh_term,
            },
            "threshold": snap.threshold,
            "mode": snap.mode,
            "trigger_reason": snap.trigger_reason,
            "onion_address": self.onion_address,
            "ttl_seconds": self.ttl_seconds,
            "issued_at": _now_utc().isoformat(),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def pack(self, signing_key_hex: str) -> AlertRecord:
        """Serialize and Ed25519-sign the alert, returning an AlertRecord.

        Parameters
        ----------
        signing_key_hex:
            32-byte Ed25519 private key seed encoded as a 64-character hex
            string.  In a real deployment this would be loaded from a
            hardware security module or encrypted keystore — never from an
            environment variable in plaintext.

        Returns
        -------
        AlertRecord
            A fully populated AlertRecord with the signed JSON body embedded
            in ``payload_json``.  The signature is appended to the payload
            under the ``"ed25519_sig"`` key so the whole record is self-
            contained and can be verified offline.
        """
        key_bytes = bytes.fromhex(signing_key_hex)
        private_key: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(key_bytes)

        payload_dict = self._build_payload()
        # Canonical serialization: sorted keys, no extra whitespace.
        payload_canonical = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
        message_bytes = payload_canonical.encode("utf-8")

        signature: bytes = private_key.sign(message_bytes)
        sig_hex = signature.hex()

        # Embed the signature inside the final JSON so the record is self-contained.
        outer = {
            "body": payload_dict,
            "ed25519_sig": sig_hex,
        }
        signed_json = json.dumps(outer, sort_keys=True)

        record = AlertRecord(
            alert_id=uuid4(),
            timestamp=_now_utc(),
            triggering_snapshot_id=self.snapshot.snapshot_id,
            payload_json=signed_json,
            onion_address=self.onion_address,
            ttl_seconds=self.ttl_seconds,
            dispatched=False,
            dispatch_error=None,
        )
        logger.debug(
            "shroud_speak.pack alert_id=%s snapshot_id=%s onion=%s",
            record.alert_id,
            self.snapshot.snapshot_id,
            self.onion_address,
        )
        return record

    @staticmethod
    def verify(alert: AlertRecord, verifying_key_hex: str) -> bool:
        """Verify the Ed25519 signature embedded in an AlertRecord.

        Parameters
        ----------
        alert:
            An AlertRecord whose ``payload_json`` field contains the signed
            envelope produced by :py:meth:`pack`.
        verifying_key_hex:
            32-byte Ed25519 public key encoded as a 64-character hex string.

        Returns
        -------
        bool
            True if the signature is valid and the body has not been tampered
            with; False on any verification failure (including malformed JSON).
        """
        try:
            outer = json.loads(alert.payload_json)
            body_dict: dict = outer["body"]
            sig_hex: str = outer["ed25519_sig"]

            # Re-derive the canonical form of the body to verify against.
            body_canonical = json.dumps(body_dict, sort_keys=True, separators=(",", ":"))
            message_bytes = body_canonical.encode("utf-8")
            signature_bytes = bytes.fromhex(sig_hex)

            key_bytes = bytes.fromhex(verifying_key_hex)
            public_key: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(key_bytes)
            public_key.verify(signature_bytes, message_bytes)
            return True

        except Exception as exc:  # noqa: BLE001
            logger.debug("shroud_speak.verify failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# OnionAddressRotator
# ---------------------------------------------------------------------------

class OnionAddressRotator:
    """Maintains a pool of synthetic Tor v3 .onion addresses and rotates them.

    In a real deployment, these addresses correspond to running arti-client
    hidden service instances.  Here, they are synthetic strings used to
    demonstrate the rotation protocol and key-sync payload structure.

    The key-sync payload serializes the current address pool encrypted with
    Fernet symmetric encryption.  In deployment this ciphertext would be
    broadcast over LoRa (SX1262 channel 2) to field agents.  This module
    does not perform any transmission.

    Parameters
    ----------
    pool_size:
        Number of onion addresses to pre-generate.  Must be >= 2 so there
        is always a next address to rotate into.
    fernet_key:
        URL-safe base64-encoded 32-byte Fernet key.  If None, a fresh key
        is generated and stored on the instance.  In a real system this key
        is derived from a shared secret established out-of-band.
    """

    def __init__(self, pool_size: int = 6, fernet_key: bytes | None = None) -> None:
        if pool_size < 2:
            raise ValueError("pool_size must be >= 2 to support rotation")

        self._pool: Deque[str] = deque(
            _generate_v3_onion() for _ in range(pool_size)
        )
        self._rotation_count: int = 0
        self._fernet_key: bytes = fernet_key if fernet_key is not None else Fernet.generate_key()
        self._fernet = Fernet(self._fernet_key)

        logger.info(
            "OnionAddressRotator initialised pool_size=%d current=%s",
            pool_size,
            self._pool[0],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def current_address(self) -> str:
        """Return the active onion address without advancing the pool."""
        return self._pool[0]

    def rotate(self) -> str:
        """Retire the current address and promote the next one.

        A fresh synthetic address is appended to the tail of the pool so the
        pool never shrinks below its original size.  Returns the new active
        address after rotation.
        """
        retired = self._pool.popleft()
        new_address = _generate_v3_onion()
        self._pool.append(new_address)
        self._rotation_count += 1

        logger.info(
            "OnionAddressRotator.rotate #%d retired=%s new_active=%s",
            self._rotation_count,
            retired,
            self._pool[0],
        )
        return self._pool[0]

    def sync_key_rotation_payload(self) -> bytes:
        """Produce the encrypted payload that field agents would receive via SX1262 #2.

        The payload encodes the full current address pool so a field agent who
        missed one or more rotations can catch up.  In deployment this ciphertext
        would be serialized into a LoRa frame and broadcast on the coordination
        channel.  This method demonstrates the payload structure only — no
        transmission occurs.

        Returns
        -------
        bytes
            Fernet-encrypted JSON encoding current pool, rotation count, and
            a UTC timestamp.  The receiver needs only the shared Fernet key to
            decrypt and update their active address.
        """
        payload = {
            "schema_version": "1.0",
            "rotation_count": self._rotation_count,
            "active_address": self._pool[0],
            "pool": list(self._pool),
            "issued_at": _now_utc().isoformat(),
        }
        plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)
        logger.debug(
            "sync_key_rotation_payload rotation_count=%d payload_bytes=%d",
            self._rotation_count,
            len(ciphertext),
        )
        return ciphertext

    @property
    def rotation_count(self) -> int:
        """Number of rotations performed since instantiation."""
        return self._rotation_count

    @property
    def pool_size(self) -> int:
        return len(self._pool)

    def __repr__(self) -> str:
        return (
            f"OnionAddressRotator("
            f"pool_size={len(self._pool)}, "
            f"rotation_count={self._rotation_count}, "
            f"current={self._pool[0]!r})"
        )

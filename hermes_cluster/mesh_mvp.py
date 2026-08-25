"""Fail-closed placement-only Hermes Mesh MVP.

This module deliberately does not own Kanban state.  It issues bounded work leases,
accepts signed worker claims, and records only ``verified_claim`` after an independent
verification step.  A caller may then use the authoritative Hermes Kanban API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTOCOL_VERSION = "hermes-mesh/1"
ENVELOPE_KEYS = {"version", "device_id", "timestamp", "nonce", "payload", "signature"}
LEASE_KEYS = {
    "kind", "lease_id", "task_id", "worker_id", "issued_at", "expires_at", "attempt",
    "capabilities", "adapter", "input_digest", "payload_digest",
}
RECEIPT_KEYS = {
    "kind", "receipt_id", "lease_id", "task_id", "worker_id", "started_at", "finished_at",
    "adapter", "input_digest", "output_digest", "artifact_digest", "artifact_type",
    "artifact_bytes", "resources", "outcome",
}


class MeshError(RuntimeError):
    pass


class SignatureError(MeshError):
    pass


class ReplayError(SignatureError):
    pass


class LeaseError(MeshError):
    pass


class GateRefusal(MeshError):
    pass


class VerificationError(MeshError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def canonical_digest(value: Any) -> str:
    data = value if isinstance(value, bytes) else canonical_bytes(value)
    return hashlib.sha256(data).hexdigest()


def _signing_bytes(envelope: Mapping[str, Any]) -> bytes:
    return canonical_bytes({key: envelope[key] for key in ("version", "device_id", "timestamp", "nonce", "payload")})


@dataclass
class DeviceKey:
    device_id: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, device_id: str) -> "DeviceKey":
        return cls(device_id, Ed25519PrivateKey.generate())

    def public_b64(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode()

    def private_b64(self) -> str:
        raw = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.b64encode(raw).decode()

    @classmethod
    def from_private_b64(cls, device_id: str, value: str) -> "DeviceKey":
        return cls(device_id, Ed25519PrivateKey.from_private_bytes(base64.b64decode(value, validate=True)))

    def sign_envelope(self, payload: Mapping[str, Any], *, nonce: str | None = None, now: float | None = None) -> dict[str, Any]:
        envelope: dict[str, Any] = {
            "version": PROTOCOL_VERSION,
            "device_id": self.device_id,
            "timestamp": int(time.time() if now is None else now),
            "nonce": nonce or uuid.uuid4().hex,
            "payload": dict(payload),
        }
        envelope["signature"] = base64.b64encode(self.private_key.sign(_signing_bytes(envelope))).decode()
        return envelope


class IdentityRegistry:
    def __init__(self, allowlist: Mapping[str, str], *, max_clock_skew: int = 300):
        self._keys = {
            device_id: Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
            for device_id, value in allowlist.items()
        }
        self.max_clock_skew = max_clock_skew
        self._nonces: set[tuple[str, str]] = set()

    def verify(
        self,
        envelope: Mapping[str, Any],
        *,
        now: float | None = None,
        allowed_payload_keys: set[str] | None = None,
        consume_nonce: bool = True,
    ) -> dict[str, Any]:
        if set(envelope) != ENVELOPE_KEYS:
            raise SignatureError("closed schema violation in envelope")
        if envelope["version"] != PROTOCOL_VERSION:
            raise SignatureError("unsupported protocol version")
        device_id = envelope["device_id"]
        if device_id not in self._keys:
            raise SignatureError("unknown device")
        current = int(time.time() if now is None else now)
        if abs(current - int(envelope["timestamp"])) > self.max_clock_skew:
            raise SignatureError("stale timestamp")
        payload = envelope["payload"]
        if not isinstance(payload, dict):
            raise SignatureError("payload must be an object")
        if allowed_payload_keys is not None and set(payload) != allowed_payload_keys:
            raise SignatureError("closed schema violation in payload")
        nonce_key = (device_id, str(envelope["nonce"]))
        if nonce_key in self._nonces:
            raise ReplayError("replayed nonce")
        try:
            signature = base64.b64decode(envelope["signature"], validate=True)
            self._keys[device_id].verify(signature, _signing_bytes(envelope))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise SignatureError("bad signature") from exc
        if consume_nonce:
            self._nonces.add(nonce_key)
        return dict(payload)


@dataclass
class AdapterPolicy:
    allowed: set[str]
    timeout_seconds: float
    min_free_memory_mb: int
    min_free_disk_mb: int
    max_thermal_c: float
    network_allowed: bool = False
    owner_opt_in: bool = True


@dataclass
class ArtifactPolicy:
    root: Path
    max_bytes: int
    allowed_types: set[str]

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        (self.root / "quarantine").mkdir(parents=True, exist_ok=True)
        (self.root / "objects" / "sha256").mkdir(parents=True, exist_ok=True)

    def promote(self, data: bytes, media_type: str, digest: str, name: str) -> Path:
        if len(data) > self.max_bytes:
            raise MeshError("artifact too large")
        if media_type not in self.allowed_types:
            raise MeshError("artifact type not allowed")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", ".."}:
            raise MeshError("invalid artifact name")
        if canonical_digest(data) != digest:
            raise VerificationError("artifact digest mismatch before transfer")
        fd, staged_name = tempfile.mkstemp(prefix="mesh-", dir=self.root / "quarantine")
        staged = Path(staged_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if canonical_digest(staged.read_bytes()) != digest:
                raise VerificationError("artifact digest mismatch after transfer")
            destination = self.root / "objects" / "sha256" / digest
            os.replace(staged, destination)
            return destination
        finally:
            staged.unlink(missing_ok=True)


class Worker:
    def __init__(self, key: DeviceKey, allowlist: Mapping[str, str], policy: AdapterPolicy):
        self.key = key
        self.identities = IdentityRegistry(allowlist)
        self.policy = policy

    def _resources(self) -> dict[str, float]:
        usage = shutil.disk_usage(Path.cwd())
        memory_mb = 1_000_000
        try:
            pages = os.sysconf("SC_AVPHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            memory_mb = pages * page_size / 1024 / 1024
        except (ValueError, OSError, AttributeError):
            pass
        return {"free_memory_mb": memory_mb, "free_disk_mb": usage.free / 1024 / 1024, "thermal_c": 0.0}

    def execute(
        self,
        lease: Mapping[str, Any],
        payload: Mapping[str, Any],
        *,
        now: float | None = None,
        resources: Mapping[str, float] | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        current = time.time() if now is None else now
        lease_payload = self.identities.verify(lease, now=current, allowed_payload_keys=LEASE_KEYS)
        if lease_payload["kind"] != "lease" or lease_payload["worker_id"] != self.key.device_id:
            raise LeaseError("lease is not assigned to this worker")
        if current > lease_payload["expires_at"]:
            raise LeaseError("expired lease")
        if canonical_digest(payload) != lease_payload["input_digest"]:
            raise VerificationError("input digest mismatch")
        adapter = lease_payload["adapter"]
        if not self.policy.owner_opt_in:
            raise GateRefusal("owner opt-in required")
        if adapter not in self.policy.allowed:
            raise GateRefusal("adapter not allowed")
        if self.policy.timeout_seconds <= 0:
            raise GateRefusal("timeout gate refusal")
        observed = dict(resources or self._resources())
        if observed["free_memory_mb"] < self.policy.min_free_memory_mb:
            raise GateRefusal("memory gate refusal")
        if observed["free_disk_mb"] < self.policy.min_free_disk_mb:
            raise GateRefusal("disk gate refusal")
        if observed["thermal_c"] > self.policy.max_thermal_c:
            raise GateRefusal("thermal gate refusal")
        started = current
        if adapter != "sha256-benchmark@1":
            raise GateRefusal("adapter not implemented")
        text = str(payload["text"]).encode()
        iterations = int(payload["iterations"])
        if iterations < 1 or iterations > 1_000_000:
            raise GateRefusal("iterations outside bounded adapter policy")
        result = text
        for _ in range(iterations):
            result = hashlib.sha256(result).digest()
        output = {"adapter": adapter, "iterations": iterations, "result": result.hex()}
        artifact = canonical_bytes(output)
        finished = time.time() if now is None else current
        receipt_payload = {
            "kind": "receipt",
            "receipt_id": uuid.uuid4().hex,
            "lease_id": lease_payload["lease_id"],
            "task_id": lease_payload["task_id"],
            "worker_id": self.key.device_id,
            "started_at": started,
            "finished_at": finished,
            "adapter": adapter,
            "input_digest": canonical_digest(payload),
            "output_digest": canonical_digest(output),
            "artifact_digest": canonical_digest(artifact),
            "artifact_type": "application/json",
            "artifact_bytes": len(artifact),
            "resources": observed,
            "outcome": "claimed_success",
        }
        return self.key.sign_envelope(receipt_payload, now=finished), artifact


class Coordinator:
    def __init__(
        self,
        key: DeviceKey,
        allowlist: Mapping[str, str],
        artifacts: ArtifactPolicy,
        *,
        lease_ttl: int = 60,
    ):
        self.key = key
        self.identities = IdentityRegistry(allowlist)
        self.artifacts = artifacts
        self.lease_ttl = lease_ttl
        self.leases: dict[str, dict[str, Any]] = {}
        self.task_states: dict[str, str] = {}
        self.receipts: list[dict[str, Any]] = []
        self._receipt_ids: set[str] = set()
        self._attempts: dict[str, int] = {}
        self.events: list[dict[str, Any]] = []

    def issue_lease(
        self,
        task_id: str,
        worker_id: str,
        adapter: str,
        payload: Mapping[str, Any],
        capabilities: list[str],
        *,
        now: float | None = None,
        ttl: int | None = None,
    ) -> dict[str, Any]:
        issued = time.time() if now is None else now
        attempt = self._attempts.get(task_id, 0) + 1
        self._attempts[task_id] = attempt
        lease_id = uuid.uuid4().hex
        body = {
            "kind": "lease", "lease_id": lease_id, "task_id": task_id, "worker_id": worker_id,
            "issued_at": issued, "expires_at": issued + (self.lease_ttl if ttl is None else ttl),
            "attempt": attempt, "capabilities": sorted(capabilities), "adapter": adapter,
            "input_digest": canonical_digest(payload), "payload_digest": canonical_digest(payload),
        }
        envelope = self.key.sign_envelope(body, now=issued)
        self.leases[lease_id] = body
        self.task_states[task_id] = "leased"
        self.events.append({"event": "lease_issued", "timestamp": issued, "task_id": task_id, "lease_id": lease_id, "attempt": attempt})
        return envelope

    def accept_lease_request(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        return self.identities.verify(envelope)

    def canonical_status(self, task_id: str) -> str:
        return self.task_states.get(task_id, "unknown")

    def verify_receipt(
        self,
        receipt: Mapping[str, Any],
        artifact: bytes,
        input_payload: Mapping[str, Any],
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        verification_started = time.time()
        payload = receipt.get("payload")
        if not isinstance(payload, dict) or set(payload) != RECEIPT_KEYS:
            raise VerificationError("closed schema violation in receipt")
        receipt_id = payload["receipt_id"]
        if receipt_id in self._receipt_ids:
            raise ReplayError("replayed receipt")
        current = time.time() if now is None else now
        verified = self.identities.verify(receipt, now=current, allowed_payload_keys=RECEIPT_KEYS)
        lease = self.leases.get(verified["lease_id"])
        if lease is None:
            raise LeaseError("unknown lease")
        if current > lease["expires_at"]:
            raise LeaseError("expired lease")
        for key in ("task_id", "worker_id", "adapter", "input_digest"):
            if verified[key] != lease[key]:
                raise VerificationError(f"lease lineage mismatch: {key}")
        if canonical_digest(input_payload) != verified["input_digest"]:
            raise VerificationError("input digest mismatch")
        if len(artifact) != verified["artifact_bytes"] or canonical_digest(artifact) != verified["artifact_digest"]:
            raise VerificationError("artifact digest mismatch")
        try:
            output = json.loads(artifact)
        except json.JSONDecodeError as exc:
            raise VerificationError("artifact is not valid JSON") from exc
        if canonical_digest(output) != verified["output_digest"]:
            raise VerificationError("output digest mismatch")
        expected = str(input_payload["text"]).encode()
        for _ in range(int(input_payload["iterations"])):
            expected = hashlib.sha256(expected).digest()
        if output != {"adapter": "sha256-benchmark@1", "iterations": int(input_payload["iterations"]), "result": expected.hex()}:
            raise VerificationError("workload result rejected")
        path = self.artifacts.promote(artifact, verified["artifact_type"], verified["artifact_digest"], receipt_id)
        self._receipt_ids.add(receipt_id)
        self.receipts.append(dict(verified))
        self.task_states[verified["task_id"]] = "verified_claim"
        metrics = {
            "queue_ms": 0,
            "lease_ms": max(0, int((verified["started_at"] - lease["issued_at"]) * 1000)),
            "transfer_ms": 0,
            "verification_ms": max(0, int((time.time() - verification_started) * 1000)),
            "bytes_transferred": len(artifact),
        }
        event = {"event": "receipt_accepted", "timestamp": current, "task_id": verified["task_id"], "lease_id": verified["lease_id"], "receipt_id": receipt_id, "metrics": metrics, "artifact_path": str(path)}
        self.events.append(event)
        return {"verified": True, "receipt_id": receipt_id, "artifact_digest": verified["artifact_digest"], "metrics": metrics}

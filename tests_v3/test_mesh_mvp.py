from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from hermes_cluster.mesh_mvp import (
    AdapterPolicy,
    ArtifactPolicy,
    Coordinator,
    DeviceKey,
    GateRefusal,
    LeaseError,
    MeshError,
    ReplayError,
    SignatureError,
    VerificationError,
    Worker,
    canonical_digest,
)


@pytest.fixture()
def setup(tmp_path: Path):
    groot = DeviceKey.generate("groot")
    mbp = DeviceKey.generate("mbp")
    unknown = DeviceKey.generate("unknown")
    allowlist = {"groot": groot.public_b64(), "mbp": mbp.public_b64()}
    artifacts = ArtifactPolicy(tmp_path / "artifacts", max_bytes=1024, allowed_types={"application/json"})
    coordinator = Coordinator(groot, allowlist, artifacts, lease_ttl=30)
    worker = Worker(
        mbp,
        allowlist,
        AdapterPolicy(
            allowed={"sha256-benchmark@1"},
            timeout_seconds=2,
            min_free_memory_mb=1,
            min_free_disk_mb=1,
            max_thermal_c=95,
            network_allowed=False,
        ),
    )
    return coordinator, worker, groot, mbp, unknown


def test_valid_end_to_end_receipt_requires_independent_verification(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "deterministic benchmark", "iterations": 4}
    lease = coordinator.issue_lease("t_demo", "mbp", "sha256-benchmark@1", payload, ["cpu"])
    receipt, artifact = worker.execute(lease, payload)

    assert coordinator.canonical_status("t_demo") == "leased"
    accepted = coordinator.verify_receipt(receipt, artifact, payload)

    assert accepted["verified"] is True
    assert coordinator.canonical_status("t_demo") == "verified_claim"
    assert accepted["receipt_id"] == receipt["payload"]["receipt_id"]


def test_unknown_key_is_rejected(setup):
    coordinator, _, _, _, unknown = setup
    payload = {"text": "x", "iterations": 1}
    lease = coordinator.issue_lease("t_unknown", "mbp", "sha256-benchmark@1", payload, ["cpu"])
    forged = unknown.sign_envelope({**lease["payload"], "worker_id": "unknown"}, nonce="unknown-nonce")
    with pytest.raises(SignatureError, match="unknown device"):
        coordinator.accept_lease_request(forged)


def test_mutation_after_signing_is_rejected(setup):
    coordinator, *_ = setup
    envelope = coordinator.key.sign_envelope({"kind": "probe", "value": 1}, nonce="n1")
    envelope["payload"]["value"] = 2
    with pytest.raises(SignatureError, match="bad signature"):
        coordinator.identities.verify(envelope)


def test_nonce_and_receipt_replay_are_rejected(setup):
    coordinator, worker, *_ = setup
    probe = worker.key.sign_envelope({"kind": "probe"}, nonce="same")
    coordinator.identities.verify(probe)
    with pytest.raises(ReplayError):
        coordinator.identities.verify(probe)

    payload = {"text": "replay", "iterations": 1}
    lease = coordinator.issue_lease("t_replay", "mbp", "sha256-benchmark@1", payload, ["cpu"])
    receipt, artifact = worker.execute(lease, payload)
    coordinator.verify_receipt(receipt, artifact, payload)
    with pytest.raises(ReplayError, match="receipt"):
        coordinator.verify_receipt(receipt, artifact, payload)


def test_expired_lease_fails_closed_and_reissue_has_new_id(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "expired", "iterations": 1}
    old = coordinator.issue_lease("t_exp", "mbp", "sha256-benchmark@1", payload, [], now=10, ttl=1)
    new = coordinator.issue_lease("t_exp", "mbp", "sha256-benchmark@1", payload, [], now=12, ttl=10)
    receipt, artifact = worker.execute(old, payload, now=10)
    assert old["payload"]["lease_id"] != new["payload"]["lease_id"]
    with pytest.raises(LeaseError, match="expired"):
        coordinator.verify_receipt(receipt, artifact, payload, now=13)


def test_worker_cannot_self_award_completion(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "claim", "iterations": 1}
    lease = coordinator.issue_lease("t_claim", "mbp", "sha256-benchmark@1", payload, [])
    receipt, artifact = worker.execute(lease, payload)
    receipt["payload"]["canonical_status"] = "done"
    receipt = worker.key.sign_envelope(receipt["payload"], nonce="forged-complete")
    with pytest.raises(VerificationError, match="closed schema"):
        coordinator.verify_receipt(receipt, artifact, payload)
    assert coordinator.canonical_status("t_claim") == "leased"


def test_input_digest_mismatch_is_rejected(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "digest", "iterations": 1}
    lease = coordinator.issue_lease("t_digest", "mbp", "sha256-benchmark@1", payload, [])
    receipt, artifact = worker.execute(lease, payload)
    with pytest.raises(VerificationError, match="input digest"):
        coordinator.verify_receipt(receipt, artifact, {"text": "changed", "iterations": 1})


def test_artifact_digest_mismatch_is_rejected(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "digest", "iterations": 1}
    lease = coordinator.issue_lease("t_artifact_digest", "mbp", "sha256-benchmark@1", payload, [])
    receipt, artifact = worker.execute(lease, payload)
    with pytest.raises(VerificationError, match="artifact digest"):
        coordinator.verify_receipt(receipt, artifact + b"x", payload)


def test_artifact_policy_rejects_oversize_type_and_path_traversal(setup):
    coordinator, *_ = setup
    policy = coordinator.artifacts
    with pytest.raises(MeshError, match="too large"):
        policy.promote(b"x" * 1025, "application/json", canonical_digest(b"x" * 1025), "oversize")
    with pytest.raises(MeshError, match="type"):
        policy.promote(b"{}", "text/x-shellscript", canonical_digest(b"{}"), "type")
    with pytest.raises(MeshError, match="artifact name"):
        policy.promote(b"{}", "application/json", canonical_digest(b"{}"), "../escape")


def test_disallowed_adapter_is_rejected(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "shell", "iterations": 1}
    lease = coordinator.issue_lease("t_shell", "mbp", "shell@1", payload, [])
    with pytest.raises(GateRefusal, match="adapter"):
        worker.execute(lease, payload)


@pytest.mark.parametrize(
    "resources, message",
    [
        ({"free_memory_mb": 0, "free_disk_mb": 10, "thermal_c": 20}, "memory"),
        ({"free_memory_mb": 10, "free_disk_mb": 0, "thermal_c": 20}, "disk"),
        ({"free_memory_mb": 10, "free_disk_mb": 10, "thermal_c": 100}, "thermal"),
    ],
)
def test_resource_and_thermal_refusals(setup, resources, message):
    coordinator, worker, *_ = setup
    payload = {"text": "gated", "iterations": 1}
    lease = coordinator.issue_lease("t_gate", "mbp", "sha256-benchmark@1", payload, [])
    with pytest.raises(GateRefusal, match=message):
        worker.execute(lease, payload, resources=resources)


def test_timeout_refusal(setup):
    coordinator, worker, *_ = setup
    worker.policy.timeout_seconds = 0
    payload = {"text": "timeout", "iterations": 1}
    lease = coordinator.issue_lease("t_timeout", "mbp", "sha256-benchmark@1", payload, [])
    with pytest.raises(GateRefusal, match="timeout"):
        worker.execute(lease, payload)


def test_verifier_rejects_incorrect_workload_result(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "verify", "iterations": 2}
    lease = coordinator.issue_lease("t_verify", "mbp", "sha256-benchmark@1", payload, [])
    receipt, artifact = worker.execute(lease, payload)
    decoded = json.loads(artifact)
    decoded["result"] = "0" * 64
    bad_artifact = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()
    receipt_payload = dict(receipt["payload"])
    receipt_payload["artifact_digest"] = canonical_digest(bad_artifact)
    receipt_payload["output_digest"] = canonical_digest(decoded)
    forged_consistent = worker.key.sign_envelope(receipt_payload, nonce="wrong-result")
    with pytest.raises(VerificationError, match="workload result"):
        coordinator.verify_receipt(forged_consistent, bad_artifact, payload)


def test_closed_schema_and_stale_timestamp_rejected(setup):
    coordinator, worker, *_ = setup
    envelope = worker.key.sign_envelope({"kind": "probe", "extension": True}, nonce="ext", now=1)
    with pytest.raises(SignatureError, match="stale"):
        coordinator.identities.verify(envelope, now=1000, allowed_payload_keys={"kind"})


def test_events_are_machine_readable_and_cover_timings(setup):
    coordinator, worker, *_ = setup
    payload = {"text": "metrics", "iterations": 1}
    lease = coordinator.issue_lease("t_metrics", "mbp", "sha256-benchmark@1", payload, [])
    receipt, artifact = worker.execute(lease, payload)
    coordinator.verify_receipt(receipt, artifact, payload)
    events = coordinator.events
    assert {e["event"] for e in events} >= {"lease_issued", "receipt_accepted"}
    accepted = events[-1]
    assert {"queue_ms", "lease_ms", "transfer_ms", "verification_ms", "bytes_transferred"} <= set(accepted["metrics"])

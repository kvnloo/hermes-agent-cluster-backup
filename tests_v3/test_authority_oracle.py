"""Executable authority oracle for Hermes Mesh integration mode."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hermes_cluster import plugin
from hermes_cluster.app import create_app
from hermes_cluster.authority import (
    ExecutionReceipt,
    Lease,
    NodeCapability,
    ResourceCeilings,
    RuntimeAdapter,
    WorkOffer,
)


@pytest.fixture
def mesh_client():
    return TestClient(create_app(cluster_id="oracle", node_id="zero-authority"))


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("post", "/api/v1/tasks", {"title": "forbidden"}),
        ("post", "/api/v1/tasks/canonical/complete", None),
        ("post", "/api/v1/tasks/canonical/fail", {"reason": "forbidden"}),
        ("post", "/api/v1/tasks/canonical/unblock", None),
        ("post", "/api/v1/tasks/canonical/advance", None),
        ("post", "/api/v1/tasks/canonical/dependencies", {"depends_on": ["parent"]}),
        ("post", "/api/v1/tasks/canonical/claim", {"node_id": "zero-authority"}),
        ("post", "/api/v1/tasks/canonical/release", {"node_id": "zero-authority"}),
        ("post", "/api/v1/schedule/trigger", None),
        ("post", "/api/v1/recovery/trigger", {"node_id": "zero-authority"}),
        ("post", "/api/v1/recovery/detect-expired", None),
        ("post", "/api/v1/sync/receive", {"event_type": "task_completed"}),
        ("post", "/api/v1/sync/receive-batch", {"messages": []}),
        ("post", "/api/v1/federation/tasks", {"cluster_id": "x", "title": "forbidden"}),
    ],
)
def test_zero_authority_mode_denies_every_canonical_lifecycle_mutation(
    mesh_client, method, path, payload
):
    response = getattr(mesh_client, method)(path, json=payload)

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Hermes Kanban is the sole lifecycle authority; cluster owns placement only"
    }


def test_mesh_mode_preserves_node_heartbeat_capability_metrics_and_dashboard(mesh_client):
    joined = mesh_client.post(
        "/api/v1/nodes/join",
        json={"node_name": "worker", "capabilities": ["synthetic"]},
    )
    assert joined.status_code == 200
    node_id = joined.json()["node_id"]

    assert mesh_client.post(
        "/api/v1/nodes/heartbeat", json={"node_id": node_id}
    ).status_code == 200
    assert mesh_client.patch(
        f"/api/v1/nodes/{node_id}/capabilities",
        json={"capabilities": ["synthetic", "gpu"]},
    ).status_code == 200
    assert mesh_client.get("/api/v1/cluster/metrics").status_code == 200
    assert mesh_client.get("/dashboard/").status_code == 404


def test_legacy_standalone_mode_is_explicit_and_retains_upstream_lifecycle():
    client = TestClient(create_app(authority_mode="legacy-standalone"))

    created = client.post("/api/v1/tasks", json={"title": "legacy task"})
    assert created.status_code == 200
    completed = client.post(f"/api/v1/tasks/{created.json()['id']}/complete")
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"


def test_contracts_are_revision_bound_bounded_and_receipt_has_no_completion_authority():
    now = datetime.now(timezone.utc)
    ceilings = ResourceCeilings(
        cpu_seconds=10,
        memory_bytes=64 * 1024 * 1024,
        disk_bytes=16 * 1024 * 1024,
        wall_seconds=30,
    )
    capability = NodeCapability(
        node_id="worker-1",
        revision=2,
        generation=7,
        capabilities=["synthetic"],
        resource_ceilings=ceilings,
        runtime_adapters=[RuntimeAdapter.synthetic],
        signer="ed25519:worker-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        sequence=11,
        replay_domain="mesh:oracle:nodes",
    )
    offer = WorkOffer(
        offer_id="offer-1",
        canonical_task_id="kanban-1",
        revision=3,
        generation=8,
        requirements=["synthetic"],
        resource_ceilings=ceilings,
        runtime_adapter=RuntimeAdapter.synthetic,
        input_hashes={"payload": "sha256:" + "1" * 64},
        signer="ed25519:coordinator",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        sequence=12,
        replay_domain="mesh:oracle:offers",
    )
    lease = Lease(
        lease_id="lease-1",
        offer_id=offer.offer_id,
        node_id=capability.node_id,
        revision=offer.revision,
        generation=offer.generation,
        resource_ceilings=ceilings,
        runtime_adapter=offer.runtime_adapter,
        input_hashes=offer.input_hashes,
        signer="ed25519:coordinator",
        issued_at=now,
        expires_at=now + timedelta(minutes=1),
        sequence=13,
        replay_domain="mesh:oracle:leases",
    )
    receipt = ExecutionReceipt(
        receipt_id="receipt-1",
        lease_id=lease.lease_id,
        offer_id=offer.offer_id,
        canonical_task_id=offer.canonical_task_id,
        revision=lease.revision,
        generation=lease.generation,
        runtime_adapter=lease.runtime_adapter,
        input_hashes=lease.input_hashes,
        output_hashes={"result": "sha256:" + "2" * 64},
        resource_usage={"cpu_seconds": 1, "wall_seconds": 2},
        signer="ed25519:worker-1",
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        sequence=14,
        replay_domain="mesh:oracle:receipts",
        signature="base64:signed-receipt",
    )

    assert "status" not in receipt.model_dump()
    assert "completed" not in receipt.model_dump()
    assert receipt.canonical_task_id == "kanban-1"


def test_contracts_reject_arbitrary_runtime_and_unbounded_resources():
    with pytest.raises(ValidationError):
        ResourceCeilings(cpu_seconds=0, memory_bytes=1, disk_bytes=1, wall_seconds=1)
    with pytest.raises(ValidationError):
        WorkOffer.model_validate({
            "offer_id": "offer-bad",
            "canonical_task_id": "kanban-1",
            "revision": 1,
            "generation": 1,
            "requirements": [],
            "resource_ceilings": {
                "cpu_seconds": 1,
                "memory_bytes": 1,
                "disk_bytes": 1,
                "wall_seconds": 1,
            },
            "runtime_adapter": "shell",
            "signer": "x",
            "issued_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=1),
            "sequence": 1,
            "replay_domain": "mesh:test",
        })


class RecordingPluginContext:
    def __init__(self):
        self.tools = []

    def register_tool(self, **kwargs):
        self.tools.append(kwargs["name"])

    def register_hook(self, *_args, **_kwargs):
        pass


def test_plugin_default_exposes_placement_tools_but_no_task_authority(monkeypatch):
    monkeypatch.delenv("HERMES_CLUSTER_AUTHORITY_MODE", raising=False)
    context = RecordingPluginContext()

    plugin.register(context)

    assert "kanban_cluster_join" in context.tools
    assert "kanban_cluster_nodes" in context.tools
    assert "kanban_cluster_heartbeat" in context.tools
    assert "kanban_cluster_submit" not in context.tools
    assert "kanban_cluster_complete" not in context.tools


def test_plugin_legacy_tools_require_explicit_standalone_mode(monkeypatch):
    monkeypatch.setenv("HERMES_CLUSTER_AUTHORITY_MODE", "legacy-standalone")
    context = RecordingPluginContext()

    plugin.register(context)

    assert "kanban_cluster_submit" in context.tools
    assert "kanban_cluster_complete" in context.tools

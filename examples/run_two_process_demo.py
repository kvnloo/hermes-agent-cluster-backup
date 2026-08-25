#!/usr/bin/env python3
"""Executable two-process groot→mbp integration harness with local-only sockets."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hermes_cluster.mesh_mvp import DeviceKey


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_ready(url: str) -> None:
    for _ in range(100):
        try:
            if httpx.get(url, timeout=0.2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"service did not become ready: {url}")


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="hermes-mesh-demo-"))
    groot = DeviceKey.generate("groot")
    mbp = DeviceKey.generate("mbp")
    allowlist = {"groot": groot.public_b64(), "mbp": mbp.public_b64()}
    groot_secret = root / "groot.secret.json"
    mbp_secret = root / "mbp.secret.json"
    groot_secret.write_text(json.dumps({"device_id": "groot", "private_key_b64": groot.private_b64()}), encoding="utf-8")
    mbp_secret.write_text(json.dumps({"device_id": "mbp", "private_key_b64": mbp.private_b64()}), encoding="utf-8")
    groot_secret.chmod(0o600)
    mbp_secret.chmod(0o600)
    coordinator_cfg = {
        "role": "coordinator", "device_allowlist": allowlist, "lease_ttl_seconds": 30,
        "audit_jsonl": str(root / "coordinator.jsonl"),
        "artifact_policy": {"root": str(root / "artifacts"), "max_bytes": 1048576, "allowed_types": ["application/json"]},
    }
    worker_cfg = {
        "role": "worker", "device_allowlist": allowlist, "audit_jsonl": str(root / "worker.jsonl"),
        "adapter_policy": {"allowed": ["sha256-benchmark@1"], "timeout_seconds": 5,
                           "min_free_memory_mb": 1, "min_free_disk_mb": 1,
                           "max_thermal_c": 95, "owner_opt_in": True},
    }
    coordinator_path = root / "coordinator.json"
    worker_path = root / "worker.json"
    coordinator_path.write_text(json.dumps(coordinator_cfg), encoding="utf-8")
    worker_path.write_text(json.dumps(worker_cfg), encoding="utf-8")
    coordinator_port, worker_port = free_port(), free_port()
    coordinator = subprocess.Popen([
        sys.executable, "-m", "hermes_cluster.mesh_runtime", "serve", "--config", str(coordinator_path),
        "--secret", str(groot_secret), "--port", str(coordinator_port),
    ])
    worker = subprocess.Popen([
        sys.executable, "-m", "hermes_cluster.mesh_runtime", "serve", "--config", str(worker_path),
        "--secret", str(mbp_secret), "--port", str(worker_port),
    ])
    try:
        wait_ready(f"http://127.0.0.1:{coordinator_port}/health")
        wait_ready(f"http://127.0.0.1:{worker_port}/health")
        payload = {"text": "two-process-local-canary", "iterations": 100}
        lease_response = httpx.post(
            f"http://127.0.0.1:{coordinator_port}/v1/leases",
            json={"task_id": "t_local_canary", "worker_id": "mbp", "adapter": "sha256-benchmark@1", "payload": payload, "capabilities": ["cpu"]},
            timeout=5,
        )
        lease_response.raise_for_status()
        execution_response = httpx.post(
            f"http://127.0.0.1:{worker_port}/v1/execute",
            json={"lease": lease_response.json()["lease"], "payload": payload}, timeout=5,
        )
        execution_response.raise_for_status()
        claim = execution_response.json()
        verify_response = httpx.post(
            f"http://127.0.0.1:{coordinator_port}/v1/receipts/verify",
            json={"receipt": claim["receipt"], "payload": payload, "artifact_b64": claim["artifact_b64"]}, timeout=5,
        )
        verify_response.raise_for_status()
        state = httpx.get(f"http://127.0.0.1:{coordinator_port}/v1/tasks/t_local_canary/placement-state", timeout=5).json()
        evidence = {
            "result": "PASS", "topology": ["groot-baseline", "mbp-worker"],
            "transport": "two local HTTP processes", "real_mbp_proven": False,
            "verification": verify_response.json(), "placement_state_readback": state,
            "evidence_root": str(root),
        }
        output = root / "result.json"
        output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(evidence, sort_keys=True))
    finally:
        for process in (worker, coordinator):
            process.terminate()
        for process in (worker, coordinator):
            process.wait(timeout=5)


if __name__ == "__main__":
    main()

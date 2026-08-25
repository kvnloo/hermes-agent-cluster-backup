"""HTTP surfaces for the bounded groot coordinator and one mbp worker.

Run with ``python -m hermes_cluster.mesh_runtime --help``.  The HTTP layer carries
signed protocol envelopes only; it never exposes a shell or direct Kanban mutation.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from .mesh_mvp import AdapterPolicy, ArtifactPolicy, Coordinator, DeviceKey, MeshError, Worker


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LeaseRequest(ClosedModel):
    task_id: str
    worker_id: Literal["mbp"]
    adapter: Literal["sha256-benchmark@1"]
    payload: dict[str, Any]
    capabilities: list[str] = []


class ExecuteRequest(ClosedModel):
    lease: dict[str, Any]
    payload: dict[str, Any]


class VerifyRequest(ClosedModel):
    receipt: dict[str, Any]
    payload: dict[str, Any]
    artifact_b64: str


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()


def coordinator_app(coordinator: Coordinator, audit_path: Path) -> FastAPI:
    app = FastAPI(title="Hermes Mesh placement-only coordinator", version="1")

    @app.post("/v1/leases")
    def issue(request: LeaseRequest):
        try:
            lease = coordinator.issue_lease(
                request.task_id, request.worker_id, request.adapter, request.payload, request.capabilities
            )
            _append_jsonl(audit_path, coordinator.events[-1])
            return {"lease": lease}
        except MeshError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/receipts/verify")
    def verify(request: VerifyRequest):
        try:
            artifact = base64.b64decode(request.artifact_b64, validate=True)
            result = coordinator.verify_receipt(request.receipt, artifact, request.payload)
            _append_jsonl(audit_path, coordinator.events[-1])
            return result
        except (MeshError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/tasks/{task_id}/placement-state")
    def state(task_id: str):
        return {"task_id": task_id, "placement_state": coordinator.canonical_status(task_id), "canonical_authority": "external-hermes-kanban"}

    @app.get("/health")
    def health():
        return {"ok": True, "role": "coordinator", "authority": "placement-only"}

    return app


def worker_app(worker: Worker, audit_path: Path) -> FastAPI:
    app = FastAPI(title="Hermes Mesh bounded mbp worker", version="1")

    @app.post("/v1/execute")
    def execute(request: ExecuteRequest):
        try:
            receipt, artifact = worker.execute(request.lease, request.payload)
            _append_jsonl(audit_path, {"event": "worker_receipt_claimed", "receipt": receipt["payload"]})
            return {"receipt": receipt, "artifact_b64": base64.b64encode(artifact).decode()}
        except MeshError as exc:
            _append_jsonl(audit_path, {"event": "worker_refusal", "reason": str(exc)})
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/health")
    def health():
        return {"ok": True, "role": "worker", "adapters": sorted(worker.policy.allowed)}

    return app


def load_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_runtime(config_path: Path, secret_path: Path) -> FastAPI:
    config = load_config(config_path)
    secret = load_config(secret_path)
    key = DeviceKey.from_private_b64(secret["device_id"], secret["private_key_b64"])
    role = config["role"]
    audit_path = Path(config["audit_jsonl"])
    if role == "coordinator":
        artifact = config["artifact_policy"]
        coordinator = Coordinator(
            key,
            config["device_allowlist"],
            ArtifactPolicy(Path(artifact["root"]), artifact["max_bytes"], set(artifact["allowed_types"])),
            lease_ttl=config["lease_ttl_seconds"],
        )
        return coordinator_app(coordinator, audit_path)
    if role == "worker":
        policy = config["adapter_policy"]
        worker = Worker(
            key,
            config["device_allowlist"],
            AdapterPolicy(
                allowed=set(policy["allowed"]),
                timeout_seconds=policy["timeout_seconds"],
                min_free_memory_mb=policy["min_free_memory_mb"],
                min_free_disk_mb=policy["min_free_disk_mb"],
                max_thermal_c=policy["max_thermal_c"],
                network_allowed=False,
                owner_opt_in=policy["owner_opt_in"],
            ),
        )
        return worker_app(worker, audit_path)
    raise ValueError(f"unsupported role: {role}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hermes Mesh placement-only MVP")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--secret", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, required=True)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("--device-id", required=True)
    keygen.add_argument("--secret-out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "keygen":
        key = DeviceKey.generate(args.device_id)
        args.secret_out.parent.mkdir(parents=True, exist_ok=True)
        args.secret_out.write_text(json.dumps({"device_id": args.device_id, "private_key_b64": key.private_b64()}) + "\n", encoding="utf-8")
        args.secret_out.chmod(0o600)
        print(json.dumps({"device_id": args.device_id, "public_key_b64": key.public_b64()}))
        return
    uvicorn.run(build_runtime(args.config, args.secret), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

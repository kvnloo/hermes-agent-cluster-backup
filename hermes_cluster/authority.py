"""Hermes Mesh placement contracts and lifecycle authority boundary.

These contracts describe placement evidence only.  In particular,
``ExecutionReceipt`` intentionally has no canonical lifecycle status field.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, model_validator

AUTHORITY_DENIED_DETAIL = (
    "Hermes Kanban is the sole lifecycle authority; cluster owns placement only"
)


class AuthorityMode(str, Enum):
    """Cluster authority modes; Mesh is the safe integration default."""

    mesh = "mesh"
    legacy_standalone = "legacy-standalone"


class RuntimeAdapter(str, Enum):
    """Typed adapters allowlisted by the P0 contract."""

    synthetic = "synthetic"
    hermes_a2a = "hermes-a2a"
    rootless_container = "rootless-container"


class ResourceCeilings(BaseModel):
    """Hard upper bounds granted to one placement execution."""

    cpu_seconds: int = Field(gt=0)
    memory_bytes: int = Field(gt=0)
    disk_bytes: int = Field(gt=0)
    wall_seconds: int = Field(gt=0)


class SignedReplayBound(BaseModel):
    """Common signed, ordered envelope fields."""

    revision: int = Field(ge=0)
    generation: int = Field(ge=0)
    signer: str = Field(min_length=1)
    sequence: int = Field(ge=0)
    replay_domain: str = Field(min_length=1)


class ExpiringEnvelope(SignedReplayBound):
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def expiry_follows_issue(self):
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self


class NodeCapability(ExpiringEnvelope):
    node_id: str = Field(min_length=1)
    capabilities: list[str]
    resource_ceilings: ResourceCeilings
    runtime_adapters: list[RuntimeAdapter]


class WorkOffer(ExpiringEnvelope):
    offer_id: str = Field(min_length=1)
    canonical_task_id: str = Field(min_length=1)
    requirements: list[str]
    resource_ceilings: ResourceCeilings
    runtime_adapter: RuntimeAdapter
    input_hashes: dict[str, str] = Field(default_factory=dict)


class Lease(ExpiringEnvelope):
    """Revision-bound placement lease, not a canonical task claim."""

    lease_id: str = Field(min_length=1)
    offer_id: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    resource_ceilings: ResourceCeilings
    runtime_adapter: RuntimeAdapter
    input_hashes: dict[str, str] = Field(default_factory=dict)


class ExecutionReceipt(SignedReplayBound):
    """Signed execution evidence; never an instruction to complete a task."""

    receipt_id: str = Field(min_length=1)
    lease_id: str = Field(min_length=1)
    offer_id: str = Field(min_length=1)
    canonical_task_id: str = Field(min_length=1)
    runtime_adapter: RuntimeAdapter
    input_hashes: dict[str, str] = Field(default_factory=dict)
    output_hashes: dict[str, str] = Field(default_factory=dict)
    resource_usage: dict[str, int] = Field(default_factory=dict)
    started_at: datetime
    finished_at: datetime
    signature: str = Field(min_length=1)

    @model_validator(mode="after")
    def finish_follows_start(self):
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        return self

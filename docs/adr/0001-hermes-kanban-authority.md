# ADR 0001: Hermes Kanban authority and Mesh placement contracts

- Status: accepted
- Date: 2026-08-24
- Scope: P0 authority surgery

## Context

The upstream cluster exposes a complete, replicated task lifecycle. Hermes already has a canonical Kanban lifecycle and review graph. Letting a cluster worker operate both makes a receipt, replica, or stale worker a second authority. Shared SQLite and arbitrary remote shell execution would create the same boundary violation through storage or runtime rather than HTTP.

## Decision

Hermes Kanban is the sole canonical lifecycle authority. Hermes Mesh owns placement metadata only: node registry, capability and pressure observations, heartbeats, offers, bounded leases, execution receipts, metrics, and dashboard projections. Future agent conversation transport is upstream Hermes A2A.

`create_app()` defaults to `authority_mode="mesh"`. In this mode the authority oracle rejects every legacy endpoint that creates, completes, fails, unblocks, advances, claims, releases, reparents, schedules, recovers, synchronizes, or forwards canonical-looking tasks. The Hermes plugin does not register task-submit or task-complete tools.

Existing upstream behavior remains available only when an operator explicitly selects `authority_mode="legacy-standalone"` or sets `HERMES_CLUSTER_AUTHORITY_MODE=legacy-standalone`. This is a compatibility mode, not Hermes integration mode.

Contracts live in `hermes_cluster/authority.py`:

- `NodeCapability` binds a node and generation/revision to capabilities, ceilings, adapter allowlist, signer, validity window, monotonic sequence, and replay domain.
- `WorkOffer` binds a canonical task reference and requirements to a bounded typed adapter and input hashes. It is placement intent, not a task replica.
- `Lease` binds one offer/node/revision/generation to the same ceilings, adapter, and inputs for a short validity window.
- `ExecutionReceipt` binds inputs and outputs, measured resource usage, signer, timestamps, sequence/replay domain, and signature. It deliberately contains no lifecycle status or completion instruction.

Only typed adapters are representable: `synthetic`, future `hermes-a2a`, and future `rootless-container`. There is no shell or argv adapter. All resource ceilings are positive and mandatory.

## Authority inventory

Public lifecycle mutation surfaces present in the upstream-compatible implementation:

| Surface | Canonical-looking effect | Mesh disposition |
| --- | --- | --- |
| `POST /api/v1/tasks` | create and promote task | denied |
| `POST /api/v1/tasks/{id}/complete` | complete and advance dependencies | denied |
| `POST /api/v1/tasks/{id}/fail` | fail and block dependents | denied |
| `POST /api/v1/tasks/{id}/unblock` | unblock | denied |
| `POST /api/v1/tasks/{id}/advance` | ready/advance | denied |
| `POST /api/v1/tasks/{id}/dependencies` | reparent dependency graph | denied |
| `POST /api/v1/tasks/{id}/claim` | running/assignment plus lease | denied |
| `POST /api/v1/tasks/{id}/release` | ready/unassign | denied |
| `POST /api/v1/schedule/trigger` | promote and assign | denied |
| `POST /api/v1/recovery/trigger`, `/detect-expired` | revoke/reschedule lifecycle | denied |
| `POST /api/v1/sync/receive`, `/receive-batch` | apply replicated task events | denied |
| `POST /api/v1/federation/tasks` | create canonical-looking remote work | denied |
| plugin `kanban_cluster_submit` | create through task API | not registered |
| plugin `kanban_cluster_complete` | complete through task API | not registered |
| `TaskManager` create/duplicate/update/cancel/retry/delete/auto-schedule/manual schedule | direct standalone lifecycle library API | retained as internal legacy compatibility; not exported by the Hermes plugin |
| `ClusterState` task/dependency/status/sync/schedule methods | persistence primitives underlying the above | retained for explicit legacy standalone mode |

Node join, heartbeat, capability updates, lease observations, pressure/metrics/status reads, configuration, hooks, and dashboard serving remain available. Old task-associated lease APIs are retained for compatibility but do not themselves award canonical completion.

## Consequences and residual risks

The boundary is compatibility-safe for callers that explicitly opt into standalone behavior, while default Hermes integration fails closed. P0 does not yet implement offer pull, signature verification, replay persistence, pressure admission, content-addressed artifact verification, or A2A transport; these belong to P1/P2. Contracts describe signed evidence but do not claim cryptographic verification exists yet. Legacy mode remains powerful by design and must not be exposed as a Hermes worker integration endpoint.

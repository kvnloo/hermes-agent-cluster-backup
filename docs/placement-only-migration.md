# Placement-only v1 migration

The upstream cluster's replicated Kanban/task-completion and arbitrary federation surfaces are not part of this MVP. Do not expose `/tasks/*/complete`, task sync, recovery rescheduling, or federation endpoints to a remote worker.

Migration steps:

1. Keep groot's existing Hermes Kanban API and SQLite database unchanged and private. It remains the only authority.
2. Generate one key on groot and one key on mbp. Exchange only the printed public keys; never copy either secret file or groot credentials.
3. Copy the example role configs and set the same two-entry public allowlist in both. Store secret JSON separately with mode 0600.
4. Start only `hermes_cluster.mesh_runtime` on each host. Bind to a private interface or localhost during setup; use a mutually protected private transport for a real device run.
5. Run the deterministic adapter canary. A `verified_claim` is evidence for a separate groot-side Kanban transition, not completion itself.
6. Preserve coordinator and worker JSONL logs plus promoted sha256 objects for review.

Rollback is process-level: stop the two mesh runtime processes. No Kanban schema or database migration is performed, so canonical task state is unaffected.

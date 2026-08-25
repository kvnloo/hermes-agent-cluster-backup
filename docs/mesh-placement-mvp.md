# Safe groot → mbp placement-only Mesh MVP

## Trust boundary

Hermes Kanban on groot is the sole task and completion authority. This runtime only issues placement leases and verifies signed worker claims. It never opens Kanban SQLite, replicates tasks, exposes remote shell, or marks a task done. The only worker is the owner-opted-in `mbp`; groot remains the local baseline.

Protocol envelopes use Ed25519 signatures over closed, versioned canonical JSON. Leases carry unique IDs, task/worker identity, issue/expiry time, attempt, capability requirements, adapter version, and input/payload digest. Receipts are append-only claims with lease lineage, input/output/artifact digests, resource observations, adapter/version, timestamps, and outcome. Nonces and receipt IDs are replay-protected.

Artifacts are size/type bounded, addressed by sha256, written to quarantine, checked before and after transfer, and atomically promoted by digest. The worker accepts only `sha256-benchmark@1`; it has no shell adapter and no network access contract.

## Local executable proof

```sh
python examples/run_two_process_demo.py
```

This starts separate coordinator and worker processes on random localhost ports, performs a signed lease → bounded execution → signed receipt → independent verification flow, reads placement state back, and prints the temporary evidence directory. It intentionally reports `real_mbp_proven: false`.

## Device setup

On groot:

```sh
python -m hermes_cluster.mesh_runtime keygen --device-id groot --secret-out ~/.config/hermes-mesh/groot.secret.json
```

On mbp:

```sh
python -m hermes_cluster.mesh_runtime keygen --device-id mbp --secret-out "$HOME/Library/Application Support/hermes-mesh/mbp.secret.json"
```

Exchange only the printed public-key JSON. Put both public keys in copies of `config/mesh-coordinator.example.json` and `config/mesh-worker-mbp.example.json`. Keep each private secret on its originating device. Then run:

```sh
# groot, private bind chosen by operator
python -m hermes_cluster.mesh_runtime serve --config /etc/hermes-mesh/coordinator.json --secret ~/.config/hermes-mesh/groot.secret.json --host 0.0.0.0 --port 8788

# mbp, private bind chosen by operator
python -m hermes_cluster.mesh_runtime serve --config "$HOME/Library/Application Support/hermes-mesh/worker.json" --secret "$HOME/Library/Application Support/hermes-mesh/mbp.secret.json" --host 0.0.0.0 --port 8789
```

Use only a private, mutually protected network path and firewall each port to the peer. The signed application protocol is mandatory even on that path. The mbp worker endpoint is `POST /v1/execute`; groot issues leases at `POST /v1/leases` and independently verifies receipts at `POST /v1/receipts/verify`.

## Resource policy

The mbp config requires explicit `owner_opt_in`, an allowlisted versioned adapter, timeout, minimum free memory and disk, maximum thermal observation, and no network. A gate failure emits a machine-readable refusal and executes nothing. The deterministic adapter bounds iterations to 1–1,000,000.

## Evidence and observability

Coordinator and worker append JSONL events. Accepted receipt events contain queue, lease, transfer, verification timing fields and bytes transferred. Lease events include attempts. Worker events distinguish claims and resource/policy refusals. Promoted artifacts live under `objects/sha256/<digest>`.

## Known limitations / field gate

- No real mbp canary is claimed until external recovery task `t_e6416d46` is complete and the host is reachable.
- Runtime state and replay caches are in memory for this bounded MVP; JSONL receipts/events are durable audit evidence, but restart-time replay admission must be reviewed before persistent unattended deployment.
- Thermal observation defaults to zero when not supplied by a platform sensor integration. Production mbp deployment must wire a real sensor observation before enabling persistence.
- The coordinator intentionally does not call Kanban completion. A separate trusted groot integration must read `verified_claim`, apply workload policy, and perform any canonical transition through the existing Kanban API.
- No performance multiplier claim is made.

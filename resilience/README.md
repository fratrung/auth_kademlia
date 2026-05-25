# Resilience Test

Simulates a **malicious Node B** flooding **Node A** to test crash resistance.

## Scenario

| Node | Role | Description |
|------|------|-------------|
| A (`node_a`) | Victim / seed | Seeds 5 DID records, then handles incoming RPCs under load. Limited to **2 CPU cores** and **256 MB RAM** to simulate an embedded edge node. |
| B (`node_b`) | Attacker | Bootstraps with A, pre-generates a pool of 150 DID records, then floods A for 120 s with a mix of valid SETs, GET hits, GET misses, and **invalid SETs** (tampered Dilithium signature). |

## What is tested

| Check | Expected |
|-------|----------|
| Node A does not crash | Process keeps running, [health] lines appear every 30 s |
| Node A stays responsive | Timeout rate < 10 % in the attacker's final report |
| Invalid records rejected | `invalid_accepted = 0` in the final report |
| Record immutability | Duplicate SETs return `rejected`, not accepted |
| Graceful degradation | Under CPU saturation, A may slow down but must not panic |

## Why Docker?

Running attacker and victim in the **same process** shares a Tokio runtime, so the attacker's overhead directly degrades the victim's runtime — that is not a realistic model. Docker gives each node its own OS process and runtime, and lets you constrain Node A's CPU budget with `deploy.resources.limits`, making the attack meaningful without locking up the host machine.

## Quick start

```bash
cd resilience

# Default: 120 s attack, 25 concurrent ops, Node A limited to 2 cores
docker compose up --build

# Custom intensity (longer, more concurrent)
DURATION_SECS=300 CONCURRENCY=40 docker compose up --build

# Detached + follow logs
docker compose up --build -d
docker compose logs -f
```

## Reading the output

```
[attacker] in progress         30s    312 ops   10.4/s
[attacker]   SET  ok=140   rejected=0     timeout=0
[attacker]   GET  hit=89   miss=72        timeout=0
[attacker]   INV  rejected=11  accepted=0

...

[attacker] ━━━ Resilience verdict ━━━

  [✓] Node A responsive   timeout rate 0.3% < 10%
  [✓] Security intact      all 18 invalid records rejected
  [✓] Valid SETs stored    140
  [✓] Rejected SETs        0 (dup/invalid)

  RESULT: Node A survived the attack without security violations.
```

A non-zero `invalid_accepted` count means Node A accepted a cryptographically
invalid record — that would be a **security failure** and causes the attacker
container to exit with code 1.

A timeout rate ≥ 10 % indicates Node A was CPU-saturated but still alive.
This is expected behaviour when `cpus` is set very low (e.g. `0.5`).

## Tuning

| Env var (node_b) | Default | Effect |
|------------------|---------|--------|
| `POOL_SIZE` | 150 | Pre-generated valid records. Each is a Dilithium-2 keypair (~6 KB). |
| `CONCURRENCY` | 25 | Max in-flight RPC ops. Higher = more load on Node A. |
| `DURATION_SECS` | 120 | Attack duration. |
| `TARGET_ADDR` | 172.21.0.10:5678 | Must match node_a's IP + `NODE_PORT`. |

| Env var (node_a) | Default | Effect |
|------------------|---------|--------|
| `NODE_PORT` | 5678 | UDP port. |
| `SEED_COUNT` | 5 | Records pre-seeded in local storage. |

CPU limit for Node A is set in `docker-compose.yaml` under `deploy.resources.limits.cpus`.

## Port allocation

| Port | Usage |
|------|-------|
| 172.21.0.10:5678 | Node A (internal Docker network) |
| 172.21.0.11:5679 | Node B (internal Docker network) |
| 0.0.0.0:15900/udp | Node A exposed to host (for external tooling) |

No conflict with the existing demo (`docker-compose.yaml`) which uses the `172.20.0.0/24` subnet.

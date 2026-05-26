#!/usr/bin/env python3
"""
Resilience benchmark — N-run statistical analysis.

Runs the Docker resilience test N times, collects METRICS_JSON from node_b,
then computes mean, standard deviation, and Student-t confidence intervals
for each performance metric.

Usage:
    cd auth-kademlia-rs
    python3 resilience/run_stats.py              # 10 runs, 95% CI
    python3 resilience/run_stats.py --runs 20 --confidence 0.99
    python3 resilience/run_stats.py --no-build   # skip --build (images already up to date)

Output:
    Console table + resilience/stats.json
"""

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

COMPOSE_DIR = Path(__file__).parent



def _t_ppf(alpha_half: float, df: int) -> float:
    """Upper critical value t_{alpha/2, df} for two-tailed CI."""
    try:
        from scipy.stats import t as _t
        return float(_t.ppf(1.0 - alpha_half, df))
    except ImportError:
        pass
    # Lookup table (alpha_half = 0.025, i.e. 95% CI)
    # Extend with a few extra levels; always use the closest >= df row.
    TABLE_95 = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
        6: 2.447,  7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
        16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
        25: 2.060, 30: 2.042, 40: 2.021, 60: 2.000, 120: 1.980,
    }
    TABLE_99 = {
        1: 63.657, 2: 9.925, 3: 5.841, 4: 4.604, 5: 4.032,
        6: 3.707,  7: 3.499, 8: 3.355, 9: 3.250, 10: 3.169,
        15: 2.947, 20: 2.845, 30: 2.750, 60: 2.660, 120: 2.617,
    }
    table = TABLE_99 if abs(alpha_half - 0.005) < 0.001 else TABLE_95
    keys = sorted(table)
    for i, k in enumerate(keys):
        if df <= k:
            if i == 0:
                return table[k]
            k0, k1 = keys[i - 1], k
            # linear interpolation on df
            frac = (df - k0) / (k1 - k0)
            return table[k0] + frac * (table[k1] - table[k0])
    return 1.960  # large-df normal approximation


def describe(samples: list, confidence: float) -> dict:
    n = len(samples)
    mean = sum(samples) / n
    if n < 2:
        return {"n": n, "mean": mean, "std": 0.0, "ci_lo": mean, "ci_hi": mean}
    var = sum((x - mean) ** 2 for x in samples) / (n - 1)
    std = math.sqrt(var)
    sem = std / math.sqrt(n)
    tc = _t_ppf((1.0 - confidence) / 2.0, n - 1)
    return {
        "n": n,
        "mean": mean,
        "std": std,
        "ci_lo": mean - tc * sem,
        "ci_hi": mean + tc * sem,
    }



def docker_run(build: bool) -> dict | None:
    subprocess.run(
        ["docker", "compose", "down", "--remove-orphans"],
        cwd=COMPOSE_DIR, capture_output=True,
    )
    cmd = ["docker", "compose", "up", "--abort-on-container-exit"]
    if build:
        cmd.append("--build")
    proc = subprocess.run(cmd, cwd=COMPOSE_DIR, capture_output=True, text=True)
    output = proc.stdout + proc.stderr
    marker = "METRICS_JSON "
    for line in reversed(output.splitlines()):
        idx = line.find(marker)
        if idx != -1:
            try:
                return json.loads(line[idx + len(marker):])
            except json.JSONDecodeError:
                pass
    return None



def derive(runs: list) -> dict:
    def pct(num, den):
        return num / den * 100.0 if den else 0.0

    return {
        "acceptance_rate_%": [
            pct(r["p1_accepted"], r["p1_accepted"] + r["p1_rejected"] + r["p1_timeout"])
            for r in runs
        ],
        "store_avg_ms":    [r["p1_avg_ms"]  for r in runs],
        "store_p95_ms":    [r["p1_p95_ms"]  for r in runs],
        "store_tps":       [r["p1_tps"]     for r in runs],
        "security_%":      [
            pct(r["p2_rejected"], r["p2_rejected"] + r["p2_accepted"] + r["p2_timeout"])
            for r in runs
        ],
        "get_miss_%":      [
            pct(r["p3_misses"], r["p3_hits"] + r["p3_misses"] + r["p3_timeout"])
            for r in runs
        ],
        "get_avg_ms":      [r["p3_avg_ms"]  for r in runs],
        "get_p95_ms":      [r["p3_p95_ms"]  for r in runs],
        "get_tps":         [r["p3_tps"]     for r in runs],
    }



def print_table(stats: dict, confidence: float):
    pct = int(confidence * 100)
    col = [28, 10, 10, 11, 11]
    sep = "  "
    header = (
        f"{'Metric':<{col[0]}}{sep}"
        f"{'Mean':>{col[1]}}{sep}"
        f"{'Std':>{col[2]}}{sep}"
        f"{'CI lo':>{col[3]}}{sep}"
        f"{'CI hi':>{col[4]}}  ({pct}% t-CI)"
    )
    print(header)
    print("─" * len(header))
    for name, s in stats.items():
        print(
            f"{name:<{col[0]}}{sep}"
            f"{s['mean']:>{col[1]}.3f}{sep}"
            f"{s['std']:>{col[2]}.3f}{sep}"
            f"{s['ci_lo']:>{col[3]}.3f}{sep}"
            f"{s['ci_hi']:>{col[4]}.3f}"
        )



def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs",       type=int,   default=10,   help="number of runs (default: 10)")
    ap.add_argument("--confidence", type=float, default=0.95, help="CI level (default: 0.95)")
    ap.add_argument("--no-build",   action="store_true",      help="skip --build on first run")
    args = ap.parse_args()

    print(f"Resilience benchmark — {args.runs} runs, "
          f"{args.confidence * 100:.0f}% t-Student CI\n")

    raw_runs: list[dict] = []
    try:
        for i in range(args.runs):
            build = (i == 0) and not args.no_build
            tag = "(--build)" if build else "         "
            print(f"  run {i + 1:>2}/{args.runs} {tag} … ", end="", flush=True)
            m = docker_run(build)
            if m is None:
                print("FAILED — METRICS_JSON not found in output")
                continue
            raw_runs.append(m)
            acc   = m["p1_accepted"]
            total = acc + m["p1_rejected"] + m["p1_timeout"]
            print(f"ok  accepted={acc}/{total}  store_p95={m['p1_p95_ms']:.1f}ms  "
                  f"get_p95={m['p3_p95_ms']:.1f}ms")
    except KeyboardInterrupt:
        print("\n\nInterrupted — computing stats on collected runs…")

    n_ok = len(raw_runs)
    if n_ok < 2:
        print(f"\nNeed ≥ 2 successful runs for statistics (got {n_ok}).")
        sys.exit(1)

    metrics  = derive(raw_runs)
    stats_tb = {k: describe(v, args.confidence) for k, v in metrics.items()}

    print(f"\nResults ({n_ok}/{args.runs} successful runs):\n")
    print_table(stats_tb, args.confidence)

    out = COMPOSE_DIR / "stats.json"
    out.write_text(json.dumps({"n_runs": n_ok, "confidence": args.confidence,
                               "stats": stats_tb, "raw": raw_runs}, indent=2))
    print(f"\nFull data → {out}")


if __name__ == "__main__":
    main()

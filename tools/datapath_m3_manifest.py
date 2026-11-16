#!/usr/bin/env python3
"""Render bounded M3 stages. This tool deliberately cannot execute commands."""

import argparse
import itertools
import json
import shlex
from pathlib import Path


def policy(name, shards, ingress="1", affinity="off", auto="1", strict="1"):
    return dict(name=name, shards=shards, ingress=ingress, affinity=affinity, auto=auto, strict=strict)


def screening_cases(stage):
    cases = []
    guards = [policy("default-unset", "unset", "unset", "unset", "unset", "unset"),
              policy("default-one", "1", "unset", "unset", "unset", "unset")]
    guards += [policy(f"spsc{ingress}-shards{shards}", shards, ingress)
               for shards, ingress in itertools.product(("1", "2"), ("0", "1"))]
    guards += [policy("auto-rollback", "auto", auto="0"),
               policy("explicit-rollback", "2", auto="0")]
    for config in guards:
        for direction in stage["directions"]:
            cases.append((config, 1, direction, "off"))
    for shards, parallel, direction in itertools.product(stage["shards"], stage["parallel"], stage["directions"]):
        cases.append((policy(f"scale-shards{shards}", shards), parallel, direction, "on"))
    # Matched count-one controls are needed for the auto P1 regression gate.
    for shards, direction in itertools.product(("1", "auto"), stage["directions"]):
        cases.append((policy(f"p1-shards{shards}", shards), 1, direction, "on"))
    return cases


def campaign(manifest, cpus, run_dir, decisions=None):
    budget = manifest["startup_cpu_budget"]
    if len(set(cpus)) != len(cpus) or any(cpu < 0 for cpu in cpus) or len(cpus) != budget:
        raise ValueError(f"supply exactly {budget} distinct nonnegative CPU IDs (one budget only)")
    decisions = decisions or {}
    s1, s2 = manifest["stages"]["S1"], manifest["stages"]["S2"]
    cases = screening_cases(s1)
    fixed_count = 2 * len(cases)
    shortlist = decisions.get("affinity_shortlist", [])
    if shortlist:
        if not decisions.get("screening_passed") or not decisions.get("evidence"):
            raise ValueError("affinity shortlist requires passed screening and an evidence reference")
        counts = [max(1, min(8, budget // 2)) if value == "auto" else int(value) for value in shortlist]
        if (len(shortlist) != s1["affinity_shortlist_size"] or len(set(counts)) != len(counts)
                or any(value not in s1["shards"] for value in shortlist)
                or any(count <= 1 or count > budget for count in counts)):
            raise ValueError("select two distinct eligible multiworker shard counts")
        for shards, affinity, parallel, direction in itertools.product(
            shortlist, ("off", "workers"), s1["parallel"], s1["directions"]
        ):
            cases.append((policy(f"affinity-shards{shards}-{affinity}", shards, affinity=affinity), parallel, direction, "on"))
    reserved_affinity = 2 * s1["affinity_shortlist_size"] * 2 * len(s1["parallel"]) * len(s1["directions"])
    upper_bound = fixed_count + reserved_affinity
    if upper_bound > min(160, s1["max_cells"]):
        raise ValueError(f"S1 budget exceeded: {upper_bound} cells (hard limit <=160)")
    rows = []
    for index, (config, parallel, direction, gso) in enumerate(cases):
        # Exactly one control/candidate pair; alternate order, no ABBA in screening.
        variants = ("control", "candidate") if index % 2 == 0 else ("candidate", "control")
        for slot, variant in enumerate(variants, 1):
            rows.append(_command(manifest, cpus, run_dir, "S1", config, parallel, direction, gso,
                                 variant, "xtcp", s1["duration"], s1["omit"], f"pass1-slot{slot}"))
    summaries = {"S1": {"cells": len(rows), "pending_cells": 0 if shortlist else reserved_affinity,
                        "max_planned_cells": upper_bound, "budget": s1["max_cells"]}}
    survivors = decisions.get("survivors", [])
    if len(survivors) > min(2, s2["max_survivors"]) or len(set(survivors)) != len(survivors):
        raise ValueError("S2 permits at most two distinct S1 survivors")
    configurations = {config["name"]: config for config, _, _, _ in cases
                      if config["name"].startswith(("scale-", "affinity-"))}
    if survivors and (not shortlist or not decisions.get("s1_complete") or not decisions.get("guards_passed")
                      or not decisions.get("evidence") or any(name not in configurations for name in survivors)):
        raise ValueError("S2 is blocked until complete S1 evidence passes all decision rules")
    start = len(rows)
    for name, parallel, direction, cycle in itertools.product(survivors, s2["parallel"], s2["directions"], range(1, s2["abba_cycles"] + 1)):
        for slot, variant in enumerate(s2["variant_order"], 1):
            for stack in ("native", "xtcp"):
                rows.append(_command(manifest, cpus, run_dir, "S2", configurations[name], parallel, direction,
                                     "on" if stack == "xtcp" else "off", variant, stack,
                                     s2["duration"], s2["omit"], f"cycle{cycle}-slot{slot}"))
    s2_count = len(rows) - start
    if s2_count > min(288, s2["max_cells"]):
        raise ValueError("S2 budget exceeded (hard limit <=288)")
    summaries["S2"] = {"cells": s2_count, "budget": s2["max_cells"], "status": "selected" if survivors else "blocked_pending_S1"}
    for check in manifest["invalid_input_checks"]:
        argv = ["bash", "tools/run_datapath_linux_matrix.sh", "--dry-run", "--artifacts", "/unused", *check["flags"]]
        rows.append(dict(stage="validation", cell=check["name"], expected_exit=2, argv=argv))
    summaries["validation"] = {"checks": len(manifest["invalid_input_checks"]), "measurement_cells": 0}
    return summaries, rows


def _command(manifest, cpus, run_dir, stage, config, parallel, direction, gso, variant, stack, duration, omit, exposure):
    count = max(1, min(8, len(cpus) // 2)) if config["shards"] == "auto" else (1 if config["shards"] == "unset" else int(config["shards"]))
    flags = ["--xtcp-shards", config["shards"], "--xtcp-spsc-ingress", config["ingress"],
             "--xtcp-affinity", config["affinity"], "--xtcp-io-cpus",
             ",".join(map(str, cpus[:count])) if config["affinity"] == "workers" else "unset",
             "--xtcp-affinity-strict", config["strict"], "--xtcp-auto-shards", config["auto"], "--xtcp-cc", "kcc"]
    cell = f"{stage}/{config['name']}/p{parallel}-{direction}-gso{gso}/{exposure}-{variant}-{stack}"
    argv = ["flock", "/tmp/ppp-m2-measure.lock", "bash", "tools/run_m3_isolated.sh", "--run-dir", run_dir, "--", "env"]
    for key in manifest["unset_process_env"]:
        argv += ["-u", key]
    argv += ["bash", "tools/run_datapath_linux_matrix.sh", *manifest["runner_flags"], "--affinity-cpus", ",".join(map(str, cpus)),
             *flags, "--ppp-bin", manifest["binaries"][variant], "--artifacts", f"{run_dir}/results/{cell}",
             "--stacks", stack, "--parallel", str(parallel), "--directions", direction, "--tap-gso", gso,
             "--rounds", "1", "--duration", str(duration), "--omit", str(omit)]
    return dict(stage=stage, cell=cell, expected_exit=0, argv=argv)


def commands(manifest, cpus, run_dir, decisions=None):
    return iter(campaign(manifest, cpus, run_dir, decisions)[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cpus", required=True, help="explicit ordered CPU IDs for the future board")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--decisions", type=Path, help="reviewed S1 decisions and evidence reference; absent means blocked")
    parser.add_argument("--dry-run", action="store_true", required=True)
    args = parser.parse_args()
    try:
        summaries, rows = campaign(json.loads(args.manifest.read_text()), list(map(int, args.cpus.split(","))),
                                   args.run_dir, json.loads(args.decisions.read_text()) if args.decisions else None)
    except (ValueError, KeyError) as error:
        parser.error(str(error))
    for stage, summary in summaries.items():
        print(f"# stage={stage} " + " ".join(f"{key}={value}" for key, value in summary.items()))
    for row in rows:
        print(f"# stage={row['stage']} cell={row['cell']} expected_exit={row['expected_exit']}")
        print(shlex.join(row["argv"]))


if __name__ == "__main__":
    main()

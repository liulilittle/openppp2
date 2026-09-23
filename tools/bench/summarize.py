#!/usr/bin/env python3
import json
import statistics
import sys
from pathlib import Path


def median(rows, field):
    values = [row[field] for row in rows if isinstance(row.get(field), (int, float))]
    return statistics.median(values) if values else None


def read_cycles(path):
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        columns = line.split(",")
        if len(columns) > 2 and columns[2].strip() == "cycles":
            try:
                return int(columns[0].replace(" ", ""))
            except ValueError:
                return None
    return None


def summarize(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = [row for row in document.get("benchmarks", []) if row.get("run_type") == "iteration"]
    grouped = {}
    for row in rows:
        grouped.setdefault(row["name"], []).append(row)
    return {
        name: {
            "ns_per_op": median(samples, "real_time"),
            "pps": median(samples, "items_per_second"),
            "allocations_per_op": median(samples, "allocations"),
        }
        for name, samples in sorted(grouped.items())
    }, sum(row.get("iterations", 0) for row in rows)


def main():
    result_dir = Path(sys.argv[1])
    output = {}
    for path in sorted(result_dir.glob("bm_*.json")):
        benchmarks, iterations = summarize(path)
        cycles = read_cycles(path.with_suffix(".perf"))
        output[path.stem] = {
            "benchmarks": benchmarks,
            "aggregate_cycles_per_packet": cycles / iterations if cycles is not None and iterations else None,
        }
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()

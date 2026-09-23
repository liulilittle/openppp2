#!/usr/bin/env python3
"""compare.py — openppp2 UDP 微基准 A/B 判定。

用法: compare.py <baseline.json> <candidate.json>

输入必须包含每次 repetition 的 run_type=iteration 行。脚本对每个同名 benchmark：
  - 取 real_time 的中位数；
  - bootstrap 95% 置信区间（固定 seed，可复现）；
  - 仅当 candidate 与 baseline 的 CI 不重叠时判定显著变化。
"""
import json
import random
import sys

random.seed(42)
BOOTSTRAP_N = 4000
CI = 0.95


def median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return float("nan")
    m = n // 2
    return s[m] if n % 2 else (s[m - 1] + s[m]) / 2.0


def bootstrap_ci(data):
    if len(data) < 2:
        v = median(data) if data else float("nan")
        return v, v
    meds = []
    n = len(data)
    for _ in range(BOOTSTRAP_N):
        sample = [data[random.randrange(n)] for _ in range(n)]
        meds.append(median(sample))
    meds.sort()
    lo = meds[int((1 - CI) / 2 * BOOTSTRAP_N)]
    hi = meds[int((1 + CI) / 2 * BOOTSTRAP_N)]
    return lo, hi


def load(path):
    """Return {benchmark_name: [real_time, ...]} for raw repetition samples only."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)

    out = {}
    for benchmark in doc.get("benchmarks", []):
        if benchmark.get("run_type") != "iteration":
            continue
        name = benchmark.get("name")
        real_time = benchmark.get("real_time")
        if not name or real_time is None:
            continue
        out.setdefault(name, []).append(float(real_time))
    return out


def require_samples(label, path, samples):
    if samples:
        return
    print(f"{label} contains no raw repetition samples: {path}", file=sys.stderr)
    print(
        "remove DisplayAggregatesOnly(true) and do not pass "
        "--benchmark_report_aggregates_only",
        file=sys.stderr,
    )
    sys.exit(1)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)

    baseline_path, candidate_path = sys.argv[1:]
    baseline = load(baseline_path)
    candidate = load(candidate_path)

    require_samples("baseline", baseline_path, baseline)
    require_samples("candidate", candidate_path, candidate)

    names = sorted(set(baseline) & set(candidate))
    if not names:
        print("no common raw benchmark samples", file=sys.stderr)
        print(f"baseline benchmarks: {sorted(baseline)}", file=sys.stderr)
        print(f"candidate benchmarks: {sorted(candidate)}", file=sys.stderr)
        sys.exit(1)

    print(f"{'benchmark':<52} {'base(ns)':>10} {'cand(ns)':>10} {'delta':>8}  verdict")
    print("-" * 100)
    improved = regressed = noise = 0

    for name in names:
        base_median = median(baseline[name])
        candidate_median = median(candidate[name])
        base_lo, base_hi = bootstrap_ci(baseline[name])
        candidate_lo, candidate_hi = bootstrap_ci(candidate[name])
        delta = (candidate_median - base_median) / base_median * 100.0 if base_median else 0.0

        if candidate_hi < base_lo:
            verdict = "IMPROVED (CI disjoint)"
            improved += 1
        elif candidate_lo > base_hi:
            verdict = "REGRESSED (CI disjoint)"
            regressed += 1
        else:
            verdict = "noise (CI overlap)"
            noise += 1

        short = name.replace("/repeats:15/real_time", "").replace("/real_time", "")
        print(f"{short:<52} {base_median:>10.1f} {candidate_median:>10.1f} {delta:>+7.1f}%  {verdict}")

    print("-" * 100)
    print(f"improved={improved}  regressed={regressed}  noise={noise}")


if __name__ == "__main__":
    main()

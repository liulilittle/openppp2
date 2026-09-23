#!/usr/bin/env python3
import json
import math
from pathlib import Path
import sys

from validate_fixed_host import validate_environment
from summarize import summarize as summarize_micro_file


TARGETS = {
    "bm_allocator",
    "bm_crypto",
    "bm_crypto_chain",
    "bm_endpoint_serialize",
    "bm_packet_codec",
}
STABLE_ENVIRONMENT_FIELDS = {
    "cpu",
    "arch",
    "host_id",
    "virt",
    "kernel",
    "git_sha",
    "compiler",
    "bench_flags",
    "governor",
}
CYCLE_CASES = {
    "endpoint_ipv4",
    "packet_codec_64",
    "packet_codec_1400",
    "crypto_openssl_64",
    "crypto_simd_64",
    "crypto_openssl_1400",
    "crypto_simd_1400",
}


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def number(value, name, allow_zero=True):
    minimum = 0 if allow_zero else 0.0
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < minimum
        or (not allow_zero and value == 0)
    ):
        raise ValueError(f"{name} must be a finite positive number")
    return value


def benchmark_metrics(summary, target, name):
    try:
        metrics = summary[target]["benchmarks"][name]
    except (KeyError, TypeError) as error:
        raise ValueError(f"missing {target}:{name}") from error
    return {
        "ns_per_op": number(metrics.get("ns_per_op"), f"{name}.ns_per_op", False),
        "pps": number(metrics.get("pps"), f"{name}.pps", False),
        "allocations_per_op": number(
            metrics.get("allocations_per_op"), f"{name}.allocations_per_op"
        ),
    }


def validate_raw_micro(micro, summary):
    for target in TARGETS:
        path = micro / f"{target}.json"
        document = load_json(path)
        rows = document.get("benchmarks")
        if not isinstance(rows, list) or not any(
            isinstance(row, dict) and row.get("run_type") == "iteration"
            for row in rows
        ):
            raise ValueError(f"{target}.json contains no iteration results")
        calculated, _ = summarize_micro_file(path)
        if summary.get(target, {}).get("benchmarks") != calculated:
            raise ValueError(f"{target} summary does not match raw benchmark results")


def validate_e2e(e2e, root):
    if load_json(e2e / "appsettings.bench.json") != load_json(
        root / "appsettings.bench.json"
    ):
        raise ValueError("E2E appsettings.bench.json differs from the frozen config")
    output = {}
    offered_bitrate = None
    for size in (64, 1400):
        raw = load_json(e2e / f"e2e-{size}.json")
        if raw.get("error"):
            raise ValueError(f"e2e-{size}.json contains an iperf error")
        summary = load_json(e2e / f"e2e-{size}.summary.json")
        for name in ("seconds", "packets", "pps"):
            number(summary.get(name), f"e2e-{size}.{name}", False)
        bitrate = summary.get("offered_bitrate")
        if not isinstance(bitrate, str) or not bitrate:
            raise ValueError(f"e2e-{size}.offered_bitrate is missing")
        if offered_bitrate is not None and bitrate != offered_bitrate:
            raise ValueError("E2E packet sizes use different offered bitrates")
        raw_metrics = raw.get("end", {}).get("sum") or raw.get("end", {}).get(
            "sum_sent"
        )
        if not isinstance(raw_metrics, dict):
            raise ValueError(f"e2e-{size}.json has no completed UDP summary")
        seconds = number(raw_metrics.get("seconds"), f"e2e-{size}.raw.seconds", False)
        packets = number(raw_metrics.get("packets"), f"e2e-{size}.raw.packets", False)
        if (
            summary["seconds"] != seconds
            or summary["packets"] != packets
            or not math.isclose(summary["pps"], packets / seconds, rel_tol=1e-12)
        ):
            raise ValueError(f"e2e-{size} summary does not match raw iperf results")
        offered_bitrate = bitrate
        output[str(size)] = summary
    return output


def packet_report(size, summary, cycles, e2e):
    endpoint = benchmark_metrics(
        summary, "bm_endpoint_serialize", "BM_EndpointRoundTrip/ipv4"
    )
    packet = benchmark_metrics(summary, "bm_packet_codec", f"BM_PacketCodec/{size}")
    openssl = benchmark_metrics(
        summary, "bm_crypto_chain", f"BM_CryptoChain/openssl/{size}"
    )
    simd = benchmark_metrics(
        summary, "bm_crypto_chain", f"BM_CryptoChain/simd/{size}"
    )
    endpoint_cycles = cycles["endpoint_ipv4"]["cycles_per_packet"]
    packet_cycles = cycles[f"packet_codec_{size}"]["cycles_per_packet"]
    openssl_cycles = cycles[f"crypto_openssl_{size}"]["cycles_per_packet"]
    simd_cycles = cycles[f"crypto_simd_{size}"]["cycles_per_packet"]
    for name, value in (
        ("endpoint cycles", endpoint_cycles),
        ("packet codec cycles", packet_cycles),
        ("OpenSSL crypto cycles", openssl_cycles),
        ("SIMD crypto cycles", simd_cycles),
    ):
        number(value, name, False)
    total_openssl_cycles = endpoint_cycles + packet_cycles + openssl_cycles
    total_simd_cycles = endpoint_cycles + packet_cycles + simd_cycles
    total_openssl_ns = endpoint["ns_per_op"] + packet["ns_per_op"] + openssl["ns_per_op"]
    total_simd_ns = endpoint["ns_per_op"] + packet["ns_per_op"] + simd["ns_per_op"]
    return {
        "components": {
            "endpoint": endpoint,
            "packet_codec": packet,
            "crypto_openssl": openssl,
            "crypto_simd": simd,
        },
        "openssl_cycles_per_packet": total_openssl_cycles,
        "simd_cycles_per_packet": total_simd_cycles,
        "openssl_ns_per_packet": total_openssl_ns,
        "simd_ns_per_packet": total_simd_ns,
        "amdahl_improvement_percent":
            (total_openssl_cycles - total_simd_cycles) / total_openssl_cycles * 100,
        "e2e": e2e[str(size)],
    }


def main():
    if len(sys.argv) != 5:
        print(
            "usage: validate_baseline_bundle.py MICRO_DIR E2E_DIR EXPECTED_HOST_ID EXPECTED_GIT_SHA",
            file=sys.stderr,
        )
        return 2
    micro, e2e = Path(sys.argv[1]), Path(sys.argv[2])
    expected_host_id, expected_git_sha = sys.argv[3], sys.argv[4]
    try:
        if len(expected_git_sha) != 40 or any(
            character not in "0123456789abcdef" for character in expected_git_sha
        ):
            raise ValueError("expected git SHA must be 40 lowercase hex characters")
        environments = [load_json(path / "env.json") for path in (micro, e2e)]
        for environment in environments:
            error = validate_environment(
                environment, expected_host_id, expected_git_sha
            )
            if error:
                raise ValueError(error)
        for field in sorted(STABLE_ENVIRONMENT_FIELDS):
            if any(environment.get(field) in (None, "") for environment in environments):
                raise ValueError(f"environment fingerprint is missing {field}")
            if environments[0].get(field) != environments[1].get(field):
                raise ValueError(f"micro/E2E environment mismatch: {field}")
        summary = load_json(micro / "summary.json")
        if set(summary) != TARGETS:
            raise ValueError("micro summary does not contain the exact benchmark target set")
        validate_raw_micro(micro, summary)
        cycles_document = load_json(micro / "cycles.json")
        if cycles_document.get("available") is not True:
            raise ValueError("per-case cycles are unavailable")
        cycles = cycles_document.get("cases")
        if not isinstance(cycles, dict) or set(cycles) != CYCLE_CASES:
            raise ValueError("cycles.json does not contain the exact required case set")
        e2e_results = validate_e2e(e2e, Path(__file__).resolve().parent)
        report = {
            "schema_version": 1,
            "host_id": expected_host_id,
            "git_sha": expected_git_sha,
            "environment": environments[0],
            "packets": {
                str(size): packet_report(size, summary, cycles, e2e_results)
                for size in (64, 1400)
            },
        }
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as error:
        print(error, file=sys.stderr)
        return 1
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

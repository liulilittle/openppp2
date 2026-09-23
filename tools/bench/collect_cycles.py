#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


CASES = {
    "endpoint_ipv4": ("bm_endpoint_serialize", "BM_EndpointRoundTrip/ipv4"),
    "packet_codec_64": ("bm_packet_codec", "BM_PacketCodec/64"),
    "packet_codec_1400": ("bm_packet_codec", "BM_PacketCodec/1400"),
    "crypto_openssl_64": ("bm_crypto_chain", "BM_CryptoChain/openssl/64"),
    "crypto_simd_64": ("bm_crypto_chain", "BM_CryptoChain/simd/64"),
    "crypto_openssl_1400": ("bm_crypto_chain", "BM_CryptoChain/openssl/1400"),
    "crypto_simd_1400": ("bm_crypto_chain", "BM_CryptoChain/simd/1400"),
}


def read_cycles(path):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        columns = line.split(",")
        if len(columns) > 2 and columns[2].strip() == "cycles":
            try:
                return int(columns[0].replace(" ", ""))
            except ValueError:
                break
    raise ValueError("perf did not report cycles")


def read_iterations(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    iterations = sum(
        row.get("iterations", 0)
        for row in document.get("benchmarks", [])
        if row.get("run_type") == "iteration"
    )
    if not isinstance(iterations, int) or iterations < 1:
        raise ValueError("benchmark did not report iterations")
    return iterations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--unavailable", action="store_true")
    args = parser.parse_args()
    if args.list:
        print(json.dumps(CASES, indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("BUILD and OUTPUT are required")
    if args.unavailable:
        args.output.write_text(
            json.dumps({"available": False, "cases": {}}, indent=2) + "\n",
            encoding="utf-8",
        )
        return 0
    if args.build is None:
        parser.error("BUILD is required")

    output = {}
    try:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            for case, (target, benchmark) in CASES.items():
                executable = args.build / target
                if not executable.is_file():
                    raise ValueError(f"missing benchmark executable: {executable}")
                perf_path = temporary / f"{case}.perf"
                json_path = temporary / f"{case}.json"
                command = [
                    "nice", "-n", "19", "perf", "stat", "-x,", "-e", "cycles",
                    "-o", str(perf_path), "--", str(executable),
                    f"--benchmark_filter=^{re.escape(benchmark)}$",
                    "--benchmark_min_time=0.2",
                    "--benchmark_repetitions=1",
                    f"--benchmark_out={json_path}",
                    "--benchmark_out_format=json",
                ]
                completed = subprocess.run(command, capture_output=True, text=True)
                if completed.returncode != 0:
                    raise ValueError(
                        f"{case} failed: {completed.stderr.strip() or completed.stdout.strip()}"
                    )
                cycles = read_cycles(perf_path)
                iterations = read_iterations(json_path)
                output[case] = {
                    "benchmark": benchmark,
                    "cycles": cycles,
                    "iterations": iterations,
                    "cycles_per_packet": cycles / iterations,
                }
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    args.output.write_text(
        json.dumps({"available": True, "cases": output}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

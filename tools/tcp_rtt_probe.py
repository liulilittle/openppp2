#!/usr/bin/env python3
"""Low-rate in-band TCP echo-latency probe for datapath laboratory runs."""

import argparse
import csv
import socket
import sys
import time
from pathlib import Path


def monotonic_sleep_until(target_ns: int) -> None:
    remaining_ns = target_ns - time.monotonic_ns()
    if remaining_ns > 0:
        time.sleep(remaining_ns / 1_000_000_000)


def run_server(args: argparse.Namespace) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen()
        while True:
            connection, _ = listener.accept()
            with connection:
                while True:
                    payload = connection.recv(4096)
                    if not payload:
                        break
                    connection.sendall(payload)


def run_client(args: argparse.Namespace) -> int:
    if args.rate_hz <= 0:
        raise ValueError("--rate-hz must be positive")
    if args.deadline_monotonic_ns <= args.start_monotonic_ns:
        raise ValueError("--deadline-monotonic-ns must exceed --start-monotonic-ns")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    period_ns = max(1, round(1_000_000_000 / args.rate_hz))
    sequence = 0
    next_sample_ns = args.start_monotonic_ns
    connection = None

    def close_connection() -> None:
        nonlocal connection
        if connection is not None:
            connection.close()
            connection = None

    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("sequence", "start_monotonic_ns", "end_monotonic_ns", "echo_latency_ns", "status"))
        while next_sample_ns < args.deadline_monotonic_ns:
            monotonic_sleep_until(next_sample_ns)
            start_ns = time.monotonic_ns()
            if start_ns >= args.deadline_monotonic_ns:
                break
            status = "ok"
            try:
                if connection is None:
                    connection = socket.create_connection((args.host, args.port), timeout=args.timeout_s)
                    connection.settimeout(args.timeout_s)
                connection.sendall(b"\0")
                echoed = connection.recv(1)
                if echoed != b"\0":
                    raise ConnectionError("unexpected echo payload")
            except OSError as error:
                status = f"error:{error.__class__.__name__}"
                close_connection()
            end_ns = time.monotonic_ns()
            writer.writerow((sequence, start_ns, end_ns, end_ns - start_ns, status))
            stream.flush()
            sequence += 1
            next_sample_ns += period_ns
    close_connection()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server = subparsers.add_parser("server", help="run a TCP echo server")
    server.add_argument("--host", required=True)
    server.add_argument("--port", required=True, type=int)
    server.set_defaults(handler=run_server)

    client = subparsers.add_parser(
        "client", help="sample in-band echo latency on one persistent TCP connection"
    )
    client.add_argument("--host", required=True)
    client.add_argument("--port", required=True, type=int)
    client.add_argument("--start-monotonic-ns", required=True, type=int)
    client.add_argument("--deadline-monotonic-ns", required=True, type=int)
    client.add_argument("--rate-hz", required=True, type=float)
    client.add_argument("--timeout-s", default=0.5, type=float)
    client.add_argument("--output", required=True)
    client.set_defaults(handler=run_client)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return args.handler(args)
    except (OSError, ValueError) as error:
        print(f"tcp_echo_probe: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

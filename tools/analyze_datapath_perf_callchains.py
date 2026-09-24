#!/usr/bin/env python3
"""Classify split cpu-clock perf callchains for PPP datapath measurements.

Kernel location categories are mutually exclusive. Mechanism labels deliberately
overlap. Kernel samples retain userspace frames below the syscall boundary, so
all kernel classification operates only on canonical kernel-address frames.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import json
import re
from pathlib import Path
from typing import Iterable

HEADER_RE = re.compile(r"\bcpu-clock:(?P<mode>[uk]):\s*$")
DSO_SUFFIX_RE = re.compile(r"\s+\((?P<dso>[^()]*)\)\s*$")

KERNEL_LOCATION_RULES = (
    ("tun_output", ("tun_chr_write_iter", "tun_get_user", "tun_net_xmit", "tun_do_xmit")),
    ("tun_input", ("tun_chr_read_iter", "tun_do_read")),
    ("carrier_tcp_tx", ("tcp_sendmsg", "tcp_write_xmit", "__tcp_transmit_skb", "__ip_queue_xmit", "tcp_push_pending_frames")),
    ("carrier_tcp_rx_ack", ("tcp_v4_rcv", "tcp_rcv_established", "tcp_ack", "tcp_data_queue", "tcp_recvmsg")),
)
OTHER_NETWORK_ANCHORS = (
    "ip_", "netif_", "__netif", "skb_", "__dev_queue_xmit", "net_rx_action", "napi", "xfrm", "tcp_",
    "udp_", "inet_", "sock_", "dev_", "fib_", "dst_",
)
SCHEDULER_ANCHORS = ("schedule", "sched_", "finish_task_switch", "futex", "try_to_wake_up")
FD_IO_ANCHORS = ("vfs_read", "vfs_write", "new_sync_read", "new_sync_write", "do_iter_read", "do_iter_write", "ksys_read", "ksys_write", "io_uring")
SYSCALL_ANCHORS = ("do_syscall", "__x64_sys", "entry_syscall")

MECHANISM_RULES = {
    "copy_move": ("copy", "memcpy", "rep_movs", "memmove"),
    "checksum": ("csum", "checksum"),
    "skb_alloc_free": ("__alloc_skb", "skb_alloc", "skb_free", "kfree_skb", "consume_skb", "skb_release", "skb_clone"),
    "spinlock": ("spin_lock", "spin_unlock", "_raw_spin"),
    "syscall_entry_exit": SYSCALL_ANCHORS,
    "scheduler": SCHEDULER_ANCHORS,
}

USER_LOCATION_RULES = (
    ("crypto", ("aesni", "crypto_", "evp_", "ossl_", "aes_", "cfb", "gcm", "chacha")),
    ("vnet", ("vnet", "vnetstack", "vethernet", "lwip", "pbuf")),
    ("tun", ("taplinux", "tun", "tap_")),
    ("mux_frame", ("mux", "frame", "vmux")),
    ("asio_event", ("boost::asio", "io_context", "scheduler", "executor", "epoll", "reactor")),
    ("allocator", ("malloc", "free", "new", "delete", "allocate", "deallocate")),
    ("copy_move", ("memcpy", "memmove", "copy", "rep movs")),
)


@dataclasses.dataclass(frozen=True)
class Frame:
    address: str
    symbol: str
    dso: str


def samples_from_script(path: Path) -> Iterable[tuple[str, list[Frame]]]:
    block: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            block.append(line)
            continue
        if block:
            yield parse_block(block)
            block = []
    if block:
        yield parse_block(block)


def parse_block(block: list[str]) -> tuple[str, list[Frame]]:
    header_match = HEADER_RE.search(block[0])
    if not header_match:
        return "unknown", []
    mode = header_match.group("mode")
    frames: list[Frame] = []
    for line in block[1:]:
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        address, tail = parts
        dso_match = DSO_SUFFIX_RE.search(tail)
        dso = dso_match.group("dso") if dso_match else "[dso unavailable]"
        symbol = tail[:dso_match.start()].strip() if dso_match else tail.strip()
        if not symbol:
            continue
        # A kernel sample also contains the userspace caller chain. Exclude it
        # before all kernel classification to prevent false Asio/scheduler hits.
        if mode == "k" and not address.lower().startswith("ffffffff"):
            continue
        frames.append(Frame(address=address, symbol=symbol, dso=dso))
    return mode, frames


def contains_any(frames: list[Frame], anchors: tuple[str, ...]) -> bool:
    text = "\n".join(frame.symbol for frame in frames).lower()
    return any(anchor in text for anchor in anchors)


def classify_kernel(frames: list[Frame]) -> str:
    if not frames:
        return "unresolved"
    for domain, anchors in KERNEL_LOCATION_RULES:
        if contains_any(frames, anchors):
            return domain
    if contains_any(frames, OTHER_NETWORK_ANCHORS):
        return "other_network"
    if contains_any(frames, SCHEDULER_ANCHORS):
        return "scheduler_futex"
    if contains_any(frames, FD_IO_ANCHORS):
        return "non_network_fd_io"
    if contains_any(frames, SYSCALL_ANCHORS):
        return "unattributed_syscall_path"
    return "other_kernel"


def classify_user(frames: list[Frame]) -> str:
    if not frames:
        return "unresolved"
    leaf = frames[0]
    for domain, anchors in USER_LOCATION_RULES:
        if contains_any([leaf], anchors):
            return domain
    if leaf.symbol == "[unknown]":
        return "unresolved_libc_leaf" if "libc.so" in leaf.dso else "unresolved_user_leaf"
    return "other_user"


def percentage(count: int, total: int) -> float:
    return round(100.0 * count / total, 3) if total else 0.0


def ranked(counter: collections.Counter[str], total: int) -> list[dict[str, object]]:
    return [{"name": name, "samples": count, "percent": percentage(count, total)} for name, count in counter.most_common()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("perf_script", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--top", type=int, default=30)
    args = parser.parse_args()

    kernel_locations: collections.Counter[str] = collections.Counter()
    kernel_mechanisms: collections.Counter[str] = collections.Counter()
    user_locations: collections.Counter[str] = collections.Counter()
    user_leaves: collections.Counter[str] = collections.Counter()
    user_dsos: collections.Counter[str] = collections.Counter()
    totals: collections.Counter[str] = collections.Counter()

    for mode, frames in samples_from_script(args.perf_script):
        if mode == "k":
            totals["kernel"] += 1
            kernel_locations[classify_kernel(frames)] += 1
            for name, anchors in MECHANISM_RULES.items():
                if contains_any(frames, anchors):
                    kernel_mechanisms[name] += 1
        elif mode == "u":
            totals["user"] += 1
            user_locations[classify_user(frames)] += 1
            if frames:
                user_leaves[frames[0].symbol] += 1
                user_dsos[frames[0].dso] += 1

    result = {
        "input": str(args.perf_script),
        "sample_totals": dict(totals),
        "kernel_location_mutually_exclusive": ranked(kernel_locations, totals["kernel"]),
        "kernel_location_check": {
            "classified_samples": sum(kernel_locations.values()),
            "kernel_samples": totals["kernel"],
            "matches": sum(kernel_locations.values()) == totals["kernel"],
        },
        "kernel_mechanisms_overlapping": ranked(kernel_mechanisms, totals["kernel"]),
        "user_location_mutually_exclusive": ranked(user_locations, totals["user"]),
        "user_leaf_symbols": ranked(user_leaves, totals["user"])[: args.top],
        "user_leaf_dsos": ranked(user_dsos, totals["user"])[: args.top],
        "notes": [
            "Kernel location categories are mutually exclusive and use ordered callchain anchors.",
            "Kernel mechanism categories overlap and must not be summed.",
            "Kernel labels inspect only canonical kernel frames; retained userspace callers are ignored.",
            "unattributed_syscall_path means samples whose deepest identifiable frame is generic syscall entry/exit; it does not prove the entry/exit instructions themselves cost that much.",
            "User locations use the sampled leaf and its DSO. Unresolved libc leaves are reported without guessing their operation.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

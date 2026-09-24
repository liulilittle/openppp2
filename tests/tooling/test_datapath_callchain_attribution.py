#!/usr/bin/env python3
"""Regression contract for tools/analyze_datapath_perf_callchains.py."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYZER = ROOT / "tools/analyze_datapath_perf_callchains.py"
FIXTURE = """\
ppp 1/1 cpu-clock:k:
    ffffffffa0000001 tcp_write_xmit ([kernel.kallsyms])
    ffffffffa0000002 do_syscall_64 ([kernel.kallsyms])
        555555555555 boost::asio::detail::scheduler::run() (/tmp/ppp)

ppp 1/1 cpu-clock:k:
    ffffffffa0000003 schedule ([kernel.kallsyms])
    ffffffffa0000004 do_syscall_64 ([kernel.kallsyms])

ppp 1/1 cpu-clock:u:
        7f0000000001 [unknown] (/usr/lib/x86_64-linux-gnu/libc.so.6)

ppp 1/1 cpu-clock:u:
        555555555556 aesni_encrypt (/tmp/ppp)
"""


def entries_by_name(entries):
    return {entry["name"]: entry["samples"] for entry in entries}


def main():
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        script = directory / "fixture.perf.script"
        output = directory / "result.json"
        script.write_text(FIXTURE, encoding="utf-8")
        subprocess.run([sys.executable, str(ANALYZER), str(script), "--output", str(output)], check=True, stdout=subprocess.DEVNULL)
        result = json.loads(output.read_text(encoding="utf-8"))

    kernel = entries_by_name(result["kernel_location_mutually_exclusive"])
    user = entries_by_name(result["user_location_mutually_exclusive"])
    dsos = entries_by_name(result["user_leaf_dsos"])
    assert kernel == {"carrier_tcp_tx": 1, "scheduler_futex": 1}, kernel
    assert user == {"unresolved_libc_leaf": 1, "crypto": 1}, user
    assert dsos["/usr/lib/x86_64-linux-gnu/libc.so.6"] == 1, dsos
    assert result["kernel_location_check"]["matches"], result
    print("datapath callchain attribution contract: pass")


if __name__ == "__main__":
    main()

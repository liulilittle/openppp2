#!/usr/bin/env python3
"""Read-only, fail-closed interval evidence analysis; not a throughput gate."""

import argparse
import json
import math
import sys

if __package__:
    from .xtcp_ul_stall_input import EvidenceError, finite_number, integer, load_document, sampling_role
else:
    from xtcp_ul_stall_input import EvidenceError, finite_number, integer, load_document, sampling_role


# iperf JSON timestamps are printed to microseconds. Never use relative
# tolerance (large timestamps must not conceal large missing intervals).
CONTINUITY_TOLERANCE = 0.000001
EDGE_TOLERANCE = 0.001  # timer reset/measurement boundary skew, not internal gaps
EXIT_CODES = {"no_observed_stall": 0, "observed_stall": 1, "not_assessed": 2}
LIMITATION = (
    "Sender-side interval observations only: no proof of receiver delivery, "
    "continuous application demand, budget deadlock, or throughput acceptance. "
    "Positive-byte intervals may still contain shorter unobservable pauses."
)


def _object(value, name):
    if not isinstance(value, dict):
        raise EvidenceError(f"{name}: expected object")
    return value


def _number(value, name, positive=False):
    value = finite_number(value, name, positive=positive)
    try:
        result = float(value)
    except OverflowError as exc:
        raise EvidenceError(f"{name}: outside supported float range") from exc
    if not math.isfinite(result):
        raise EvidenceError(f"{name}: outside supported float range")
    return result


def _bytes(value, name):
    value = integer(value, name)
    if value > 2**64 - 1:
        raise EvidenceError(f"{name}: exceeds uint64 counter")
    return value


def _rate(count, duration):
    result = count / duration
    if not math.isfinite(result):
        raise EvidenceError("rate outside supported float range")
    return result


def _jain(rates):
    largest = max(rates)
    if largest == 0:
        return None  # 0/0 is undefined, not perfect fairness
    scaled = [value / largest for value in rates]
    return math.fsum(scaled)**2 / (len(scaled) * math.fsum(x*x for x in scaled))


def _envelope(threshold):
    return {
        "schema_version": 1, "status": "not_assessed", "reasons": [],
        "sampling_side": "unverified", "stall_seconds": threshold,
        "continuity_tolerance_seconds": CONTINUITY_TOLERANCE,
        "edge_tolerance_seconds": EDGE_TOLERANCE,
        "limitations": LIMITATION, "flows": [], "fairness": None,
    }


def _collect(doc):
    sockets = sampling_role(doc)
    expected = set(sockets)
    config = doc["start"]["test_start"]
    duration = _number(config.get("duration"), "test_start.duration", positive=True)
    if doc.get("error") is not None:
        raise EvidenceError("iperf reported an error")
    rows = doc.get("intervals")
    if not isinstance(rows, list) or not rows:
        raise EvidenceError("intervals: missing or empty")
    samples = {socket: [] for socket in sockets}
    for index, row in enumerate(rows):
        streams = _object(row, f"interval[{index}]").get("streams")
        if not isinstance(streams, list):
            raise EvidenceError(f"interval[{index}].streams: expected list")
        seen = set()
        for raw in streams:
            raw = _object(raw, f"interval[{index}].stream")
            socket = integer(raw.get("socket"), "interval.socket")
            if socket in seen or socket not in expected:
                raise EvidenceError(f"interval[{index}]: duplicate or unknown socket {socket}")
            seen.add(socket)
            if raw.get("sender") is not True:
                raise EvidenceError(f"socket {socket}: sender-side evidence missing")
            omitted = raw.get("omitted")
            if type(omitted) is not bool:
                raise EvidenceError(f"socket {socket}: omitted must be boolean")
            start = _number(raw.get("start"), "interval.start")
            end = _number(raw.get("end"), "interval.end")
            count = _bytes(raw.get("bytes"), "interval.bytes")
            if end <= start:
                raise EvidenceError(f"socket {socket}: non-positive interval duration")
            if omitted:
                if samples[socket]:
                    raise EvidenceError(f"socket {socket}: omit after measurement began")
                continue
            previous = samples[socket]
            if previous:
                delta = start - previous[-1]["end"]
                if (start <= previous[-1]["start"] or end <= previous[-1]["end"]
                        or abs(delta) > CONTINUITY_TOLERANCE):
                    raise EvidenceError(f"socket {socket}: gap, overlap or unordered intervals")
            previous.append({"start": start, "end": end, "bytes": count})
        if seen != expected:
            raise EvidenceError(f"interval[{index}]: missing stream coverage")

    # End-of-test sender summaries anchor the measurement tail and byte totals.
    # Merely continuous intervals cannot prove that the first/last row exists.
    summaries = _object(doc.get("end"), "end").get("streams")
    if not isinstance(summaries, list):
        raise EvidenceError("end.streams: required for coverage validation")
    seen = set()
    for entry in summaries:
        sender = _object(_object(entry, "end.stream").get("sender"), "end.sender")
        socket = integer(sender.get("socket"), "end.sender.socket")
        if socket in seen or socket not in expected:
            raise EvidenceError("end.streams: duplicate or unknown socket")
        seen.add(socket)
        if sender.get("sender") is not True:
            raise EvidenceError("end.sender: sender-side evidence missing")
        start = _number(sender.get("start"), "end.sender.start")
        end = _number(sender.get("end"), "end.sender.end", positive=True)
        count = _bytes(sender.get("bytes"), "end.sender.bytes")
        values = samples[socket]
        if not values:
            raise EvidenceError(f"socket {socket}: no non-omit measurement")
        if (start > EDGE_TOLERANCE or end - start < duration - EDGE_TOLERANCE
                or abs(values[0]["start"] - start) > EDGE_TOLERANCE
                or abs(values[-1]["end"] - end) > CONTINUITY_TOLERANCE):
            raise EvidenceError(f"socket {socket}: incomplete measurement head/tail")
        if sum(value["bytes"] for value in values) != count:
            raise EvidenceError(
                f"socket {socket}: interval/summary byte mismatch "
                f"({sum(value['bytes'] for value in values)} != {count})")
    if seen != expected:
        raise EvidenceError("end.streams: missing socket")
    starts = [values[0]["start"] for values in samples.values()]
    ends = [values[-1]["end"] for values in samples.values()]
    if max(starts) - min(starts) > EDGE_TOLERANCE or max(ends) - min(ends) > EDGE_TOLERANCE:
        raise EvidenceError("streams do not cover a common measurement window")
    return samples


def _flow(socket, values, threshold):
    runs = []
    current = None
    for value in values:
        if value["bytes"] == 0:
            # Count the union of measured zero intervals: exclude tolerated
            # gaps and never double-count tolerated timestamp overlaps.
            if current is None:
                current = {"start": value["start"], "end": value["end"], "seconds": 0.0}
                runs.append(current)
            contribution_start = value["start"] if current["seconds"] == 0 else max(
                value["start"], current["end"])
            current["seconds"] += value["end"] - contribution_start
            current["end"] = value["end"]
        else:
            current = None
    longest = max((run["seconds"] for run in runs), default=0.0)
    measured = math.fsum(value["end"] - value["start"] for value in values)
    count = sum(value["bytes"] for value in values)
    return {
        "socket": socket, "start": values[0]["start"], "end": values[-1]["end"],
        "measured_seconds": measured, "bytes": count,
        "bytes_per_second": _rate(count, measured), "interval_count": len(values),
        "max_zero_seconds": longest, "zero_runs": runs,
        "observed_stall": longest >= threshold,
    }


def _fairness(samples, flows):
    groups = list(samples.values())
    aligned = all(len(values) == len(groups[0]) for values in groups)
    intervals = []
    if aligned:
        for batch in zip(*groups):
            starts = [value["start"] for value in batch]
            ends = [value["end"] for value in batch]
            if (max(starts) >= min(ends)
                    or max(starts) - min(starts) > CONTINUITY_TOLERANCE
                    or max(ends) - min(ends) > CONTINUITY_TOLERANCE):
                aligned = False
                break
            rates = [_rate(value["bytes"], value["end"] - value["start"]) for value in batch]
            intervals.append({"start": max(starts), "end": min(ends), "jain": _jain(rates)})
    return {
        "overall_jain": _jain([flow["bytes_per_second"] for flow in flows]),
        "interval_status": "assessed" if aligned else "not_assessed",
        "interval_reason": None if aligned else "sampling boundaries differ; no interpolation",
        "intervals": intervals if aligned else [],
    }


def analyze_document(doc, stall_seconds=2.0):
    """Return a complete report or not_assessed; never expose partial success."""
    report = _envelope(None)
    try:
        threshold = _number(stall_seconds, "stall_seconds", positive=True)
        report["stall_seconds"] = threshold
        samples = _collect(doc)
        flows = [_flow(socket, values, threshold) for socket, values in samples.items()]
        fairness = _fairness(samples, flows)
        report.update(
            status="observed_stall" if any(flow["observed_stall"] for flow in flows) else "no_observed_stall",
            sampling_side="sender", flows=flows, fairness=fairness,
        )
    except (EvidenceError, OverflowError) as exc:
        report["reasons"] = [str(exc)]
    return report


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise EvidenceError(message)


def main(argv=None):
    report = _envelope(None)
    try:
        parser = _Parser(description=__doc__)
        parser.add_argument("iperf_json", help="UL client iperf JSON (read only)")
        parser.add_argument("--stall-seconds", default=2.0, type=float)
        args = parser.parse_args(argv)
        report = analyze_document(load_document(args.iperf_json), args.stall_seconds)
        report["input"] = args.iperf_json
    except EvidenceError as exc:
        report["reasons"] = [str(exc)]
    print(json.dumps(report, indent=2, allow_nan=False))
    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    sys.exit(main())

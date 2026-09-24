"""Input validation helpers for XTCP uplink stall evidence."""

import json
import math


class EvidenceError(ValueError):
    """Raised for malformed evidence input."""


def _reject_constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def _validate_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"non-finite JSON number: {value}")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_document(path):
    """Read one JSON object from *path* without accepting ambiguous JSON."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
                parse_float=_validate_float,
            )
    except (OSError, TypeError, UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"cannot load evidence document: {exc}") from exc

    if not isinstance(document, dict):
        raise EvidenceError("evidence document root must be a JSON object")
    return document


def finite_number(value, name, positive=False):
    """Return a finite int/float, requiring >0 when *positive* is true."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{name} must be a finite number")
    if isinstance(value, int):
        if positive:
            if value <= 0:
                raise EvidenceError(f"{name} must be > 0")
        elif value < 0:
            raise EvidenceError(f"{name} must be >= 0")
        return value
    if not math.isfinite(value):
        raise EvidenceError(f"{name} must be a finite number")
    if positive:
        if value <= 0:
            raise EvidenceError(f"{name} must be > 0")
    elif value < 0:
        raise EvidenceError(f"{name} must be >= 0")
    return value


def integer(value, name):
    """Return a non-negative integer, rejecting bools and float-like ints."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{name} must be a non-negative integer")
    if value < 0:
        raise EvidenceError(f"{name} must be a non-negative integer")
    return value


def _object_field(value, name):
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} must be an object")
    return value


def _zero_or_false(value, name):
    if value is False or (type(value) is int and value == 0):
        return
    raise EvidenceError(f"{name} must be 0 or false")


def sampling_role(doc):
    """Validate a minimal sampling role and return connected socket ids."""
    if not isinstance(doc, dict):
        raise EvidenceError("evidence document root must be a JSON object")
    start = _object_field(doc.get("start"), "start")
    test_start = _object_field(start.get("test_start"), "start.test_start")

    if test_start.get("protocol") != "TCP":
        raise EvidenceError("start.test_start.protocol must be TCP")
    if "reverse" not in test_start:
        raise EvidenceError("start.test_start.reverse is required")
    _zero_or_false(test_start.get("reverse"), "start.test_start.reverse")
    if "bidir" in test_start:
        _zero_or_false(test_start.get("bidir"), "start.test_start.bidir")

    num_streams = test_start.get("num_streams")
    if isinstance(num_streams, bool) or not isinstance(num_streams, int) or num_streams <= 0:
        raise EvidenceError("start.test_start.num_streams must be a positive integer")

    connected = start.get("connected")
    if not isinstance(connected, list):
        raise EvidenceError("start.connected must be a list")
    if len(connected) != num_streams:
        raise EvidenceError("start.connected length must equal num_streams")

    sockets = []
    for index, connected_member in enumerate(connected):
        name = f"start.connected[{index}]"
        connected_object = _object_field(connected_member, name)
        if "socket" not in connected_object:
            raise EvidenceError(f"{name} must contain 'socket'")
        socket_id = integer(connected_object["socket"], f"{name}.socket")
        if socket_id in sockets:
            raise EvidenceError(f"{name}.socket is duplicated")
        sockets.append(socket_id)
    return sockets

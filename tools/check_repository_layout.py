#!/usr/bin/env python3
"""Enforce repository dependency and public API boundaries."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


SOURCE_SUFFIXES = {".h", ".hpp", ".cpp", ".cc", ".cxx", ".inc"}

GRANDFATHERED_INC_FILES = {
    "ppp/app/client/VEthernetNetworkSwitcherMembers.inc",
    "ppp/app/client/VEthernetNetworkSwitcherPrivateMethods.inc",
    "ppp/app/client/VEthernetNetworkSwitcherProtectedMethods.inc",
    "ppp/app/client/VEthernetNetworkSwitcherPublicMethods.inc",
    "ppp/app/client/VEthernetNetworkSwitcherPublicTypes.inc",
}

MIGRATION_BASELINE = {
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/route/RouteHost.h",
    ): 2,
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/dns/DnsHost.h",
    ): 8,
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/dns/DnsInterceptor.h",
    ): 2,
    (
        "route/DNS public API exposes concrete host",
        "ppp/app/client/dns/DnsUdpRelay.h",
    ): 4,
    (
        "mutable container pointer in public API",
        "ppp/app/client/route/RouteHost.h",
    ): 2,
}

CONCRETE_HOST_PATTERN = re.compile(
    r"\bVEthernet(?:NetworkSwitcher|Exchanger)\b"
)
MUTABLE_CONTAINER_POINTER_PATTERN = re.compile(
    r"\b(?:unordered_(?:map|set)|vector|map|set)\s*<[^;]+>\s*\*"
)
PROTOCOL_REVERSE_INCLUDE_PATTERN = re.compile(
    r"#\s*include\s*[<\"]ppp/app/(?:client|server)/"
)
CLIENT_SERVER_INCLUDE_PATTERN = re.compile(
    r"#\s*include\s*[<\"]ppp/app/server/"
)


@dataclass(frozen=True)
class Candidate:
    path: str
    line_number: int
    rule: str

    def render(self) -> str:
        return f"{self.path}:{self.line_number}: {self.rule}"


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")


def _find_braced_block(
    lines: list[str], pattern: re.Pattern[str]
) -> tuple[int, int] | None:
    start = next(
        (index for index, line in enumerate(lines) if pattern.search(line)),
        None,
    )
    if start is None:
        return None
    brace_depth = 0
    entered = False
    for index in range(start, len(lines)):
        entered |= "{" in lines[index]
        brace_depth += lines[index].count("{") - lines[index].count("}")
        if entered and brace_depth == 0:
            return start, index + 1
    return start, len(lines)


def _collect_candidates(root: Path) -> list[Candidate]:
    candidates: list[Candidate] = []
    ppp_root = root / "ppp"
    ppp_files = (
        sorted(item for item in ppp_root.rglob("*") if item.is_file())
        if ppp_root.exists()
        else []
    )
    for path in ppp_files:
        if path.suffix not in SOURCE_SUFFIXES:
            continue

        relative = path.relative_to(root).as_posix()
        if relative.startswith("ppp/app/client/RouteTableManager"):
            candidates.append(
                Candidate(relative, 1, "legacy RouteTableManager intermediary")
            )
        if path.suffix == ".inc" and relative not in GRANDFATHERED_INC_FILES:
            candidates.append(Candidate(relative, 1, "new .inc declaration fragment"))

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

        if re.fullmatch(
            r"ppp/app/client/route/RouteCoordinator_(?:linux|darwin|win32|mobile)\.cpp",
            relative,
        ):
            first_code_line = next((line.strip() for line in lines if line.strip()), "")
            if first_code_line != "#include <ppp/stdafx.h>":
                candidates.append(
                    Candidate(relative, 1, "platform source must include stdafx first")
                )

        if relative == "ppp/app/client/route/LinuxRoutePlatform.cpp":
            contents = "\n".join(lines)
            if "entry." in contents and "#include <ppp/net/native/rib.h>" not in contents:
                candidates.append(
                    Candidate(
                        relative,
                        1,
                        "Linux route adapter requires complete RouteEntry",
                    )
                )

        if relative == "ppp/app/client/route/DarwinRoutePlatform.cpp":
            route_probe = _find_braced_block(
                lines, re.compile(r"\boperations\.route_exists\s*=")
            )
            if route_probe is not None:
                probe_start, probe_end = route_probe
                block = "\n".join(lines[probe_start:probe_end])
                if "TapDarwin::TryRouteExists(" not in block:
                    candidates.append(
                        Candidate(
                            relative,
                            probe_start + 1,
                            "Darwin system route probe bypasses exact route query",
                        )
                    )

        if relative == "ppp/app/client/route/WindowsRoutePlatform.cpp":
            for line_number, line in enumerate(lines, 1):
                if re.search(
                    r"ppp::vector\s*<\s*ppp::string\s*>\s*\{\s*underlying_gateway\s*\}",
                    line,
                ):
                    candidates.append(
                        Candidate(
                            relative,
                            line_number,
                            "Windows gateway crosses string allocator boundary",
                        )
                    )

            add_start = next(
                (
                    index
                    for index, line in enumerate(lines)
                    if re.search(r"\boperations\.add\s*=", line)
                ),
                None,
            )
            if add_start is not None:
                brace_depth = 0
                entered_add = False
                for index in range(add_start, len(lines)):
                    entered_add |= "{" in lines[index]
                    brace_depth += lines[index].count("{") - lines[index].count("}")
                    if (
                        entered_add
                        and not _is_comment_line(lines[index])
                        and re.search(r"\bRouter::(?:GetBestRoute|Delete)\s*\(", lines[index])
                    ):
                        candidates.append(
                            Candidate(
                                relative,
                                index + 1,
                                "Windows route Add mutates pre-existing route",
                            )
                        )
                    if entered_add and brace_depth == 0:
                        break

        if relative == "ppp/app/client/VEthernetNetworkSwitcher.cpp":
            route_add_lines = [
                index
                for index, line in enumerate(lines)
                if "route_coordinator_->AddRoute(" in line
            ]
            for index in route_add_lines:
                if re.fullmatch(
                    r"\s*route_coordinator_->AddRoute\([^;]*\);\s*",
                    lines[index],
                ):
                    candidates.append(
                        Candidate(
                            relative,
                            index + 1,
                            "switcher ignores route transaction result",
                        )
                    )
            policy_line = next(
                (
                    index
                    for index, line in enumerate(lines)
                    if "UsePaperAirplaneController(" in line
                ),
                None,
            )
            if route_add_lines and policy_line is not None and policy_line < route_add_lines[0]:
                candidates.append(
                    Candidate(
                        relative,
                        policy_line + 1,
                        "host policy precedes route transaction",
                    )
                )

            method_start = next(
                (
                    index
                    for index, line in enumerate(lines)
                    if re.search(r"\bVEthernetNetworkSwitcher::DeleteRoute\s*\(", line)
                ),
                None,
            )
            if method_start is not None:
                brace_depth = 0
                entered_method = False
                method_end = len(lines)
                for index in range(method_start, len(lines)):
                    entered_method |= "{" in lines[index]
                    brace_depth += lines[index].count("{") - lines[index].count("}")
                    if entered_method and brace_depth == 0:
                        method_end = index + 1
                        break
                method_lines = lines[method_start:method_end]
                clear_line = next(
                    (
                        index
                        for index, line in enumerate(method_lines)
                        if re.search(r"\bClearPeerPrefixRoutes\s*\(", line)
                    ),
                    None,
                )
                stop_line = next(
                    (
                        index
                        for index, line in enumerate(method_lines)
                        if re.search(r"\broute_coordinator_->DeleteRoute\s*\(", line)
                    ),
                    None,
                )
                if clear_line is not None and stop_line is not None and clear_line < stop_line:
                    candidates.append(
                        Candidate(
                            relative,
                            method_start + clear_line + 1,
                            "peer route teardown bypasses coordinator undo",
                        )
                    )

        for line_number, line in enumerate(lines, 1):
            if "RouteTableManager" in line and not _is_comment_line(line):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "legacy RouteTableManager intermediary",
                    )
                )

            if relative.startswith("ppp/app/protocol/") and PROTOCOL_REVERSE_INCLUDE_PATTERN.search(line):
                candidates.append(Candidate(relative, line_number, "protocol -> client/server"))

            if relative.startswith("ppp/app/client/") and CLIENT_SERVER_INCLUDE_PATTERN.search(line):
                candidates.append(Candidate(relative, line_number, "client -> server"))

            if (
                relative == "ppp/app/client/route/RouteCoordinator_linux.cpp"
                and "RouteHostPorts" in line
            ):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "Linux route manager bypasses RouteState",
                    )
                )

            if (
                relative.startswith("ppp/app/client/route/")
                and "owner_" in line
                and not _is_comment_line(line)
            ):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "route coordinator retains concrete host owner",
                    )
                )

            if "RouteHostPorts" in line:
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "legacy RouteHostPorts service locator",
                    )
                )

            if any(token in line for token in ("DnsHostPorts", "IDnsHost", "dns_host_ports_cache_")):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "legacy DNS host service locator",
                    )
                )

            is_route_or_dns_header = (
                path.suffix in {".h", ".hpp"}
                and (
                    relative.startswith("ppp/app/client/route/")
                    or relative.startswith("ppp/app/client/dns/")
                )
            )
            if not is_route_or_dns_header or _is_comment_line(line):
                continue

            if CONCRETE_HOST_PATTERN.search(line):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "route/DNS public API exposes concrete host",
                    )
                )
            if (
                relative.startswith("ppp/app/client/route/")
                and re.search(r"\b_?P?MIB_IPFORWARD_?(?:TABLE|ROW)2?\b", line)
            ):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "route public API exposes Windows MIB type",
                    )
                )
            if MUTABLE_CONTAINER_POINTER_PATTERN.search(line):
                candidates.append(
                    Candidate(
                        relative,
                        line_number,
                        "mutable container pointer in public API",
                    )
                )

    tap_linux = root / "linux/ppp/tap/TapLinux.cpp"
    if tap_linux.exists():
        lines = tap_linux.read_text(encoding="utf-8", errors="replace").splitlines()
        method = _find_braced_block(
            lines, re.compile(r"\bTapLinux::AddRouteStatus\s*\(")
        )
        if method is not None:
            method_start, method_end = method
            eexist = _find_braced_block(
                lines[method_start:method_end], re.compile(r"\bEEXIST\b")
            )
            if eexist is not None:
                eexist_start, eexist_end = eexist
                block = "\n".join(
                    lines[
                        method_start + eexist_start :
                        method_start + eexist_end
                    ]
                )
                if (
                    "TryRouteExists(" not in block
                    or "ClassifyRouteAddResult(" not in block
                    or re.search(
                        r"return\s+RouteMutationResult::Unchanged\s*;", block
                    )
                ):
                    candidates.append(
                        Candidate(
                            "linux/ppp/tap/TapLinux.cpp",
                            method_start + eexist_start + 1,
                            "Linux route EEXIST bypasses exact production classifier",
                        )
                    )

    tap_darwin = root / "darwin/ppp/tap/TapDarwin.cpp"
    if tap_darwin.exists():
        lines = tap_darwin.read_text(encoding="utf-8", errors="replace").splitlines()
        method = _find_braced_block(
            lines, re.compile(r"\bTapDarwin::TryRouteExists\s*\(")
        )
        if method is not None:
            method_start, method_end = method
            block = "\n".join(lines[method_start:method_end])
            if (
                "FetchAllRouteNtreeStuff(" not in block
                or "IsExactRoute(" not in block
                or "TryFindAllDefaultGatewayRoutes(" in block
            ):
                candidates.append(
                    Candidate(
                        "darwin/ppp/tap/TapDarwin.cpp",
                        method_start + 1,
                        "Darwin route query bypasses all-route production identity",
                    )
                )

    return candidates


def check_repository(root: Path) -> list[str]:
    grouped: dict[tuple[str, str], list[Candidate]] = defaultdict(list)
    for candidate in _collect_candidates(root):
        grouped[(candidate.rule, candidate.path)].append(candidate)

    violations: list[str] = []
    for key, candidates in sorted(grouped.items()):
        allowed = MIGRATION_BASELINE.get(key, 0)
        violations.extend(candidate.render() for candidate in candidates[allowed:])
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    violations = check_repository(root)
    if violations:
        print("Repository layout violations:")
        for violation in violations:
            print(violation)
        return 1
    print("PASS: repository layout boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

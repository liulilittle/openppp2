#!/usr/bin/env bash
# Fixed entry point for the strict Linux native/XTCP datapath acceptance run.
# It deliberately accepts no external execution adapter.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
project_root="$(cd "${script_dir}/.." && pwd -P)"
acceptance_tool="${script_dir}/datapath_acceptance.py"
strict_adapter="${script_dir}/datapath_linux_strict_adapter.py"

usage() {
    cat <<'EOF'
Usage:
  tools/run_datapath_linux_acceptance.sh plan
  tools/run_datapath_linux_acceptance.sh prepare [acceptance prepare options]
  tools/run_datapath_linux_acceptance.sh seal [acceptance seal options]
  tools/run_datapath_linux_acceptance.sh verify [acceptance verify options]
  tools/run_datapath_linux_acceptance.sh freeze [acceptance freeze options]
  tools/run_datapath_linux_acceptance.sh run \
      --artifacts PATH --candidate PATH \
      [--source-root PATH] [--threshold DECIMAL] \
      [--network-profile PROFILE --netem-seed INTEGER]

Commands:
  plan, prepare, seal, verify, freeze
      Pass through to tools/datapath_acceptance.py.  Preparation and freezing
      require fresh artifact roots; verification is fail-closed.

  run
      Creates a fresh root, invokes only the in-tree strict Linux adapter under
      env -i, then seals and verifies only after that adapter succeeds.  It
      requires root plus the Linux tools and queue controls checked by the
      adapter.  The candidate must be an explicit external executable.
EOF
}

die() {
    printf 'datapath acceptance wrapper: %s\n' "$*" >&2
    exit 2
}

require_value() {
    local option="$1"
    local value="${2:-}"
    [[ -n "${value}" ]] || die "${option} requires a value"
}

run_acceptance() {
    local artifacts=""
    local candidate=""
    local source_root="${project_root}"
    local threshold=""
    local network_profile=""
    local netem_seed=""

    while (($#)); do
        case "$1" in
            --artifacts)
                require_value "$1" "${2:-}"
                artifacts="$2"
                shift 2
                ;;
            --candidate)
                require_value "$1" "${2:-}"
                candidate="$2"
                shift 2
                ;;
            --source-root)
                require_value "$1" "${2:-}"
                source_root="$2"
                shift 2
                ;;
            --threshold)
                require_value "$1" "${2:-}"
                threshold="$2"
                shift 2
                ;;
            --network-profile)
                require_value "$1" "${2:-}"
                network_profile="$2"
                shift 2
                ;;
            --netem-seed)
                require_value "$1" "${2:-}"
                netem_seed="$2"
                shift 2
                ;;
            --adapter)
                die "run does not permit --adapter; the strict in-tree adapter is fixed"
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                die "unknown run option: $1"
                ;;
        esac
    done

    [[ -n "${artifacts}" ]] || die "run requires --artifacts"
    [[ -n "${candidate}" ]] || die "run requires --candidate"
    if [[ -n "${network_profile}" && -z "${netem_seed}" ]] || [[ -z "${network_profile}" && -n "${netem_seed}" ]]; then
        die "--network-profile and --netem-seed must be specified together"
    fi
    [[ "$(id -u)" -eq 0 ]] || die "run requires root for Linux namespace setup"
    [[ -f "${strict_adapter}" ]] || die "fixed strict adapter is unavailable: ${strict_adapter}"

    local artifacts_absolute
    artifacts_absolute="$(python3 -B - "${artifacts}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1]).expanduser()
try:
    metadata = path.lstat()
except FileNotFoundError:
    pass
except OSError as error:
    raise SystemExit(f"cannot stat artifact root {path}: {error}")
else:
    if path.is_symlink():
        raise SystemExit(f"artifact root must not be a symlink: {path}")
print(path.resolve(strict=False))
PY
)"

    local prepare_arguments=(
        prepare
        --artifacts "${artifacts_absolute}"
        --source-root "${source_root}"
        --candidate "${candidate}"
    )
    if [[ -n "${threshold}" ]]; then
        prepare_arguments+=(--threshold "${threshold}")
    fi
    if [[ -n "${network_profile}" ]]; then
        prepare_arguments+=(--network-profile "${network_profile}" --netem-seed "${netem_seed}")
    fi
    python3 -B "${acceptance_tool}" "${prepare_arguments[@]}"

    local manifest="${artifacts_absolute}/acceptance-manifest.json"
    local candidate_absolute
    candidate_absolute="$(python3 -B - "${manifest}" <<'PY'
import json
import sys
from pathlib import Path

with Path(sys.argv[1]).open(encoding="utf-8") as handle:
    candidate = json.load(handle)["candidate"]["path"]
if not isinstance(candidate, str) or not Path(candidate).is_absolute():
    raise SystemExit("prepared manifest has no absolute candidate path")
print(candidate)
PY
)"

    env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        LC_ALL=C \
        LANG=C \
        python3 -B "${strict_adapter}" \
        --artifacts "${artifacts_absolute}" \
        --manifest "${manifest}" \
        --candidate "${candidate_absolute}"

    python3 -B "${acceptance_tool}" seal --artifacts "${artifacts_absolute}"
    python3 -B "${acceptance_tool}" verify --artifacts "${artifacts_absolute}"
}

main() {
    local command="${1:-}"
    case "${command}" in
        plan|prepare|seal|verify|freeze)
            shift
            exec python3 -B "${acceptance_tool}" "${command}" "$@"
            ;;
        run)
            shift
            run_acceptance "$@"
            ;;
        --adapter)
            die "external adapters are not supported"
            ;;
        --help|-h|help)
            usage
            ;;
        "")
            usage >&2
            exit 2
            ;;
        *)
            die "unknown command: ${command}"
            ;;
    esac
}

main "$@"

#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  netem.sh profiles
  netem.sh validate-interface INTERFACE
  netem.sh apply INTERFACE PROFILE
  netem.sh clear INTERFACE
  netem.sh run INTERFACE PROFILE -- COMMAND [ARG ...]

Profiles:
  carrier-delay  delay 40ms 0ms rate 100mbit
  carrier-loss   loss random 2% 0% rate 100mbit seed 71214
  carrier-loss-0.5  loss random 0.5% 0% rate 100mbit seed 51503
  carrier-loss-5    loss random 5% 0% rate 100mbit seed 90512
EOF
}

validate_interface() {
    local interface="${1:-}"
    if [[ -z "$interface" || "$interface" == "lo" || "$interface" == -* || ! "$interface" =~ ^[a-zA-Z0-9_.:-]+$ ]]; then
        echo "unsafe or empty interface: '$interface'" >&2
        return 2
    fi
}

profile_args() {
    case "${1:-}" in
        carrier-delay) printf '%s\n' delay 40ms 0ms rate 100mbit ;;
        carrier-loss) printf '%s\n' loss random 2% 0% rate 100mbit seed 71214 ;;
        carrier-loss-0.5) printf '%s\n' loss random 0.5% 0% rate 100mbit seed 51503 ;;
        carrier-loss-5) printf '%s\n' loss random 5% 0% rate 100mbit seed 90512 ;;
        *) echo "unknown netem profile: '${1:-}'" >&2; return 2 ;;
    esac
}

require_netem() {
    local interface="$1"
    if (( EUID != 0 )); then
        echo "netem mutation requires root" >&2
        return 1
    fi
    command -v ip >/dev/null || { echo "netem requires ip" >&2; return 1; }
    command -v tc >/dev/null || { echo "netem requires tc" >&2; return 1; }
    ip link show dev "$interface" >/dev/null 2>&1 || {
        echo "interface does not exist: '$interface'" >&2
        return 1
    }
}

apply_profile() {
    local interface="$1" profile="$2"
    local -a args
    validate_interface "$interface"
    require_netem "$interface"
    mapfile -t args < <(profile_args "$profile")
    tc qdisc replace dev "$interface" root netem "${args[@]}"
}

clear_profile() {
    local interface="$1"
    validate_interface "$interface"
    require_netem "$interface"
    tc qdisc del dev "$interface" root 2>/dev/null || true
}

command="${1:-}"
case "$command" in
    profiles)
        printf '%s\n' \
            'carrier-delay: delay 40ms 0ms rate 100mbit' \
            'carrier-loss: loss random 2% 0% rate 100mbit seed 71214' \
            'carrier-loss-0.5: loss random 0.5% 0% rate 100mbit seed 51503' \
            'carrier-loss-5: loss random 5% 0% rate 100mbit seed 90512'
        ;;
    validate-interface)
        validate_interface "${2:-}"
        ;;
    apply)
        [[ $# -eq 3 ]] || { usage >&2; exit 2; }
        apply_profile "$2" "$3"
        ;;
    clear)
        [[ $# -eq 2 ]] || { usage >&2; exit 2; }
        clear_profile "$2"
        ;;
    run)
        [[ $# -ge 5 && "$4" == "--" ]] || { usage >&2; exit 2; }
        interface="$2"
        profile="$3"
        shift 4
        cleaned=0
        cleanup() {
            if (( cleaned == 0 )); then
                cleaned=1
                clear_profile "$interface"
            fi
        }
        trap cleanup EXIT
        trap 'exit 130' INT TERM HUP
        apply_profile "$interface" "$profile"
        "$@"
        ;;
    -h|--help|help|'')
        usage
        ;;
    *)
        echo "unknown command: '$command'" >&2
        usage >&2
        exit 2
        ;;
esac

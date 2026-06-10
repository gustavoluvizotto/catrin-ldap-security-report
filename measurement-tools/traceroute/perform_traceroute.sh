#!/bin/bash

# Wrapper around the traceroute binary.
# example: ./perform_traceroute.sh 1.1.1.1 icmp

set -euo pipefail

# --- Configuration ---
# Maximum number of hops (TTL) to probe.
MAX_HOPS=30
# Number of probe packets per hop.
PROBES_PER_HOP=3
# Per-probe wait time in seconds.
WAIT_TIME=2
# --- End Configuration ---


# --- Argument Validation ---
if [[ -z "${1:-}" ]]; then
  echo "Error: No target specified." >&2
  echo "Usage: $0 <target> [protocol]" >&2
  echo "       protocol can be 'icmp', 'tcp', or 'udp'. Default is 'icmp'." >&2
  exit 1
fi

TARGET="$1"
PROTOCOL="${2:-icmp}"

# Reject anything that is not a plausible hostname / IP address. This guards
# against shell metacharacters being smuggled in via the target argument.
if ! [[ "$TARGET" =~ ^[A-Za-z0-9._:-]+$ ]] || [[ "$TARGET" == -* ]]; then
  echo "Error: Invalid target '$TARGET'." >&2
  exit 1
fi

# Map the requested protocol to traceroute flags and validate it. The flag
# spelling differs between the Linux (iproute2) and BSD/macOS traceroute, so
# pick the right one based on the OS.
PROTOCOL_FLAG=()
case "$(uname -s)" in
    Linux)
        case "$PROTOCOL" in
            icmp) PROTOCOL_FLAG=(-I) ;;
            tcp)  PROTOCOL_FLAG=(-T) ;;
            udp)  PROTOCOL_FLAG=(-U) ;;
            *)    PROTOCOL_FLAG=("invalid") ;;
        esac
        ;;
    *)  # Darwin / BSD
        case "$PROTOCOL" in
            icmp) PROTOCOL_FLAG=(-I) ;;
            tcp)  PROTOCOL_FLAG=(-P tcp) ;;
            udp)  PROTOCOL_FLAG=(-P udp) ;;
            *)    PROTOCOL_FLAG=("invalid") ;;
        esac
        ;;
esac

if [[ "${PROTOCOL_FLAG[0]}" == "invalid" ]]; then
    echo "Error: Invalid protocol '$PROTOCOL'." >&2
    echo "Please use 'icmp', 'tcp', or 'udp'." >&2
    exit 1
fi


# --- Main Execution ---
echo "Running traceroute for target: $TARGET using protocol: $PROTOCOL" >&2

exec sudo -u catrinsoc traceroute \
    "${PROTOCOL_FLAG[@]}" \
    -m "$MAX_HOPS" \
    -q "$PROBES_PER_HOP" \
    -w "$WAIT_TIME" \
    "$TARGET"

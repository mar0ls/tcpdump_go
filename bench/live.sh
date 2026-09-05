#!/usr/bin/env bash
# bench/live.sh — tcpdump vs tcpdump_go on a live interface.
#
# Sequential and interleaved: one tool runs, then the other, then back again,
# for the requested number of rounds. Live traffic drifts, so alternating and
# taking medians is the only way a live comparison means anything. Running both
# at once — as the old bench_sniff.sh did — measures contention instead.
#
# Usage: sudo bench/live.sh <interface> [seconds] [rounds]
#
# For a result that is reproducible rather than merely observed, drive the link
# yourself and say so:
#   BENCH_LOAD_CMD='iperf3 -c 10.0.0.2 -t 60' sudo -E bench/live.sh en0 10 5

set -euo pipefail
cd "$(dirname "$0")/.."
source bench/lib.sh

IFACE="${1:-}"
DURATION="${2:-10}"
ROUNDS="${3:-5}"
BINARY="./tcpdump_go"
LOAD_CMD="${BENCH_LOAD_CMD:-}"

if [[ -z "$IFACE" ]]; then
    echo "usage: sudo $0 <interface> [seconds] [rounds]" >&2
    exit 1
fi
require_tools tcpdump go awk

WORK=$(mktemp -d)
LOAD_PID=""
cleanup() {
    if [[ -n "$LOAD_PID" ]]; then kill "$LOAD_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "Building $BINARY..."
go build -o "$BINARY" .

cat <<EOF

════════════════════════════════════════════════════════════════
 Interface   : $IFACE
 Window      : ${DURATION}s per run, timed from "listening"
 Rounds      : $ROUNDS (tcpdump and tcpdump_go alternate, never parallel)
 Load        : ${LOAD_CMD:-ambient traffic only}
 tcpdump     : $(tcpdump --version 2>&1 | head -1)
════════════════════════════════════════════════════════════════
EOF

if [[ -z "$LOAD_CMD" ]]; then
    cat <<'EOF'

 WARNING: without BENCH_LOAD_CMD this measures whatever happened to cross the
 link during each window. Treat the numbers as indicative, not reproducible,
 and never quote a percentage from them.
EOF
else
    # shellcheck disable=SC2086
    $LOAD_CMD >/dev/null 2>&1 &
    LOAD_PID=$!
    sleep 1
fi

declare -a TD_PKTS TD_DROP TD_CPU GO_PKTS GO_DROP GO_CPU
TD_RSS=0
GO_RSS=0

# one_run <label> <ready-regex> <stderr-file> <cmd...>
one_run() {
    local label="$1" ready="$2" err="$3"; shift 3
    read -r real user sys rss <<<"$(bench_run_windowed "$err" "$ready" "$DURATION" "$@")"
    local pkts drops cpu
    pkts=$(captured_packets "$err"); pkts=${pkts:-0}
    drops=$(kernel_drops "$err");   drops=${drops:-0}
    cpu=$(awk -v u="$user" -v s="$sys" 'BEGIN{printf "%.2f", u+s}')
    printf "   %-11s %10s pkts  %8s dropped  %6ss cpu\n" "$label" "$pkts" "$drops" "$cpu" >&2
    echo "$pkts $drops $cpu $rss"
}

echo
for round in $(seq "$ROUNDS"); do
    echo " round $round/$ROUNDS"

    read -r p d c r <<<"$(one_run tcpdump 'listening on' "$WORK/td.err" \
        tcpdump -i "$IFACE" -n -w /dev/null)"
    TD_PKTS+=("$p"); TD_DROP+=("$d"); TD_CPU+=("$c")
    if [[ "$r" -gt "$TD_RSS" ]]; then TD_RSS=$r; fi

    read -r p d c r <<<"$(one_run tcpdump_go 'Capturing on' "$WORK/go.err" \
        "$BINARY" -i "$IFACE" -n -w /dev/null)"
    GO_PKTS+=("$p"); GO_DROP+=("$d"); GO_CPU+=("$c")
    if [[ "$r" -gt "$GO_RSS" ]]; then GO_RSS=$r; fi
done

TD_P=$(median "${TD_PKTS[@]}"); TD_D=$(median "${TD_DROP[@]}"); TD_C=$(median "${TD_CPU[@]}")
GO_P=$(median "${GO_PKTS[@]}"); GO_D=$(median "${GO_DROP[@]}"); GO_C=$(median "${GO_CPU[@]}")

cat <<EOF

════════════════════════════════════════════════════════════════
 MEDIAN OVER $ROUNDS ROUNDS (${DURATION}s each, -w /dev/null)
────────────────────────────────────────────────────────────────
EOF
printf " %-22s %14s %14s\n" "metric" "tcpdump" "tcpdump_go"
printf " %-22s %14s %14s\n" "packets captured" "$TD_P" "$GO_P"
printf " %-22s %14s %14s\n" "packets/s" "$(rate "$TD_P" "$DURATION")" "$(rate "$GO_P" "$DURATION")"
printf " %-22s %14s %14s\n" "dropped by kernel" "$TD_D" "$GO_D"
printf " %-22s %14s %14s\n" "cpu seconds" "$TD_C" "$GO_C"
printf " %-22s %14s %14s\n" "max RSS (MiB)" "$((TD_RSS / 1024))" "$((GO_RSS / 1024))"
echo "════════════════════════════════════════════════════════════════"

cat <<'EOF'

 How to read this: on a link neither tool saturates, both capture everything
 and only the CPU and RSS columns say anything. A throughput claim needs
 "dropped by kernel" to be non-zero for at least one of them — that is the
 point where a tool stops keeping up.
EOF

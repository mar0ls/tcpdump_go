#!/usr/bin/env bash
# bench/offline.sh — tcpdump vs tcpdump_go on one identical capture file.
#
# Deterministic: both tools see exactly the same packets, so the only variable
# left is the work each does per packet. Needs no root and no live interface.
#
# Usage: bench/offline.sh <capture.pcap> [repetitions]
#
# Make a capture worth measuring first, e.g.
#   sudo tcpdump -i en0 -c 500000 -w /tmp/bench.pcap

set -euo pipefail
cd "$(dirname "$0")/.."
source bench/lib.sh

PCAP="${1:-}"
REPS="${2:-5}"
BINARY="./tcpdump_go"

if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
    echo "usage: $0 <capture.pcap> [repetitions]" >&2
    exit 1
fi
require_tools tcpdump go awk

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export TOOL_ERR="$WORK/tool.err"

echo "Building $BINARY..."
go build -o "$BINARY" .

# Warm the page cache so the first repetition does not pay for disk reads that
# the later ones get for free.
cat "$PCAP" >/dev/null
cat "$PCAP" >/dev/null

PACKETS=$("$BINARY" -r "$PCAP" --count 2>/dev/null | grep -oE '^[0-9]+' || echo 0)
SIZE=$(wc -c <"$PCAP" | tr -d ' ')

cat <<EOF

════════════════════════════════════════════════════════════════
 Capture     : $PCAP
 Packets     : $PACKETS   ($((SIZE / 1024 / 1024)) MiB)
 Repetitions : $REPS (sequential, never in parallel)
 tcpdump     : $(tcpdump --version 2>&1 | head -1)
════════════════════════════════════════════════════════════════
EOF

# ── is this capture fit to benchmark with? ─────────────────────────────────────
# tcpdump keeps per-flow state to print relative sequence numbers, and an
# address cache keyed by a fixed number of buckets. A capture where almost
# every packet belongs to its own flow — which is what naive synthetic traffic
# looks like — degrades both, and tcpdump then measures its own hash tables
# rather than its packet handling. Measured here on such a file: tcpdump -n
# took 2.9s where -nS, which needs no flow table, took 1.1s.
echo
echo "Checking the capture is representative..."
"$BINARY" -r "$PCAP" --csv "$WORK/flows.csv" --count >/dev/null 2>&1 || true
if [[ -s "$WORK/flows.csv" ]]; then
    FLOWS=$(( $(wc -l <"$WORK/flows.csv") - 1 ))
    DENSITY=$(awk -v f="$FLOWS" -v p="$PACKETS" 'BEGIN{ if (p>0) printf "%.0f", 100*f/p; else print 0 }')
    echo "  $FLOWS distinct flows in $PACKETS packets (${DENSITY}%)"
    if [[ "$DENSITY" -gt 20 ]]; then
        cat <<'EOF'
  WARNING: nearly every packet starts its own flow. Real captures do not look
  like this, and tcpdump's per-flow state degrades badly on such a file. Any
  advantage this benchmark shows for tcpdump_go in print mode is an artifact.
  Use a real capture instead.
EOF
    fi
fi

# ── correctness gate ───────────────────────────────────────────────────────────
# A speed comparison is meaningless if the two tools do not write the same
# packets, so check that before timing anything.
echo
echo "Checking output parity..."
tcpdump -r "$PCAP" -w "$WORK/td.pcap" 2>/dev/null
"$BINARY" -r "$PCAP" -w "$WORK/go.pcap" 2>/dev/null
TD_PKTS=$("$BINARY" -r "$WORK/td.pcap" --count 2>/dev/null | grep -oE '^[0-9]+' || echo 0)
GO_PKTS=$("$BINARY" -r "$WORK/go.pcap" --count 2>/dev/null | grep -oE '^[0-9]+' || echo 0)
if [[ "$TD_PKTS" == "$GO_PKTS" ]]; then
    echo "  both wrote $TD_PKTS packets"
else
    echo "  WARNING: tcpdump wrote $TD_PKTS packets, $BINARY wrote $GO_PKTS — timings below are not comparable"
fi
rm -f "$WORK/td.pcap" "$WORK/go.pcap"

# ── one scenario, one tool, REPS repetitions ───────────────────────────────────
measure() {
    local label="$1"; shift
    local reals=() cpus=() rssmax=0
    for _ in $(seq "$REPS"); do
        read -r real user sys rss <<<"$(bench_run "$TOOL_ERR" "$@")"
        reals+=("$real")
        cpus+=("$(awk -v u="$user" -v s="$sys" 'BEGIN{printf "%.2f", u+s}')")
        if [[ "$rss" -gt "$rssmax" ]]; then rssmax=$rss; fi
    done
    local mr mc
    mr=$(median "${reals[@]}")
    mc=$(median "${cpus[@]}")
    printf " %-14s %9s s %9s s %9s %12s\n" \
        "$label" "$mr" "$mc" "$((rssmax / 1024)) MiB" "$(rate "$PACKETS" "$mr")"
    echo "$mr" >"$WORK/last_real"
}

scenario() {
    local title="$1" td_desc="$2" go_desc="$3"; shift 3
    echo
    echo "──────────────────────────────────────────────────────────────"
    echo " $title"
    echo "──────────────────────────────────────────────────────────────"
    printf " %-14s %11s %11s %9s %12s\n" "tool" "real (med)" "cpu (med)" "max RSS" "packets/s"
    # shellcheck disable=SC2086 # descriptions are deliberately word-split
    measure tcpdump tcpdump $td_desc
    local td_real; td_real=$(cat "$WORK/last_real")
    # shellcheck disable=SC2086
    measure tcpdump_go "$BINARY" $go_desc
    local go_real; go_real=$(cat "$WORK/last_real")
    awk -v a="$td_real" -v b="$go_real" 'BEGIN{
        if (a <= 0 || b <= 0) { print "\n ratio: n/a"; exit }
        if (b < a) printf "\n tcpdump_go is %.2fx faster than tcpdump here\n", a/b;
        else       printf "\n tcpdump_go is %.2fx slower than tcpdump here\n", b/a;
    }'
}

scenario "Write only (-w): no decoding asked for" \
    "-r $PCAP -w /dev/null" \
    "-r $PCAP -w /dev/null"

scenario "Print summaries (-n): full per-packet decoding" \
    "-n -r $PCAP" \
    "-n -r $PCAP"

cat <<'EOF'

Reading the result:
  * 'packets/s' is throughput over the median wall-clock time. Wall and CPU
    time differ for tcpdump_go because the Go runtime uses more than one
    thread; both are printed so neither number flatters it.
  * A ratio near 1.00x means the two are indistinguishable at this sample size.
    Do not quote a percentage from a single capture on a single machine.
EOF

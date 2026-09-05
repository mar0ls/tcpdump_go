#!/usr/bin/env bash
# Shared measurement helpers for the tcpdump / tcpdump_go comparisons.
#
# The rule the old benchmark broke: never run the two tools at the same time.
# They compete for CPU, for the capture buffer and for the disk, so a parallel
# run measures the scheduler, not the programs.

set -euo pipefail

# GNU time and BSD time disagree on both flags and units: %M is KiB, -l is bytes.
if /usr/bin/time -f '%e' true >/dev/null 2>&1; then
    TIME_FLAVOR=gnu
else
    TIME_FLAVOR=bsd
fi

# _time_wrap <bash-script> <args...> -> "real user sys maxrss_kb"
# The script runs with "$@" bound to args. time(1)'s own output is kept in a
# separate file so a tool's stderr stays parseable.
_time_wrap() {
    local script="$1"; shift
    local time_log
    time_log=$(mktemp)
    if [[ "$TIME_FLAVOR" == gnu ]]; then
        /usr/bin/time -f '%e %U %S %M' bash -c "$script" _ "$@" >/dev/null 2>"$time_log" || true
        tail -1 "$time_log"
    else
        /usr/bin/time -l bash -c "$script" _ "$@" >/dev/null 2>"$time_log" || true
        awk '/ real /{r=$1; u=$3; s=$5}
             /maximum resident/{m=$1}
             END{printf "%s %s %s %d\n", r, u, s, m/1024}' "$time_log"
    fi
    rm -f "$time_log"
}

# bench_run <tool-stderr-file> <cmd...> — run to completion.
bench_run() {
    export TOOL_ERR="$1"; shift
    _time_wrap '"$@" 2> "$TOOL_ERR"' "$@"
}

# bench_run_windowed <tool-stderr-file> <ready-regex> <seconds> <cmd...>
# Starts the tool, waits until it says it is listening, and only then opens the
# capture window. That is what the old script's hardcoded 400 ms head start was
# guessing at, and it removes the guess: both tools get the same window,
# measured from the moment each is actually capturing.
bench_run_windowed() {
    export TOOL_ERR="$1" READY_RE="$2" WINDOW="$3"; shift 3
    # Job control matters here: without it a background job started from a
    # non-interactive shell inherits SIGINT ignored, and the tool would never
    # see the Ctrl+C that makes it print its closing counters.
    _time_wrap '
        set -m
        "$@" 2> "$TOOL_ERR" &
        pid=$!
        set +m
        for _ in $(seq 400); do
            grep -qE "$READY_RE" "$TOOL_ERR" 2>/dev/null && break
            sleep 0.05
        done
        sleep "$WINDOW"
        kill -INT "$pid" 2>/dev/null || true
        for _ in $(seq 40); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.05
        done
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    ' "$@"
}

median() {
    printf '%s\n' "$@" | sort -g |
        awk '{v[NR]=$1}
             END{ m = (NR%2) ? v[(NR+1)/2] : (v[NR/2]+v[NR/2+1])/2
                  if (m == int(m)) printf "%d\n", m; else printf "%.2f\n", m }'
}

# Kernel drops as each tool reports them itself. A saved pcap does not carry
# this number, so the old script's attempt to recover it from the file could
# only ever print zero.
kernel_drops() {
    grep -oE '[0-9]+ packets dropped by kernel' "$1" 2>/dev/null | grep -oE '^[0-9]+' | tail -1 || true
}

captured_packets() {
    grep -oE '[0-9]+ packets captured' "$1" 2>/dev/null | grep -oE '^[0-9]+' | tail -1 || true
}

require_tools() {
    local missing=0
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || { echo "missing required tool: $t" >&2; missing=1; }
    done
    [[ $missing -eq 0 ]] || exit 1
}

rate() {
    awk -v n="$1" -v t="$2" 'BEGIN{ if (t+0 <= 0 || n+0 <= 0) print "n/a"; else printf "%.0f", n/t }'
}

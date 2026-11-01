#!/bin/sh
# Per-unit and whole-host egress watch. Installed by egress-watch.service/timer.
#
# D12 fixes in this version:
#   - samples scopes and slices as well as services (systemd-run --scope, user managers,
#     rootless containers create scopes outside the notebook unit);
#   - keeps a delta per unit and flags a counter reset instead of discarding it silently;
#   - compares the sum of unit deltas with the host interface counter, so bytes that no
#     sampled unit accounts for are a finding on their own;
#   - thresholds come from the environment, not from a constant in the source.
#
# What it still cannot see: macvlan/ipvlan/SR-IOV egress (no host counter), forwarded
# traffic with no originating socket, and any unit that exists only between samples
# (that case is the reset warning).
set -u
LC_ALL=C
export LC_ALL

STATE_DIR=${EGRESS_STATE:-/var/lib/egress-watch}
STATE=$STATE_DIR/state
THRESHOLD=${EGRESS_THRESHOLD:-1073741824}     # 1 GiB per interval
HOST_MISMATCH=${EGRESS_MISMATCH:-536870912}   # 512 MiB unattributed
WARN_RESET=${EGRESS_WARN_RESET:-1}

say() {
	if command -v logger >/dev/null 2>&1; then
		logger -t egress-watch -- "$*"
	fi
	printf '%s\n' "$*"
}

mkdir -p "$STATE_DIR" 2>/dev/null || { echo "cannot create $STATE_DIR"; exit 1; }

TMP=$(mktemp "$STATE_DIR/.state.XXXXXX" 2>/dev/null) || exit 1
UNITSTMP=$(mktemp "$STATE_DIR/.units.XXXXXX" 2>/dev/null) || exit 1
trap 'rm -f "$TMP" "$UNITSTMP"' EXIT INT TERM

host_tx() {
	sum=0
	seen=0
	for f in /sys/class/net/*/statistics/tx_bytes; do
		[ -r "$f" ] || continue
		seen=1
		iface=${f#/sys/class/net/}; iface=${iface%%/*}
		[ "$iface" = lo ] && continue
		v=$(cat "$f" 2>/dev/null) || v=0
		sum=$((sum + v))
	done
	if [ "$seen" -eq 0 ] && [ -r /proc/net/dev ]; then
		sum=$(awk -F'[: ]+' 'NR > 2 && $2 != "lo" {s += $11} END {print s + 0}' /proc/net/dev)
	fi
	printf '%s' "$sum"
}

NOW=$(date +%s)
HOST_NOW=$(host_tx)

# One call, all units: blocks of Id= / NRestarts= / IPEgressBytes=.
systemctl show --all --property=Id --property=IPEgressBytes --property=NRestarts 2>/dev/null |
awk '
/^Id=/ { if (id != "") print id "\t" eg "\t" nr; id = substr($0, 4); eg = 0; nr = 0; next }
/^IPEgressBytes=/ { v = substr($0, 15); eg = (v == "" || v == "[not set]") ? 0 : v }
/^NRestarts=/ { nr = substr($0, 11) }
END { if (id != "") print id "\t" eg "\t" nr }
' >"$UNITSTMP" 2>/dev/null

prev_of() {
	[ -f "$STATE" ] || return 1
	awk -v u="$1" -F'\t' '$1 == u {print $2 "\t" $3; found=1} END{if(!found) exit 1}' "$STATE"
}

prev_host=0
[ -f "$STATE" ] && prev_host=$(awk -F'\t' '$1 == "__host__" {print $2}' "$STATE")
[ -n "$prev_host" ] || prev_host=$HOST_NOW

sum_unit_delta=0
resets=0
units=0

while IFS='	' read -r unit eg nr; do
	[ -n "$unit" ] || continue
	units=$((units + 1))
	line=$(prev_of "$unit" 2>/dev/null) || line=''
	if [ -z "$line" ]; then
		printf '%s\t%s\t%s\n' "$unit" "$eg" "$nr" >>"$TMP"
		continue
	fi
	prev_eg=$(printf '%s' "$line" | cut -f1)
	prev_nr=$(printf '%s' "$line" | cut -f2)
	[ -n "$prev_eg" ] || prev_eg=0
	[ -n "$prev_nr" ] || prev_nr=0

	if [ "$eg" -lt "$prev_eg" ] 2>/dev/null; then
		resets=$((resets + 1))
		[ "$WARN_RESET" -eq 1 ] && say "egress-watch: counter reset on $unit ($prev_eg -> $eg); bytes since the reset are not counted"
		delta=0
	else
		delta=$((eg - prev_eg))
	fi
	sum_unit_delta=$((sum_unit_delta + delta))

	if [ "$delta" -ge "$THRESHOLD" ]; then
		say "egress-watch: $unit egress $((delta / 1048576)) MiB in this interval (threshold $((THRESHOLD / 1048576)) MiB)"
	fi
	if [ "$nr" -gt "$prev_nr" ] 2>/dev/null && [ "$WARN_RESET" -eq 1 ]; then
		say "egress-watch: $unit restarted $((nr - prev_nr)) time(s) since the last sample"
	fi

	printf '%s\t%s\t%s\n' "$unit" "$eg" "$nr" >>"$TMP"
done <"$UNITSTMP"

host_delta=$((HOST_NOW - prev_host))
[ "$host_delta" -lt 0 ] && host_delta=0
unattributed=$((host_delta - sum_unit_delta))

if [ "$unattributed" -ge "$HOST_MISMATCH" ]; then
	say "egress-watch: host egress $((host_delta / 1048576)) MiB vs units $((sum_unit_delta / 1048576)) MiB; $((unattributed / 1048576)) MiB is not attributable to a sampled unit"
fi
if [ "$host_delta" -ge "$THRESHOLD" ] && [ "$sum_unit_delta" -lt "$((THRESHOLD / 2))" ]; then
	say "egress-watch: host moved $((host_delta / 1048576)) MiB while sampled units moved $((sum_unit_delta / 1048576)) MiB"
fi

printf '__host__\t%s\t%s\n' "$HOST_NOW" "$NOW" >>"$TMP"

if [ -s "$TMP" ]; then
	mv "$TMP" "$STATE" 2>/dev/null || cp "$TMP" "$STATE"
	chmod 0600 "$STATE" 2>/dev/null
fi

if [ "$resets" -eq 1 ]; then
	say "egress-watch: 1 unit reset its counter; the sum above may under-count"
elif [ "$resets" -gt 1 ]; then
	say "egress-watch: $resets units reset their counters; the sum above may under-count"
fi
[ "$units" -eq 0 ] && say "egress-watch: no units sampled; systemd accounting is unavailable on this host"
exit 0
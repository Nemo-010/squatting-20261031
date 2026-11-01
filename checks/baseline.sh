#!/bin/sh
# Per-workload egress baseline.
#
# D59 asked for a method, not an assertion: "traffic that does not match the unit's
# declared purpose" is only meaningful if the normal range was measured first.
# D12 asked for a whole-host total to compare against.
#
#   baseline.sh record            snapshot now as the baseline
#   baseline.sh report            compare now against the baseline
#   baseline.sh declare UNIT CLASS [GIB_PER_DAY]
#                                 record what a unit is for and what it may move
#
# State lives in $BASELINE_DIR (default /var/lib/egress-baseline).
# A baseline is a measurement, not a control: the squatter's traffic is inside the
# measurement until it changes shape. Re-record after any planned workload change.
set -u
LC_ALL=C
export LC_ALL

DIR=${BASELINE_DIR:-/var/lib/egress-baseline}
BASE=$DIR/baseline
CLASSES=$DIR/classes
FACTOR=${BASELINE_FACTOR:-4}
MIN_BYTES=${BASELINE_MIN:-104857600}

say() { printf '%s\n' "$*"; }
die() { printf 'baseline: %s\n' "$*" >&2; exit 1; }

host_tx_rx() {
	tx=0; rx=0
	if [ -r /proc/net/dev ]; then
		set -- $(awk -F'[: ]+' 'NR > 2 && $2 != "lo" {tx += $11; rx += $3} END {print tx + 0, rx + 0}' /proc/net/dev)
		tx=$1; rx=$2
	fi
	printf '%s %s' "$tx" "$rx"
}

units() {
	systemctl show --all --property=Id --property=IPEgressBytes --property=IPIngressBytes 2>/dev/null |
	awk '
	/^Id=/ { if (id != "") print id "\t" eg "\t" ig; id = substr($0, 4); eg = 0; ig = 0; next }
	/^IPEgressBytes=/ { v = substr($0, 15); eg = (v == "" || v == "[not set]") ? 0 : v }
	/^IPIngressBytes=/ { v = substr($0, 16); ig = (v == "" || v == "[not set]") ? 0 : v }
	END { if (id != "") print id "\t" eg "\t" ig }
	'
}

record() {
	mkdir -p "$DIR" 2>/dev/null || die "cannot create $DIR"
	# Read the timestamp after the sample so the baseline moment is never earlier
	# than the values it describes.
	txrx=$(host_tx_rx)
	set -- $txrx
	tmp=$(mktemp "$DIR/.baseline.XXXXXX") || die 'mktemp failed'
	{
		printf '__ts__\t%s\n' "$(date +%s)"
		printf '__host__\t%s\t%s\n' "$1" "$2"
		units | sed 's/^/unit\t/'
	} >"$tmp"
	mv "$tmp" "$BASE"
	say "baseline recorded at $(date -d "@$(date +%s)" '+%F %T') in $BASE"
	say "units sampled: $(grep -c '^unit' "$BASE" 2>/dev/null)"
}

report() {
	[ -f "$BASE" ] || die "no baseline at $BASE; run 'baseline.sh record' first"
	bts=$(awk -F'\t' '$1 == "__ts__" {print $2}' "$BASE")
	now=$(date +%s)
	elapsed=$((now - bts))
	[ "$elapsed" -gt 0 ] || elapsed=1
	read -r htx hrx <<EOF
$(host_tx_rx)
EOF
	bhtx=$(awk -F'\t' '$1 == "__host__" {print $2}' "$BASE")
	bhrx=$(awk -F'\t' '$1 == "__host__" {print $3}' "$BASE")
	dtx=$((htx - bhtx)); drx=$((hrx - bhrx))
	[ "$dtx" -lt 0 ] && dtx=0
	[ "$drx" -lt 0 ] && drx=0

	printf 'baseline age: %s s\n' "$elapsed"
	printf 'host egress since baseline: %s MiB   (ingress: %s MiB)\n' \
		"$((dtx / 1048576))" "$((drx / 1048576))"
	printf '\n%-44s %12s %12s %14s  %s\n' unit 'egress MiB' 'per day MiB' 'declared' 'class'
	printf '%s\n' '--------------------------------------------------------------------------------------------'

	units | while IFS='	' read -r u eg ig; do
		[ -n "$u" ] || continue
		beg=$(awk -F'\t' -v u="$u" '$1 == "unit" && $2 == u {print $3}' "$BASE")
		[ -n "$beg" ] || beg=0
		d=$((eg - beg))
		[ "$d" -lt 0 ] && d=0
		[ "$d" -eq 0 ] && continue
		perday=$((d / elapsed * 86400))
		cls=$(awk -F'\t' -v u="$u" '$1 == u {print $3}' "$CLASSES" 2>/dev/null)
		lim=$(awk -F'\t' -v u="$u" '$1 == u {print $4}' "$CLASSES" 2>/dev/null)

		flags=''
		if [ -z "$cls" ]; then
			flags='no declared purpose'
		elif [ -n "$lim" ] && [ "$perday" -gt "$lim" ]; then
			flags="above declared allowance ($((lim / 1048576)) MiB/day)"
		fi
		printf '%-44s %12s %12s %14s  %s\n' "$u" "$((d / 1048576))" "$((perday / 1048576))" \
			"${lim:+$((lim / 1048576))}" "${cls:-?}${flags:+ - $flags}"
	done

	printf '\nInterpretation: a unit with no declared purpose that moved bytes is a question,\n'
	printf 'not a finding. A unit above its declared allowance is a finding only if the\n'
	printf 'declaration was accurate. The baseline is defeated by any workload the squatter\n'
	printf 'runs slowly enough to be inside the normal range; see HARDENING.md, D12/D57.\n'
}

declare_unit() {
	[ $# -ge 2 ] || die 'usage: baseline.sh declare UNIT CLASS [GIB_PER_DAY]'
	mkdir -p "$DIR" 2>/dev/null || die "cannot create $DIR"
	lim=0
	if [ $# -ge 3 ]; then
		# GIB_PER_DAY is decimal GiB on the command line, bytes in the file.
		lim=$(awk -v g="$3" 'BEGIN {printf "%.0f", g * 1073741824}')
	fi
	[ -f "$CLASSES" ] || : >"$CLASSES"
	awk -F'\t' -v u="$1" '$1 != u' "$CLASSES" >"$CLASSES.tmp" 2>/dev/null || : >"$CLASSES.tmp"
	printf '%s\t%s\t%s\n' "$1" "$2" "$lim" >>"$CLASSES.tmp"
	mv "$CLASSES.tmp" "$CLASSES"
	say "declared $1 as '$2'"${3:+", allowance $3 GiB/day"}
}

case ${1:-report} in
record)   record ;;
report)   report ;;
declare)  shift; declare_unit "$@" ;;
*)        die 'usage: baseline.sh [record|report|declare UNIT CLASS [GIB_PER_DAY]]' ;;
esac
exit 0
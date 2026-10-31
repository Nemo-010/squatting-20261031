#!/bin/sh
# Per-unit egress sampler for systemd hosts (systemd >= 235, Linux >= 4.11).
# Sampling, not detection: it shows which unit is moving bytes, so you can look.
#
# Caveats that decide how much to trust it:
#   * IPAccounting is NOT recursive - slices do not aggregate their children, so
#     summing a slice and its services double-counts.
#   * it excludes per-user managers (systemctl --user), so a rootless JupyterHub
#     gets nothing; meter those with nftables counters instead.
#   * it undercounts TCP because it sums skb->len before GSO (systemd #34775:
#     a 10 KB upload reports 11001 bytes). Deltas are a trend, not a bill.
set -u

STATE=${STATE:-/var/lib/egress-watch}
THRESHOLD=${THRESHOLD:-1073741824}   # 1 GiB per interval; 5 min cadence = ~28 Mbit/s
mkdir -p "$STATE" || exit 1
command -v systemctl >/dev/null 2>&1 || exit 0

systemctl list-units --type=service --type=scope --state=running --no-legend 2>/dev/null |
awk '{print $1}' | while read -r u; do
	cur=$(systemctl show "$u" -p IPEgressBytes --value 2>/dev/null)
	case ${cur:-x} in ''|*[!0-9]*) continue ;; esac
	f="$STATE/${u%.service}"
	prev=$(cat "$f" 2>/dev/null) || prev=$cur
	echo "$cur" >"$f"
	# a counter reset means the unit restarted; a negative delta is not a wrap
	[ "$cur" -ge "$prev" ] || continue
	d=$((cur - prev))
	[ "$d" -gt "$THRESHOLD" ] && logger -t egress-watch "$u emitted $d bytes since last sample"
done

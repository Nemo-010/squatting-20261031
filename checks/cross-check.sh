#!/bin/sh
# Cross-view socket check.
#
# Two different code paths into the same in-kernel socket table:
#   - netlink sock_diag (what `ss` uses by default)
#   - the procfs seq_file views /proc/net/{tcp,tcp6,udp,udp6}
# They are not independent sources of truth (see HARDENING.md, D09). They differ
# in code path, so a hook that filters one and forgets the other is visible here.
# A hook that filters both is not, and neither is an eBPF program or an LKM.
#
# This compares *inode sets*, not counts: counts race and produce false alarms,
# and a filtered view can keep the same total by dropping one socket and adding
# another. An inode difference is a specific socket to go and look at.
set -u
LC_ALL=C
export LC_ALL

have() { command -v "$1" >/dev/null 2>&1; }
have ss || { echo 'ss not found (iproute2)'; exit 2; }

TMP=$(mktemp -d 2>/dev/null || { echo 'mktemp failed'; exit 2; })
trap 'rm -rf "$TMP"' EXIT INT TERM

nl_ino() {
	# Listening and established, TCP and UDP, one inode per line. ino:0 is a
	# socket-less state and not comparable with the procfs view.
	{
		ss -Htane 2>/dev/null | grep -o 'ino:[0-9][0-9]*' | cut -d: -f2
		ss -Huane 2>/dev/null | grep -o 'ino:[0-9][0-9]*' | cut -d: -f2
	} | awk '$1 != 0'
}

proc_ino() {
	# Field 10 is the inode in the tcp/udp table format. Inode 0 rows are
	# socket-less states (TIME_WAIT remnants) and are not comparable.
	for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
		[ -r "$f" ] || continue
		awk 'NR > 1 && $10 != 0 && $10 != "" {print $10}' "$f" 2>/dev/null
	done
}

nl_ino | sort -u >"$TMP/nl"
proc_ino | sort -u >"$TMP/proc"

nl_count=$(grep -c '' "$TMP/nl")
proc_count=$(grep -c '' "$TMP/proc")
printf 'netlink inodes: %s\n' "$nl_count"
printf 'procfs  inodes: %s\n' "$proc_count"

comm -23 "$TMP/nl" "$TMP/proc" >"$TMP/only_nl"
comm -13 "$TMP/nl" "$TMP/proc" >"$TMP/only_proc"

if [ -s "$TMP/only_nl" ] || [ -s "$TMP/only_proc" ]; then
	n1=$(grep -c '' "$TMP/only_nl")
	n2=$(grep -c '' "$TMP/only_proc")
	echo
	echo "DISAGREEMENT: $n1 inode(s) only in netlink, $n2 only in procfs."
	echo 'Some churn is normal between two reads. Re-run immediately; if the same'
	echo 'inode is still visible in one view and not the other, one path is filtered.'
	echo
	if [ -s "$TMP/only_nl" ]; then
		echo 'only in netlink (hidden from /proc/net):'
		sed 's/^/  /' "$TMP/only_nl" | head -20
	fi
	if [ -s "$TMP/only_proc" ]; then
		echo 'only in procfs (hidden from sock_diag):'
		sed 's/^/  /' "$TMP/only_proc" | head -20
	fi
else
	echo 'the two views list the same inodes at this instant'
fi

echo
echo 'inode -> pid attribution (built by reading /proc/*/fd)'
echo 'NOTE: this is the same readdir path an ss -p hook can filter, and a socket'
echo 'passed with SCM_RIGHTS is attributed to its holder, not its author.'
for ino in $(cat "$TMP/only_nl" "$TMP/only_proc" 2>/dev/null | sort -u); do
	holders=$(for d in /proc/[0-9]*/fd; do
		[ -d "$d" ] || continue
		pid=${d#/proc/}; pid=${pid%%/*}
		for fd in "$d"/*; do
			[ -L "$fd" ] || continue
			[ "$(readlink "$fd" 2>/dev/null)" = "socket:[$ino]" ] && printf '%s ' "$pid"
		done
	done)
	if [ -n "$holders" ]; then
		printf '  inode %s held by pid(s): %s\n' "$ino" "$holders"
	else
		printf '  inode %s has no visible holder (kernel socket, or hidden process)\n' "$ino"
	fi
done

echo
echo 'shared objects mapped after being unlinked:'
for p in /proc/[0-9]*/maps; do
	awk '$6 ~ /\.so/ && $6 ~ /\(deleted\)$/ {print $6}' "$p" 2>/dev/null
done | sort -u | head -20 | sed 's/^/  /'

echo
echo 'per-process linker hooks (LD_PRELOAD / LD_AUDIT):'
for p in /proc/[0-9]*/environ; do
	[ -r "$p" ] || continue
	hit=$(tr '\0' '\n' <"$p" 2>/dev/null | grep -E '^LD_(PRELOAD|AUDIT)=' | head -2)
	[ -n "$hit" ] && printf '  pid %s: %s\n' "${p#/proc/}" "$hit"
done

echo
echo 'The strongest independent tiebreaker is not here: it is a counter outside the'
echo 'guest (provider billing, a second host'"'"'s flow records) or an eBPF probe that the'
echo 'compromised userland cannot reach.'
exit 0
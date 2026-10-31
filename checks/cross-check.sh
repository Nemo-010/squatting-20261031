#!/bin/sh
# Cross-view socket check: two independent datasources that disagree is the finding.
# /proc/net/tcp is trivially hooked by an LD_PRELOAD rootkit; the netlink socket list
# is not reachable from userland, so the two views are a useful diff. A raw AF_PACKET
# capture sits below both, but the strongest cross-check is a kernel-side counter
# (cgroup eBPF or conntrack), which no userland library can edit.
set -u

proc_count() {
	n=0
	for f in /proc/net/tcp /proc/net/tcp6; do
		[ -r "$f" ] || continue
		n=$((n + $(wc -l <"$f") - 1))
	done
	printf '%s' "$n"
}

command -v ss >/dev/null 2>&1 || { echo 'ss not found (iproute2)'; exit 1; }

netlink=$(ss -Htan 2>/dev/null | wc -l)
proc=$(proc_count)
echo "netlink sockets: $netlink"
echo "procfs  sockets: $proc"

if [ "$proc" -lt "$netlink" ]; then
	echo 'DISAGREEMENT: procfs shows fewer sockets than netlink.'
	echo 'Either sockets closed between samples, or something filters /proc/net/tcp.'
	echo 'Re-run immediately; if it persists, check /proc/*/maps for a .so that is not in ldd output.'
fi

echo
# PROC_NET_TCP takes a PATH, not a flag: ss.c generic_proc_open() fopen()s the value.
# PROC_NET_TCP=1 reads a file named "1" and yields nothing.
echo 'same binary, forced through procfs:'
PROC_NET_TCP=/proc/net/tcp ss -Htan 2>/dev/null | wc -l

echo
echo 'shared objects mapped by a process after being unlinked (classic preload hide):'
for p in /proc/[0-9]*/maps; do
	awk '$6 ~ /\.so/ {print $6}' "$p" 2>/dev/null
done | sort -u | while read -r lib; do
	case $lib in
	*'(deleted)'*) echo "  deleted: $lib" ;;
	esac
done | sort -u | head -20

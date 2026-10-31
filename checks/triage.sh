#!/bin/sh
# Read-only triage of one Linux host for proxy / tunnel / relay squatting.
# Nothing here writes to the system. Some checks need root to resolve owners.
set -u

hdr() { printf '\n== %s ==\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
	printf 'note: not root; /proc/<pid>/exe and ss -p will be incomplete\n'
fi

hdr 'processes running from writable or anonymous memory'
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	exe=$(readlink "$p/exe" 2>/dev/null) || continue
	case $exe in
	*/tmp/*|*/var/tmp/*|*/dev/shm/*|*/run/*|*/.cache/*|*"(deleted)"|/memfd:*)
		printf '%-7s %-48s %s\n' "$pid" "$exe" "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null)"
		;;
	esac
done

hdr 'kernel-thread names with a real user-space binary behind them'
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	comm=$(cat "$p/comm" 2>/dev/null) || continue
	case $comm in
	kworker*|ksoftirqd*|migration*|rcu_*|kthreadd*|kswapd*|watchdog*)
		exe=$(readlink "$p/exe" 2>/dev/null) || continue
		printf '%-7s %-16s %s\n' "$pid" "$comm" "$exe"
		;;
	esac
done

hdr 'ld.so.preload (any content is a finding)'
if [ -e /etc/ld.so.preload ]; then
	printf 'PRESENT:\n'
	cat /etc/ld.so.preload
else
	printf 'absent\n'
fi

if have ss; then
	hdr 'cloudflared / Argo tunnel endpoints (it dials 7844, never listens on it)'
	ss -Htnp state established '( dport = :7844 or sport = :7844 )' 2>/dev/null

	hdr 'UDP sockets (QUIC, uTP, WireGuard, DHT)'
	printf '   state recv-q send-q local peer [process]\n'
	ss -unp 2>/dev/null

	hdr 'listening TCP/UDP'
	ss -tulpn 2>/dev/null

	hdr 'established sessions per process'
	ss -tnp state established 2>/dev/null
else
	printf '\nnote: ss not found (iproute2)\n'
fi

hdr 'packet sockets (raw capture - a squatter sniffing or a sniffer you did not install)'
if have ss; then
	ss -H -0 -p 2>/dev/null | head -20
fi

hdr 'network namespaces'
for n in /proc/[0-9]*/ns/net; do readlink "$n" 2>/dev/null; done | sort | uniq -c

hdr 'containers (if docker is present)'
if have docker; then
	docker ps -q 2>/dev/null | while read -r id; do
		docker inspect --format '{{.Name}} net={{.HostConfig.NetworkMode}} priv={{.HostConfig.Privileged}} img={{.Config.Image}}' "$id" 2>/dev/null
	done
else
	printf 'docker not present\n'
fi

hdr 'persistence surfaces modified recently (7 days)'
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron /etc/systemd/system \
     /etc/rc.local -newermt '-7 days' 2>/dev/null | head -40

hdr 'users with a login shell and no recent login'
if have lastlog; then
	lastlog 2>/dev/null | awk 'NR==1 || /Never logged in/'
fi

printf '\ndone. Interpret: an established 7844 session, an exe under /tmp or /dev/shm, or any\n'
printf 'ld.so.preload content is a finding. Absence of these is not proof of cleanliness.\n'

#!/bin/sh
# Overlay / mesh network squat indicators (research/overlay-mesh-networks.md).
# Read-only. Interfaces, processes, units, state dirs, TUN device use, and the
# public endpoint feeds that survive binary renames.
set -u
LC_ALL=C
export LC_ALL

hdr()  { printf '\n== %s ==\n' "$*"; }
sub()  { printf -- '-- %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '   note: %s\n' "$*"; }

hdr 'mesh interfaces in /proc/net/dev'
note 'renames defeat this; a NEW tun interface on a server is the lead, not the name'
awk 'NR>2 {print "   " $1}' /proc/net/dev 2>/dev/null | grep -E 'tailscale0|wt0|^   zt|nebula1|ygg0|edge0|tun[0-9]|tap[0-9]' || printf '   none matching known mesh names\n'

hdr 'mesh processes (name-based; rename defeats it)'
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	exe=$(readlink "$p/exe" 2>/dev/null) || continue
	case ${exe##*/} in
	tailscaled|tailscale|netbird|zerotier-one|nebula|tincd|edge|supernode|yggdrasil|cjdroute|wireguard-go|headscale)
		printf '   pid %-7s %-16s %s\n' "$pid" "${exe##*/}" "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-140)"
		;;
	esac
done | sort -u
[ -z "$(for p in /proc/[0-9]*; do readlink "$p/exe" 2>/dev/null; done | grep -E '(tailscaled|netbird|zerotier-one|nebula|tincd|yggdrasil|cjdroute)$')" ] && printf '   none\n'

hdr 'state directories and units'
for d in /var/lib/tailscale /var/lib/zerotier-one /etc/nebula /etc/tinc /var/lib/netbird /var/lib/cjdroute; do
	[ -e "$d" ] && printf '   %s\n' "$d"
done
ls /etc/systemd/system 2>/dev/null | grep -E 'tailscaled|netbird|zerotier|nebula|tinc@|yggdrasil|cjdroute|headscale' | sed 's/^/   /'
ls /etc/tinc 2>/dev/null | sed 's/^/   tinc network: /'
[ -f /etc/default/tailscaled ] && printf '   /etc/default/tailscaled exists: %s\n' "$(grep -c . /etc/default/tailscaled) lines"

hdr 'mesh-managed firewall rules'
note 'NetBird writes nftables/iptables rules naming wt0; these survive binary renames'
if have nft; then nft list ruleset 2>/dev/null | grep -iE 'netbird|tailscale|wt0' | sed 's/^/   /' | head -5; fi
if have iptables; then iptables-save 2>/dev/null | grep -iE 'netbird|tailscale|wt0' | sed 's/^/   /' | head -5; fi

hdr 'endpoint flows that survive renames'
note 'Tailscale DERP map: https://controlplane.tailscale.com/derpmap/default'
note 'NetBird endpoints JSON: https://docs.netbird.io/docs-static/files/netbird-cloud-endpoints.json'
note 'resolve a few and grep conntrack (read-only, no probe is sent)'
if have conntrack; then
	for h in controlplane.tailscale.com derp1-all.tailscale.com api.netbird.io relay.netbird.io; do
		if have getent; then ip=$(getent ahostsv4 "$h" 2>/dev/null | awk 'NR==1{print $1}'); fi
		[ -n "${ip:-}" ] && conntrack -L 2>/dev/null | grep -c "$ip" | sed "s/^/   $h ($ip): /"
	done
else
	note 'conntrack(8) not installed; flows not checked'
fi
if have ss; then
	sub 'UDP 41641 / 9993 / 7654 and TCP 655 holders (defaults, renameable)'
	ss -Hunpa 2>/dev/null | grep -E ':(41641|9993|7654|3478)\b' | sed 's/^/   /' | head -8
	ss -Htnpa 2>/dev/null | grep -E ':655\b' | sed 's/^/   /' | head -4
fi

hdr 'Nebula recv_error oracle'
note 'Nebula replies recv_error to garbage on its port unless send_recv_error: never'
note 'probe only if you own the host or have authorization; nothing sent by this check'

hdr 'what this check cannot see'
note 'userspace modes: tailscaled --tun=userspace-networking, libzt, iroh inside another binary'
note 'self-hosted control planes: headscale, netbird self-host, zerotier moons/private planet'
note 'renamed binaries and interfaces; renamed tinc networks'
note 'see research/overlay-mesh-networks.md section 10 for what survives'

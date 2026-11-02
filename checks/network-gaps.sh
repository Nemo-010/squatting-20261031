#!/bin/sh
# Channels the rest of the corpus had no check for (D59).
# Read-only. Prints what is visible from the host and, at the end, what is not.
set -u
LC_ALL=C
export LC_ALL

hdr()  { printf '\n== %s ==\n' "$*"; }
sub()  { printf -- '-- %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '   note: %s\n' "$*"; }

hdr 'ssh / autossh forwarders and dynamic proxies'
note 'D59: ssh -D is a SOCKS proxy, -R publishes this host, -w is a tunnel device.'
hit=0
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	exe=$(readlink "$p/exe" 2>/dev/null) || continue
	case ${exe##*/} in ssh|autossh|dropbear|dbclient) ;; *) continue ;; esac
	args=$(tr '\0' '\n' <"$p/cmdline" 2>/dev/null)
	case $args in
	*-D*|*-R*|*-L*|*-w*)
		hit=1
		printf '   pid %-7s %s\n' "$pid" "$(printf '%s' "$args" | tr '\n' ' ' | cut -c1-220)"
		;;
	esac
done
[ "$hit" -eq 0 ] && printf '   none\n'

hdr 'HTTP CONNECT / SOCKS relay processes'
note 'D59: the corpus had byte constants for SOCKS but no check for HTTP CONNECT.'
hit=0
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	exe=$(readlink "$p/exe" 2>/dev/null) || continue
	base=${exe##*/}
	case $base in
	squid|tinyproxy|dante|danted|sockd|3proxy|proxy|privoxy|mitmproxy|mitmdump|gost|socat|microsocks|hev-socks5-tunnel|tun2socks)
		hit=1
		printf '   pid %-7s %s  %s\n' "$pid" "$exe" "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-160)"
		;;
	esac
done
[ "$hit" -eq 0 ] && printf '   none\n'

if have ss; then
	sub 'listeners by port, for the relay families that do listen'
	ss -Htulpn 2>/dev/null | awk '{print "   " $0}' | grep -E ':(1080|1081|3128|8080|8081|8118|9050|9051|8888|7890|7891|10808|10809|8388|1087|1090)\b' || printf '   none on the usual proxy ports\n'
fi

hdr 'DNS tunnels and DoH/DoT'
note 'D36: DoH/DoT removes the tunnel from dns.log entirely; this only finds endpoints.'
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	exe=$(readlink "$p/exe" 2>/dev/null) || continue
	case ${exe##*/} in
	dnstt*|iodine*|dns2tcp*|dnscat*|tcp-over-dns*|slipstream*|olai*|heyoka*)
		printf '   pid %-7s DNS-tunnel client: %s %s\n' "$pid" "$exe" "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-140)"
		;;
	esac
done
if have ss; then
	sub 'established sessions to :853 (DoT) and :443 sessions whose image is a DoH proxy'
	ss -Htnp state established '( dport = :853 )' 2>/dev/null | sed 's/^/   /'
	for pid in $(ss -Htnp state established 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u); do
		exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
		case ${exe##*/} in cloudflared|doh-proxy*|dnsproxy|dnscrypt*|https-dns-proxy*)
			printf '   pid %-7s DoH-capable resolver proxy: %s\n' "$pid" "$exe" ;;
		esac
	done
fi
sub 'ICMP counters (a tunnel shows up as sustained echo traffic)'
if [ -r /proc/net/snmp ]; then
	awk '
	{ k = $1; sub(/:$/, "", k) }
	$2 !~ /^[0-9]+$/ { for (i = 2; i <= NF; i++) h[k, i] = $i; next }
	k == "Icmp" || k == "IcmpMsg" { for (i = 2; i <= NF; i++) printf "   %s.%s=%s\n", k, h[k, i], $i }
	' /proc/net/snmp
fi

hdr 'ICMP payload channels'
note 'D59: ptunnel/icmptunnel need no TCP or UDP port. Raw ICMP sockets are the host-visible part.'
if [ -r /proc/net/raw ]; then
	awk 'NR>1 {printf "   raw inode %s local %s remote %s st=%s uid=%s\n", $10, $2, $3, $4, $8}' /proc/net/raw | head -20
fi
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	exe=$(readlink "$p/exe" 2>/dev/null) || continue
	case ${exe##*/} in ptunnel*|icmptunnel*|icmp-tunnel*|hans*|pingtunnel*)
		printf '   pid %-7s ICMP tunnel: %s\n' "$pid" "$exe" ;;
	esac
done

hdr 'vsock'
note 'D59: a relay to a co-resident VM over AF_VSOCK never touches an IP address.'
if have ss && ss -a --vsock >/dev/null 2>&1; then
	ss -a --vsock 2>/dev/null | sed 's/^/   /' | head -20
else
	printf '   ss --vsock unavailable on this host\n'
fi
for m in vsock vmw_vsock_virtio_transport vsock_loopback; do
	grep -q "^$m " /proc/modules 2>/dev/null && printf '   module loaded: %s\n' "$m"
done

hdr 'tun fds, kernel relays and L3 tunnel terminators'
note 'D59 (adopted from research/no-socket-relays.md): three lanes never appear in ss -Htulpn.'
note 'ip tunnel show covers only the ip_tunnel family; the type sweep needs ip -d link show.'
if have ip; then
	ip -o -d link show 2>/dev/null | grep -E 'tun|tap|gre|sit|ipip|vti|gretap|erspan|vxlan|geneve|xfrm|fou' | sed 's/^/   /'
fi
sub 'tunnel transport modules loaded in this kernel'
grep -E '^(ip_gre|ip6_gre|sit|ipip|ip_tunnel|gre|fou|vxlan|geneve|esp4|esp6) ' /proc/modules 2>/dev/null | sed 's/^/   module loaded: /' || printf '   none of: ip_gre ip6_gre sit ipip ip_tunnel fou vxlan geneve esp4 esp6\n'
sub 'processes holding a tun fd (lane A: userland TCP stacks; fd predates TUNSETIFF)'
hit=0
for p in /proc/[0-9]*/fd; do
	pid=${p#/proc/}; pid=${pid%%/*}
	for fd in "$p"/*; do
		[ -L "$fd" ] || continue
		case $(readlink "$fd" 2>/dev/null) in
		*/net/tun*)
			exe=$(readlink "$p/../exe" 2>/dev/null) || exe='?'
			hit=1
			printf '   pid %-7s %s  %s -> %s\n' "$pid" "$exe" "$(basename "$fd")" "$(readlink "$fd")"
			;;
		esac
	done
done
[ "$hit" -eq 0 ] && printf '   none (readlink-denied fdinfo fallback: major 10, minor 200)\n'
if have ss; then
	sub 'packet/raw/xdp sockets - the complement ss -Htulpn never prints'
	ss -0p 2>/dev/null | sed 's/^/   PACKET /'
	ss -wp 2>/dev/null  | sed 's/^/   RAW    /'
	ss --xdp 2>/dev/null | sed 's/^/   XDP    /'
fi
sub 'policy rules worth diffing against checks/baseline.sh (9000 and table 2022 are sing-box defaults)'
if have ip; then
	ip rule show 2>/dev/null | sed 's/^/   /' | head -20
fi
sub 'kernel-side relays: needs root, listed because they have no userspace socket at all'
if have nft; then
	if nft list ruleset 2>/dev/null | grep -E 'dnat|redirect|tproxy'; then :; else printf '   no DNAT/REDIRECT/TPROXY rules readable (or empty/non-root)\n'; fi
else
	printf '   nft not installed\n'
fi
if have tc; then
	for N in $(ip -o link show 2>/dev/null | cut -d: -f2 | tr -d ' '); do tc filter show dev "$N" ingress 2>/dev/null | grep -q . && { printf '   tc dev %s has filters\n' "$N"; tc filter show dev "$N" ingress | sed 's/^/     /'; }; tc filter show dev "$N" egress 2>/dev/null | grep -q . && { printf '   tc dev %s egress filters\n' "$N"; tc filter show dev "$N" egress | sed 's/^/     /'; }
	done
fi
if have bpftool; then
	bpftool prog show 2>/dev/null | grep -iE 'sockmap|sock_msg|sockops|cgroup/bpf' | sed 's/^/   /'
	bpftool net show 2>/dev/null | sed 's/^/   /' | head -10
else
	printf '   bpftool not installed\n'
fi
if have ip; then
	if ip xfrm state 2>/dev/null | grep -qv '^'; then ip xfrm state 2>/dev/null | sed 's/^/   xfrm /'; else printf '   no readable xfrm state (ESPATH terminator check needs root)\n'; fi
fi
note 'bind-mounted /dev/net/tun paths: fdinfo device pair fixes the attribution (major 10, minor 200).'
note 'diff nft/rules against provision time: ruleset lives in netlink state only; inotify cannot help.'
note 'bpftrace: kprobe:nf_nat_inet_fn measures the per-family NAT hook; see also checks/probes.bt.'
note 'nft monitor rules as a service is the practical offset to a ruleset that can be flushed (netlink state only).'
sub 'sing-box configuration directories (shipped unit: -C /etc/sing-box, so the glob is *.json)'
for d in /etc/sing-box /usr/local/etc/sing-box /var/lib/sing-box; do
	if [ -d "$d" ]; then
		printf '   %s: ' "$d"
		ls "$d" 2>/dev/null | tr '\n' ' '
		echo
	fi
done
note 'FP gates: container veths and CNI bridges fill the link sweep; docker/k8s SNAT fills nft; Tetragon/Tracee fill bpftool; every legit VPN, KVM-with-tap and ssh -w fills the fd sweep.'

hdr 'io_uring users'
note 'D23/D27: io_uring connect/bind/sendmsg are auditable; socket/send/recv are audit_skip.'
note 'The ring itself is visible as an anon_inode fd here, which the syscall probes miss.'
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	found=''
	for fd in "$p"/fd/*; do
		[ -L "$fd" ] || continue
		case $(readlink "$fd" 2>/dev/null) in
		anon_inode:\[io_uring\]*) found="$found $(basename "$fd")" ;;
		esac
	done
	if [ -n "$found" ]; then
		exe=$(readlink "$p/exe" 2>/dev/null) || exe='?'
		printf '   pid %-7s %s  io_uring fd(s):%s\n' "$pid" "$exe" "$found"
	fi
done

hdr 'user namespaces (unshare -Ur gives CAP_NET_ADMIN without a runtime)'
nsf=$(mktemp 2>/dev/null || echo /tmp/.gaps-ns.$$)
: >"$nsf"
for n in /proc/[0-9]*/ns/user; do
	pid=${n#/proc/}; pid=${pid%%/*}
	ino=$(readlink "$n" 2>/dev/null) || continue
	printf '%s %s\n' "$ino" "$pid" >>"$nsf"
done
awk '{c[$1]=c[$1] " " $2; n[$1]++} END{for (i in c) printf "   user ns %-18s %3d pids:%s\n", i, n[i], substr(c[i],1,140)}' "$nsf" | sort
rm -f "$nsf"

hdr 'not visible from this host'
cat <<'EOF'
   TLS-in-TLS (a tunnel inside an HTTPS session; more generally, encapsulated TLS
   handshakes) has no host-observable constant to match. It is visible only as an
   economic/statistical shape at a network vantage point: Xue, Kallitsis, Houmansadr &
   Ensafi, "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes",
   USENIX Security 2024 detect it at an ISP against "random padding and multiple layers
   of encapsulations". No checked source names a host sensor for it, so the shape is also
   what a busy API client looks like from here. This is D58's position of record: the
   detector named in the literature lives at the ISP/censor, not on the box.
   macvlan / ipvlan / SR-IOV traffic does not cross the host interface counters.
   A relay inside another netns is visible only through the container runtime's
   object list, or through an eBPF probe attached to the host kernel.
   Provider flow logs (VPC flow logs, GCP VPC Flow Logs) are the only view that
   sees a container's traffic without the guest's cooperation. They are not
   readable from the guest; see HARDENING.md, D59 and D57.
EOF
exit 0
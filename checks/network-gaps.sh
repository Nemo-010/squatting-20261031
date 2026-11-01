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
   TLS-in-TLS (a tunnel inside an HTTPS session) has no constant to match. It is
   only visible as a statistical shape, and the shape is also what a busy API
   client looks like.
   macvlan / ipvlan / SR-IOV traffic does not cross the host interface counters.
   A relay inside another netns is visible only through the container runtime's
   object list, or through an eBPF probe attached to the host kernel.
   Provider flow logs (VPC flow logs, GCP VPC Flow Logs) are the only view that
   sees a container's traffic without the guest's cooperation. They are not
   readable from the guest; see HARDENING.md, D59 and D57.
EOF
exit 0
#!/bin/sh
# Read-only triage of one Linux host for proxy / tunnel / relay squatting.
# Nothing here writes to the system. Run as root for full coverage; the coverage
# section at the end says exactly what was not inspected.
#
# Findings are tagged [high] / [medium] / [low] / [info]. A tag is a reason to look,
# not a verdict. See HARDENING.md for what this cannot see.
set -u
LC_ALL=C
export LC_ALL

hdr()  { printf '\n== %s ==\n' "$*"; }
sub()  { printf -- '-- %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '   note: %s\n' "$*"; }

ROOT=0
[ "$(id -u)" -eq 0 ] && ROOT=1

CNT=$(mktemp 2>/dev/null || echo /tmp/.triage-cnt.$$)
: >"$CNT"
trap 'rm -f "$CNT"' EXIT INT TERM
tag() {
	_sev=$1; shift
	# Appended to a file because most call sites run inside a pipeline
	# subshell, where a shell variable would not survive.
	printf '%s\n' "$_sev" >>"$CNT"
	printf '[%-6s] %s\n' "$_sev" "$*"
}

# stat3 PATH -> "mode uid gid" for the path itself.
stat3() { stat -c '%a %u %g' "$1" 2>/dev/null; }

# writable_reason PATH UID GID
# Prints a reason if UID could replace or modify PATH, and nothing otherwise.
# Group membership is approximated by the process's primary GID; supplementary
# groups are not visible per-process without parsing /proc/<pid>/status Groups:.
writable_reason() {
	_p=$1; _uid=$2; _gid=$3
	_d=$(dirname "$_p")
	_ds=$(stat3 "$_d") || return 0
	_fs=$(stat3 "$_p") || _fs=''

	_dm=$(echo "$_ds" | cut -d' ' -f1); _du=$(echo "$_ds" | cut -d' ' -f2); _dg=$(echo "$_ds" | cut -d' ' -f3)
	_dm=$((0$_dm))
	if [ -n "$_fs" ]; then
		_fm=$(echo "$_fs" | cut -d' ' -f1); _fu=$(echo "$_fs" | cut -d' ' -f2); _fg=$(echo "$_fs" | cut -d' ' -f3)
		_fm=$((0$_fm))
	else
		_fm=0; _fu=-1; _fg=-1
	fi

	if [ "$_fu" = "$_uid" ] && [ $((_fm & 0200)) -ne 0 ]; then
		echo "binary writable by uid $_uid"; return 0
	fi
	if [ "$_fg" = "$_gid" ] && [ $((_fm & 0020)) -ne 0 ]; then
		echo "binary group-writable"; return 0
	fi
	if [ $((_fm & 0002)) -ne 0 ]; then
		echo "binary world-writable"; return 0
	fi
	if [ "$_du" = "$_uid" ] && [ $((_dm & 0200)) -ne 0 ]; then
		echo "directory $_d writable by uid $_uid"; return 0
	fi
	if [ "$_dg" = "$_gid" ] && [ $((_dm & 0020)) -ne 0 ]; then
		echo "directory $_d group-writable by its owner group"; return 0
	fi
	if [ $((_dm & 0002)) -ne 0 ]; then
		echo "directory $_d world-writable"; return 0
	fi
	return 0
}

KERNEL_NAMES='kworker*|ksoftirqd*|migration*|rcu_*|kthreadd*|kswapd*|watchdog*|kblockd*|kcompactd*|khugepaged*|kdevtmpfs*|netns*|kauditd*|kdmflush*|kjournald*'
SERVICE_NAMES='sshd|cron|crond|systemd|systemd-journald|systemd-logind|dbus-daemon|nginx|apache2|httpd|postgres|mysqld|redis-server|dockerd|containerd|kubelet'
RUNNERS='Runner.Listener|Runner.Worker|buildkite-agent|gitlab-runner|jenkins-agent'

# pkg_owner PATH -> package name, 'unowned', or 'no package db'.
# Answers the only useful question about a listener: did the operator install it?
pkg_owner() {
	_f=$1
	case $_f in
	/usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/etc/*) ;;
	*) echo 'outside packaged prefixes'; return 0 ;;
	esac
	if have dpkg; then dpkg -S "$_f" 2>/dev/null | head -1 | cut -d: -f1
	elif have rpm; then rpm -qf "$_f" 2>/dev/null | head -1
	elif have pacman; then pacman -Qo "$_f" 2>/dev/null | awk '{print $NF}'
	elif have apk; then apk info -W "$_f" 2>/dev/null | head -1
	else echo 'no package db'
	fi
}

hdr 'process image paths (writability, not a directory whitelist)'
note 'D01/D02: every image is classified by whether its owner could replace it.'
note 'An image installed with pip/npm into a home directory is reported too: it is a lead, not proof.'

SEEN=0; READ_EXE=0; UNREADABLE=0; ANON_TOTAL=0
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	SEEN=$((SEEN + 1))

	cmd=''
	if [ -r "$p/cmdline" ]; then
		cmd=$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-240)
	fi
	comm=$(cat "$p/comm" 2>/dev/null) || comm=''

	# Distinguish 'no image at all' (kernel thread, ENOENT) from 'not allowed
	# to read it' (another uid, EACCES). The old script conflated the two and
	# reported a clean result for a multi-tenant host.
	_exec=$(readlink "$p/exe" 2>&1)
	case $_exec in
	*'Permission denied'*)
		exe=''; UNREADABLE=$((UNREADABLE + 1)) ;;
	*'No such file'*|*'Invalid argument'*)
		exe='' ;;
	*)
		exe=$_exec; READ_EXE=$((READ_EXE + 1)) ;;
	esac

	case $comm in
	$KERNEL_NAMES)
		if [ -n "$exe" ]; then
			tag high "pid $pid comm='$comm' resolves to '$exe' - a kernel thread has no image; this is a user process wearing a kernel name"
		fi
		;;
	\[*)
		if [ -n "$exe" ]; then
			tag high "pid $pid comm='$comm' is bracketed but has an image '$exe' - ps will render it as a kernel thread"
		fi
		;;
	esac

	[ -z "$exe" ] && continue

	case $exe in
	*/tmp/*|*/var/tmp/*|*/dev/shm/*|*/run/*|*/.cache/*|/memfd:*|*"(deleted)"*)
		tag high "pid $pid image '$exe' is in staging or anonymous memory"
		flagged=1
		;;
	*)
		flagged=0
		iuid=$(stat -c '%u' /proc/$pid 2>/dev/null) || iuid=''
		igid=$(stat -c '%g' /proc/$pid 2>/dev/null) || igid=0
		[ -n "$iuid" ] || iuid=0
		reason=$(writable_reason "$exe" "$iuid" "$igid")
		if [ -n "$reason" ]; then
			tag medium "pid $pid image '$exe': $reason"
			flagged=1
		fi
		;;
	esac

	# D03: no toolchain needed. A relay binary carries its own literals even
	# when the Go build info is stripped or the payload is C. Only scanned for
	# images already flagged, so the cost stays bounded.
	if [ "$flagged" -eq 1 ] && [ -r "$exe" ]; then
		lit=$(grep -aoE 'argotunnel|cloudflared|sing-box|xray|v2ray|hysteria|shadowsocks|trojan-go|frpc|frps|chisel|ngrok|localtunnel|rathole|zrok|tuic|naiveproxy|mihomo|peer2profit|xmrig|stratum\+tcp' "$exe" 2>/dev/null | sort -u | head -5 | tr '\n' ' ')
		[ -n "$lit" ] && tag medium "pid $pid image '$exe' contains relay literals: $lit"
	fi

	# comm is a free 16-byte string. A service name over a different image is
	# cheap to produce and worth listing, though a binary renamed 'sshd' is not.
	base=${exe##*/}
	base=${base% (deleted)}
	case $comm in
	$SERVICE_NAMES)
		if [ "$base" != "$comm" ]; then
			tag low "pid $pid comm='$comm' but image basename is '$base' - name is not identity"
		fi
		;;
	esac
	case $comm in
	$RUNNERS)
		tag info "pid $pid looks like a CI runner ('$comm'); see network-gaps.sh for its egress"
		;;
	esac

	# No new image at all: an interpreter executing strings, or a JIT.
	case $base in
	python|python[0-9]*|node|nodejs|perl|ruby|php|php[0-9]*|java|deno|bun|lua|luajit|Rscript)
		if [ -r "$p/cmdline" ]; then
			args=$(tr '\0' '\n' <"$p/cmdline" 2>/dev/null)
			if printf '%s\n' "$args" | grep -qxE -- '-c|-e|-m|--eval|--exec|-jar|--command|-r'; then
				tag medium "pid $pid runs code through $base with an inline/expression flag (no payload image on disk): $(printf '%s' "$cmd" | cut -c1-140)"
			fi
		fi
		;;
	esac

	# Executable anonymous mappings: JIT and some loaders. Linux reports them
	# with no pathname field (NF==5). A shell/JIT legitimately produces these,
	# so this is a lead only.
	if [ -r "$p/maps" ]; then
		anon=$(awk '$2 ~ /x/ && NF == 5 {n++} END{print n+0}' "$p/maps" 2>/dev/null)
		[ -n "$anon" ] || anon=0
		ANON_TOTAL=$((ANON_TOTAL + anon))
		if [ "$anon" -gt 0 ]; then
			tag low "pid $pid has $anon executable anonymous mapping(s) (JIT or unpacked code): $exe"
		fi
		dlib=$(awk '$2 ~ /x/ && NF >= 6 && $6 ~ /\(deleted\)$/ {print $6}' "$p/maps" 2>/dev/null | head -3)
		if [ -n "$dlib" ]; then
			tag medium "pid $pid maps a deleted executable file: $dlib"
		fi
	fi
done

hdr 'dynamic linker: file and per-process environment'
if [ -e /etc/ld.so.preload ]; then
	tag high "/etc/ld.so.preload is present ($(stat -c '%U:%G %a' /etc/ld.so.preload 2>/dev/null))"
	# glibc (elf/rtld.c): '#' blanks the rest of the line; entries are split on
	# spaces and colons. rkhunter strips only leading '#', which is not the rule.
	sed 's/#.*//' /etc/ld.so.preload 2>/dev/null | tr ' :\t' '\n\n\n' | sed '/^$/d' |
	while IFS= read -r so; do
		if [ -e "$so" ]; then
			printf '   entry: %s\n' "$so"
		else
			printf '   entry: %s (MISSING on disk)\n' "$so"
		fi
	done
else
	printf 'absent\n'
fi

sub 'LD_PRELOAD / LD_AUDIT in process environments'
for p in /proc/[0-9]*; do
	[ -r "$p/environ" ] || continue
	env=$(tr '\0' '\n' <"$p/environ" 2>/dev/null | grep -E '^LD_(PRELOAD|AUDIT)=' | cut -c1-200)
	if [ -n "$env" ]; then
		tag high "pid ${p#/proc/} has a per-process linker hook: $env"
	fi
done

sub 'shared objects mapped from writable or deleted paths'
for p in /proc/[0-9]*/maps; do
	awk '$6 ~ /\.so/ && ($6 ~ /\(deleted\)$/ || $6 ~ /^\/(home|tmp|var\/tmp|dev\/shm|run|opt|srv|usr\/local|var\/lib)\//) {print $6}' "$p" 2>/dev/null
done | sort -u | head -30 | while IFS= read -r lib; do
	tag medium "mapped library from a deletable location: $lib"
done

if have ss; then
	hdr 'sockets: listening inventory'
	note 'D06: this is an inventory. A port table alone identifies nothing; the image and
	package-owner columns are the finding.'
	ss -Htulpn 2>/dev/null | while IFS= read -r line; do
		pid=$(printf '%s' "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
		if [ -n "$pid" ]; then
			exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || exe='(gone)'
			own=$(pkg_owner "$exe")
			printf '   %s\n      image=%s pkg=%s\n' "$line" "$exe" "${own:-unowned}"
		else
			printf '   %s\n      image=(not attributable without root)\n' "$line"
		fi
	done

	sub 'listeners whose image is tenant-writable'
	ss -Htulpn 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u | while IFS= read -r pid; do
		exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
		iuid=$(stat -c '%u' "/proc/$pid" 2>/dev/null) || iuid=0
		igid=$(stat -c '%g' "/proc/$pid" 2>/dev/null) || igid=0
		reason=$(writable_reason "$exe" "$iuid" "$igid")
		[ -n "$reason" ] && tag medium "listener pid $pid image '$exe': $reason"
	done

	sub 'established sessions to cloudflared 7844 (one vendor, not the family)'
	ss -Htnp state established '( dport = :7844 or sport = :7844 )' 2>/dev/null

	sub 'established TCP sessions by owning image (all destinations)'
	ss -Htnp state established 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort | uniq -c | sort -rn |
	while read -r n pid; do
		exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || exe='(gone)'
		printf '   %4s sessions  pid %-7s %s\n' "$n" "$pid" "$exe"
	done

	sub 'UDP sockets (QUIC, uTP, WireGuard, DHT)'
	ss -Hunp 2>/dev/null
else
	printf '\nnote: ss not found (iproute2)\n'
fi

hdr 'packet and raw sockets (sniffing, not relaying)'
note 'D11: this finds a sniffer. It does not find a proxy, a tunnel or a seedbox.'
if have ss; then
	ss -H -0 -p 2>/dev/null | head -20
fi
if [ -r /proc/net/raw ]; then
	sub 'raw IPv4 sockets'
	awk 'NR>1 {printf "   raw inode %s local %s remote %s\n", $10, $2, $3}' /proc/net/raw 2>/dev/null | head -10
fi

hdr 'network namespaces and the runtime that should own them'
ns_pairs=$(mktemp 2>/dev/null || echo /tmp/.triage-ns.$$)
: >"$ns_pairs"
for n in /proc/[0-9]*/ns/net; do
	pid=${n#/proc/}; pid=${pid%%/*}
	ino=$(readlink "$n" 2>/dev/null) || continue
	printf '%s %s\n' "$ino" "$pid" >>"$ns_pairs"
done
awk '{c[$1]=c[$1] " " $2; n[$1]++} END{for (i in c) printf "   %-18s %3d pids:%s\n", i, n[i], substr(c[i],1,140)}' "$ns_pairs" 2>/dev/null | sort
rm -f "$ns_pairs"

sub 'container runtime sockets (the API that is always there, and has no port)'
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock \
	/run/crio/crio.sock /run/podman/podman.sock /var/run/podman/podman.sock; do
	[ -S "$s" ] || continue
	mode=$(stat -c '%a %U:%G' "$s" 2>/dev/null)
	case $mode in
	6*|7*|*w*) tag high "container runtime socket $s ($mode): write access is root-equivalent" ;;
	*) tag info "container runtime socket $s ($mode)" ;;
	esac
done
for s in /run/user/*/podman/podman.sock; do
	[ -S "$s" ] || continue
	tag medium "rootless podman socket $s (no root, no docker CLI, container control)"
done

sub 'runtime object lists (empty output is the missing comparison, not a clean host)'
if have docker; then docker ps --format '   docker  {{.ID}} {{.Names}}' 2>/dev/null | head -20; fi
if have podman; then podman ps --format '   podman  {{.ID}} {{.Names}}' 2>/dev/null | head -20; fi
if have crictl;  then crictl ps 2>/dev/null | head -10; fi
if have nerdctl; then nerdctl ps 2>/dev/null | head -10; fi
if have lxc-ls;  then lxc-ls -f 2>/dev/null | head -10; fi
if have machinectl; then machinectl list --no-legend 2>/dev/null | head -10; fi
if have systemctl; then
	sub 'scopes and slices (a payload started with systemd-run lives here, not under your unit)'
	systemctl list-units --type=scope --type=slice --all --no-legend --plain 2>/dev/null | head -20
fi

hdr 'persistence surfaces (7 days, with mtime against ctime)'
note 'D05: mtime is attacker-controlled; ctime is not, without a kernel rootkit.'
for d in /etc/cron.d /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
	/etc/cron.monthly /var/spool/cron /var/spool/at /etc/systemd/system /usr/lib/systemd/system \
	/etc/systemd/user /etc/profile.d /etc/rc.local /etc/init.d /etc/ld.so.conf.d /etc/pam.d \
	/etc/supervisor /etc/supervisord.d /etc/at.allow /etc/at.deny; do
	[ -e "$d" ] || continue
	find "$d" -maxdepth 2 -newermt '-7 days' 2>/dev/null
done | sort -u | head -60 | while IFS= read -r f; do
	[ -f "$f" ] || continue
	mt=$(stat -c '%Y' "$f" 2>/dev/null) || continue
	ct=$(stat -c '%Z' "$f" 2>/dev/null) || continue
	delta=$((ct - mt))
	owner=$(pkg_owner "$f")
	case $owner in
	''|'outside packaged prefixes'|'no package db')
		if [ "$delta" -gt 3600 ]; then
			tag medium "persistence file modified: $f (mtime $(date -d "@$mt" '+%F %T') is $((delta / 3600))h older than ctime; not owned by a package, so backdating is plausible)"
		else
			tag low "persistence file modified: $f ($(date -d "@$mt" '+%F %T'))"
		fi
		;;
	*)
		# Archive extraction preserves mtime and sets ctime at install, so a
		# packaged file with mtime before ctime is the normal case.
		tag info "persistence file modified: $f (packaged: $owner)"
		;;
	esac
done

sub 'per-user systemd units (no root needed to install one of these)'
for home in /home/* /root; do
	[ -d "$home/.config/systemd/user" ] || continue
	find "$home/.config/systemd/user" -maxdepth 2 -name '*.service' 2>/dev/null | head -20 | while IFS= read -r f; do
		if [ -n "$(find "$f" -newermt '-7 days' 2>/dev/null)" ]; then
			tag medium "user unit present: $f (modified in the last 7 days)"
		else
			tag info "user unit present: $f"
		fi
	done
done

hdr 'accounts'
if have lastlog; then
	lastlog 2>/dev/null | awk 'NR==1 || /Never logged in/'
fi
sub 'root processes with an image outside the packaged prefixes'
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	uid=$(stat -c '%u' "$p" 2>/dev/null) || continue
	[ "$uid" = 0 ] || continue
	exe=$(readlink "$p/exe" 2>/dev/null) || continue
	case $exe in
	/usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/*) ;;
	*) tag medium "root process pid $pid runs '$exe'" ;;
	esac
done

hdr 'coverage'
printf 'processes seen: %d; images read: %d; processes with no readable image: %d\n' \
	"$SEEN" "$READ_EXE" "$UNREADABLE"
if [ "$ROOT" -eq 0 ] && [ "$UNREADABLE" -gt 0 ]; then
	printf 'NOT A CLEAN RESULT: %d process(es) belong to another uid and were not inspected.\n' "$UNREADABLE"
	printf 'A squatter on a different uid is invisible to this run. Re-run as root.\n'
fi
printf 'executable anonymous mappings seen across all processes: %d\n' "$ANON_TOTAL"
printf 'findings: %d high, %d medium, %d low\n' \
	"$(grep -c '^high$' "$CNT" 2>/dev/null)" \
	"$(grep -c '^medium$' "$CNT" 2>/dev/null)" \
	"$(grep -c '^low$' "$CNT" 2>/dev/null)"

printf '\nInterpretation: a high finding is a reason to inspect that pid now. A medium finding\n'
printf 'is a lead that a legitimate workload can also produce. No finding here is proof of\n'
printf 'cleanliness: see HARDENING.md for the bypasses this script does not close.\n'
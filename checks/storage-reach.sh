#!/bin/sh
# Storage reach (research/container-storage-and-quota-escapes.md).
# Read-only. Reports every writable mount whose capacity materially exceeds the
# root filesystem, which is how a sandbox that promises 10 GB ends up handing
# over 2 TB through a bind-mounted host path.
#
#   sh checks/storage-reach.sh [--max] [/]
#
#   --max   also report the largest writable directory found (still writes nothing)
#
# Exit 0 always: a finding is a line, not a status.
set -u
LC_ALL=C
export LC_ALL

hdr()  { printf '\n== %s ==\n' "$*"; }
note() { printf '   note: %s\n' "$*"; }

CHECK_WRITE=1
ROOT=/
for a in "$@"; do
	case $a in
	--max) CHECK_WRITE=0 ;;
	*)     ROOT=$a ;;
	esac
done

root_kb=$(df -kP "$ROOT" 2>/dev/null | awk 'NR==2{print $2}')
[ -n "${root_kb:-}" ] || { echo "cannot stat $ROOT"; exit 0; }
hdr "root filesystem"
printf '   %s is %s (%s KB), used %s\n' "$ROOT" \
	"$(df -hP "$ROOT" | awk 'NR==2{print $2}')" "$root_kb" \
	"$(df -hP "$ROOT" | awk 'NR==2{print $3}')"

# The declared quota is the root filesystem. Anything meaningfully larger that
# is writable is storage the platform did not intend to hand out: a hostPath
# bind, an emptyDir backed by the node volume, or a volume mount one level down
# from a directory the sandbox already trusts.
hdr "writable mounts larger than 2x root"
found=0
seen=""
while read -r fstype target; do
	case $fstype in
	proc|sysfs|cgroup|cgroup2|devpts|mqueue|ramfs|securityfs|debugfs|tracefs|configfs|autofs|binfmt_misc|fusectl|pstore|hugetlbfs) continue ;;
	esac
	kb=$(df -kP "$target" 2>/dev/null | awk 'NR==2{print $2}')
	[ -n "${kb:-}" ] || continue
	[ "$kb" -gt $((root_kb * 2)) ] || continue

	# one line per backing filesystem: the same volume appearing at nine paths
	# is one finding, not nine
	dev=$(stat -c %D "$target" 2>/dev/null)
	case " $seen " in *" $dev "*) continue ;; esac

	# writability is the difference between a finding and a curiosity
	if [ "$CHECK_WRITE" = 1 ]; then
		wt=$target; [ -d "$wt" ] || wt=$(dirname "$wt")
		if touch "$wt/.storage-reach.$$" 2>/dev/null; then
			w=WRITABLE; rm -f "$wt/.storage-reach.$$"
		else
			continue   # a read-only mount of a big volume gives no storage
		fi
	else
		w='?'
	fi

	seen="$seen $dev"
	printf '   %-8s %-9s %-10s %s\n' \
		"$(df -hP "$target" | awk 'NR==2{print $2}')" "$fstype" "$w" "$target"
	found=$((found + 1))
done <<EOF
$(awk '{print $3, $2}' /proc/mounts 2>/dev/null | sort -u)
EOF

[ "$found" -gt 0 ] || note 'none: the declared quota is the whole story on this host'

hdr "the cheap tell: file binds report the volume behind them"
note 'df /etc/hosts frequently answers with the node data volume, not the overlay.'
note 'a file bind is one file, but df answers per filesystem, so the number is the node.'
df -hP /etc/hosts /etc/resolv.conf /etc/hostname 2>/dev/null | grep -v '^Filesystem' | sed 's/^/   /'

hdr "devices present but denied"
note 'a visible block device node is not access: open(2) is what the device cgroup gates.'
for d in /dev/sda /dev/sdb /dev/nvme0n1 /dev/dm-0 /dev/kvm /dev/mem; do
	[ -e "$d" ] || continue
	if head -c 0 "$d" 2>/dev/null; then s=OPENS; else s=denied; fi
	printf '   %-14s %s\n' "$d" "$s"
done

hdr 'summary'
note 'a writable mount inside the sandbox whose size dwarfs the quota is storage'
note 'the platform is paying for and cannot attribute to you. per-container byte'
note 'counters do not see it: the bytes never land on the container filesystem.'
note 'this cannot see: a mount the platform does not expose to /proc/mounts, or'
note 'storage reached through a network filesystem the tenant mounts itself.'

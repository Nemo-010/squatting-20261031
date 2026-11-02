#!/bin/sh
# Notebook workspace integrity (research/sandbox-as-a-service-squatting.md).
# Read-only. Finds files in a notebook tree that post-date the sandbox, and
# executables that belong to no package. This is the cheapest detection in that
# file and the only one there that fires on intent rather than on traffic.
#
#   sh checks/workspace-integrity.sh [/path/to/notebook/tree ...]
#
# Exit 0 always: a finding is a line, not a status. It is meant to be driven by
# the poller the platform already runs (300 s in the case this came from):
#
#   */5 * * * * sh /usr/local/bin/workspace-integrity.sh /workspace /data
set -u
LC_ALL=C
export LC_ALL

hdr()  { printf '\n== %s ==\n' "$*"; }
note() { printf '   note: %s\n' "$*"; }

# A file stamped at pod creation is the cheapest boot marker worth trusting: the
# container runtime writes it before the workload starts and the workload cannot
# backdate it without time control on the node.
BOOT=/dev/termination-log
[ -e "$BOOT" ] || BOOT=/etc/hostname
note "boot marker: $BOOT"

# Which package database is actually usable matters: without one, "unpackaged"
# is not a finding, it is a missing prerequisite. Probe once, then say so.
PKGDB=
for db in dpkg rpm pacman apk; do
	command -v "$db" >/dev/null 2>&1 || continue
	case $db in
	dpkg)   dpkg -l >/dev/null 2>&1   && { PKGDB=dpkg;   break; } ;;
	rpm)    rpm -qa >/dev/null 2>&1   && { PKGDB=rpm;    break; } ;;
	pacman) pacman -Q >/dev/null 2>&1 && { PKGDB=pacman; break; } ;;
	apk)    apk info >/dev/null 2>&1  && { PKGDB=apk;    break; } ;;
	esac
done
[ -n "$PKGDB" ] && note "package database: $PKGDB" || note 'package database: none usable — ownership will read "unknown"'

# Package ownership is the only name-independent identity available. A binary
# renamed sshd still belongs to whatever installed it, and nothing in the image
# does.
own() {
	case $PKGDB in
	dpkg)   dpkg -S "$1" >/dev/null 2>&1 && echo packaged || echo unpackaged ;;
	rpm)    rpm -qf "$1" >/dev/null 2>&1 && echo packaged || echo unpackaged ;;
	pacman) pacman -Qo "$1" >/dev/null 2>&1 && echo packaged || echo unpackaged ;;
	apk)    apk info --who-owns "$1" >/dev/null 2>&1 && echo packaged || echo unpackaged ;;
	*)      echo unknown ;;
	esac
}

[ $# -gt 0 ] || set -- /workspace /data /home

for tree in "$@"; do
	[ -d "$tree" ] || { hdr "$tree"; note 'not a directory, skipped'; continue; }

	hdr "$tree — files newer than the sandbox"
	find "$tree" -xdev -type f -newer "$BOOT" \
	     -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%m\t%s\t%p\n' 2>/dev/null |
	while IFS=$(printf '\t') read -r ts mode size path; do
		ts=${ts%%.*}
		# 1,3,5,7 in the owner digit position means the owner can execute it.
		case $mode in
		*1??|*3??|*5??|*7??|???1??) tag=EXEC ;;
		*)                          tag=file ;;
		esac
		printf '   %-4s %-10s %s %9s %s\n' "$tag" "$(own "$path")" "$ts" "$size" "$path"
	done

	hdr "$tree — executables that belong to no package"
	if [ -z "$PKGDB" ]; then
		note 'skipped: no usable package database, so every binary would read as unowned'
	else
		find "$tree" -xdev -type f -perm -u+x -printf '%m\t%s\t%p\n' 2>/dev/null |
		while IFS=$(printf '\t') read -r mode size path; do
			[ "$(own "$path")" = unpackaged ] || continue
			printf '   %s %9s %s\n' "$mode" "$size" "$path"
		done
	fi
done

hdr 'summary'
note 'a file that post-dates the sandbox and is executable has no legitimate'
note 'reading in a notebook tree. A process hider, a relay binary or a'
note 'bootstrap blob all land here; a dataset or an output file does not.'
note 'this cannot see: a payload carved into a packaged binary, a memfd,'
note 'a renamed packaged binary, or anything outside the trees it was given.'

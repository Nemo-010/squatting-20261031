# Detecting proxyjacking, tunnel squatting and torrent relays with auditd + /proc on one Linux host

> **Hardened 2026-11-01 — adversarial review: D17, D18, D19, D20, D21, D22, D23, D24.** The rule file now covers `sendto,sendmsg` (unconnected UDP), `execveat`, 32-bit twins, filtered `setns`, `mount`, and io_uring `connect,sendmsg,openat,openat2`. `clone3` flags cannot be filtered by audit and a blanket rule floods, so `checks/probes.bt` reads them instead. `TUNSETIFF` is no longer called the highest-value rule: WireGuard never calls it.
> The corrected checks and the residual bypasses are in
> [HARDENING.md](../HARDENING.md). Read that before relying on the commands below.

*What the kernel audit subsystem and procfs can prove about a server being used as a proxy, VPN or relay endpoint — no SIEM, no agent, no commercial product. Numbers carry their source; unconfirmed items are marked **unverified** or collected in the last section.*

---

## Summary

- **The daemon ships everywhere, under two package names**: `auditd` on Debian/Ubuntu ([Debian](https://packages.debian.org/bookworm/auditd), [Ubuntu](https://packages.ubuntu.com/noble/auditd)), `audit` on Fedora/RHEL/AL2023 ([Fedora](https://packages.fedoraproject.org/pkgs/audit/audit/fedora-43.html), [AL2023](https://docs.aws.amazon.com/linux/al2023/release-notes/all-packages-AL2023.12.html)).
- **`-F path=` needs the inode to exist when the rule loads.** `/etc/ld.so.preload` is optional ([ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html)), so `-w /etc/ld.so.preload -p wa` fails on a clean host; use `-F dir=/etc -F perm=wa`, a recursive subtree that stops at mount points unless `-q` ([audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)).
- **The best tunnel signal is the ioctl request word.** `TUNSETIFF` is `_IOW('T', 202, int)` = `0x400454ca` ([if_tun.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/if_tun.h)), and `-F a1=0x400454ca` is legal because `a0..a3` parse base-0 ([libaudit.c](https://raw.githubusercontent.com/linux-audit/audit-userspace/master/lib/libaudit.c)).
- **`socket()` has no `saddr_fam`** (it is filled only for bind/connect/sendto), so family must be matched as `-F a0=2` / `-F a0=10` ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html), [bits/socket.h](https://raw.githubusercontent.com/bminor/glibc/master/sysdeps/unix/sysv/linux/bits/socket.h)).
- **io_uring rules need kernel ≥ 5.16 and audit userspace ≥ 3.1**; Debian 12 (3.0.9) and Ubuntu 22.04 (3.0.7) cannot express them at all ([ChangeLog](https://raw.githubusercontent.com/linux-audit/audit-userspace/master/ChangeLog), [v5.15](https://raw.githubusercontent.com/torvalds/linux/v5.15/include/uapi/linux/audit.h) vs [v5.16](https://raw.githubusercontent.com/torvalds/linux/v5.16/include/uapi/linux/audit.h)).
- **`-F exe=` allows only `=`/`!=` and may appear once per rule**; string syscall arguments cannot be matched at all, so path detections are watches, not argv matches ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)).
- **Alerting without a SIEM**: an audisp plugin (`active`/`path`/`type`/`args`/`format`, max 2 args, [auditd-plugins(5)](https://man7.org/linux/man-pages/man5/auditd-plugins.5.html)), rsyslog `omprog` fed by the shipped `audisp-syslog` ([omprog](https://www.rsyslog.com/doc/configuration/modules/omprog.html)), or cron + `ausearch --start recent`, where *recent* is exactly 10 minutes ([ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html)).
- **Silent tail-drop is the failure mode that makes dashboards lie**: backlog defaults to 64 ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)), upstream sets `-b 8192` ([10-base-config.rules](https://github.com/linux-audit/audit-userspace/blob/master/rules/10-base-config.rules)), and `auditctl -s` → `lost` is the only honest counter.

---

## 1. What ships with the distro

| Distro | audit package / userspace | Kernel | `io_uring` filter |
|---|---|---|---|
| Debian 12 ([pkg](https://packages.debian.org/bookworm/auditd), [kernel](https://packages.debian.org/bookworm/linux-image-amd64)) | `auditd` 1:3.0.9-1 | 6.1.190-1 | **no** — userspace < 3.1 |
| Ubuntu 22.04 ([pkg](https://packages.ubuntu.com/jammy/auditd), [kernel](https://packages.ubuntu.com/jammy/linux-image-generic)) | `auditd` 1:3.0.7-1build1 | 5.15.0-1007 | **no** — both too old |
| Ubuntu 24.04 ([pkg](https://packages.ubuntu.com/noble/auditd), [kernel](https://packages.ubuntu.com/noble/linux-image-generic)) | `auditd` 1:3.1.2-2.1build1 | 6.8.0-147 | yes |
| RHEL 9.2 ([kernel](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/9.2_release_notes/index)) | `audit` | 5.14.0-284.11.1 | **unverified** (backport?) |
| AL2023 ([kernel](https://docs.aws.amazon.com/linux/al2023/release-notes/relnotes-2023.7.20250623.md)) | `audit` | 6.1 default | likely yes (**unverified**) |
| Fedora 43 ([pkg](https://packages.fedoraproject.org/pkgs/audit/audit/fedora-43.html)) | `audit` 4.2.1-1 | ≥ 6.1 | yes |

Debian's `auditd` package alone provides `/sbin/auditctl`, `auditd`, `augenrules`, `ausearch`, `aureport`, `audisp-syslog`, plus `/etc/audit/auditd.conf`, `/etc/audit/plugins.d/syslog.conf` and `/etc/audit/rules.d/audit.rules` ([file list](https://packages.debian.org/bookworm/amd64/auditd/filelist)).

Rules go in `/etc/audit/rules.d/*.rules` and `augenrules --load` compiles them into `/etc/audit/audit.rules`, regenerated at every service start ([RHEL 9 §12.7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)). On RHEL use `service auditd <action>` rather than `systemctl`, so `auid` is recorded correctly (same doc, §12.4).

## 2. Rule-syntax facts that decide whether the rules work

- **`-F path=<file>` requires the inode at load time** — the kernel installs an fsnotify inode mark ([kernel/audit_watch.c](https://raw.githubusercontent.com/torvalds/linux/master/kernel/audit_watch.c)), so a missing file returns ENOENT and the rule never loads.
- **`-F dir=<dir>`** is recursive to the bottom of the tree but stops at mount points unless `-q mount-point,subtree` is added ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)).
- **`-F exe=`**: `=`/`!=` only, once per rule ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)).
- **`a0..a3` are numeric only**; string arguments are pointers and cannot be matched. Hex works because parsing is `strtoul(v, NULL, 0)` ([libaudit.c](https://raw.githubusercontent.com/linux-audit/audit-userspace/master/lib/libaudit.c)).
- **`saddr_fam`** comes from `__audit_sockaddr`, i.e. bind/connect/sendto ([kernel/auditsc.c](https://raw.githubusercontent.com/torvalds/linux/master/kernel/auditsc.c)); AF numbers are 2 and 10 ([bits/socket.h](https://raw.githubusercontent.com/bminor/glibc/master/sysdeps/unix/sysv/linux/bits/socket.h)).
- **`arch` must precede `-S`**, and `perm=` wants one too or every syscall is evaluated ([audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)).
- **Keys cap at 31 bytes** ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)); longer keys silently stop matching `ausearch -k`.

## 3. A rule set aimed at proxy / tunnel / torrent nodes

`/etc/audit/rules.d/50-proxyjack.rules`:

```
# base (same as upstream 10-base-config.rules)
-D
-b 8192
--backlog_wait_time 60000
-f 1

# 1. socket() carries no saddr_fam: match the family in a0
-a always,exit -F arch=b64 -S socket -F a0=2  -k net_socket
-a always,exit -F arch=b64 -S socket -F a0=10 -k net_socket

# 2. connections, both families
-a always,exit -F arch=b64 -S connect,bind -F saddr_fam=2  -k net_conn
-a always,exit -F arch=b64 -S connect,bind -F saddr_fam=10 -k net_conn
-a always,exit -F arch=b64 -S accept,connect -k net_conn_all

# 3. tunnel/VPN interface: ioctl(fd, TUNSETIFF, &ifr)
-a always,exit -F arch=b64 -S ioctl -F a1=0x400454ca -k tun_ioctl

# 4. new network namespace (containers, VPN in a netns)
-a always,exit -F arch=b64 -S clone -F a0&0x40000000 -k ns_net
-a always,exit -F arch=b64 -S unshare,setns -k ns_change

# 5. anonymous-memory payloads (fileless proxy binaries)
-a always,exit -F arch=b64 -S memfd_create -k memfd

# 6. preload surface; /etc/ld.so.preload often does not exist
-a always,exit -F arch=b64 -F dir=/etc -F perm=wa -k etc_write

# 7. persistence
-a always,exit -F arch=b64 -F path=/etc/cron.d -F perm=wa -k persist
-a always,exit -F arch=b64 -F path=/var/spool/cron -F perm=wa -k persist
-a always,exit -F arch=b64 -F path=/etc/systemd/system -F perm=wa -k persist

# 8. module load (WireGuard-as-module, rootkits)
-a always,exit -F arch=b64 -S init_module,finit_module -k kmod

# 9. io_uring path (kernel >= 5.16, audit >= 3.1, no arch field)
-a always,io_uring -S openat,openat2 -F key=access_uring

# 10. immutable until reboot
-e 2
```

Why each one:

- Rules 1 and 2 are separate: `saddr_fam` never matches `socket()`, and one rule cannot OR two `a0` values.
- Rule 3 is the highest-value rule for tunnel squatting. `TUNSETIFF` = `0x400454ca` ([if_tun.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/if_tun.h)) and requires `CAP_NET_ADMIN` (bit 12, [capability.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/capability.h)).
- Rule 4 follows upstream `41-containers.rules` (`-F a0&0x7C020000` on clone) narrowed to `CLONE_NEWNET` = `0x40000000` (`CLONE_NEWUSER` = `0x10000000`) ([sched.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/sched.h)).
- Rule 5 catches `memfd_create()`. The follow-on `execveat()` cannot be matched: its flags live in `a4`
  and auditd exposes only `a0`..`a3` (`audit_name_to_field("a4")` returns -1), so the `/proc/*/exe`
  sweep for `/memfd:` is the practical substitute rather than a second rule.
- Rule 6 replaces the broken `/etc/ld.so.preload` watch and is loud: package upgrades rewrite much of `/etc`. Check `test -e /etc/ld.so.preload` first and, if present, switch to `-F path=/etc/ld.so.preload -F perm=wa`.
- Rule 9 takes no `arch`: "Io_uring rules do not take an arch field" ([audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html)). On older kernels it fails to load — confirm with `auditctl -l` afterwards.
- Rule 10 makes the set immutable until reboot ([99-finalize.rules](https://github.com/linux-audit/audit-userspace/blob/master/rules/99-finalize.rules) ships it commented out); without it, root can simply run `auditctl -e 0`.
- Add the `arch=b32` twins on any host running 32-bit software: a 32-bit `socket()` has a different syscall number.
- **Jupyter.** An abused notebook needs no special rule: the kernel is a child of `jupyter-lab`/`jupyter-notebook` and the payload is a `bash`/`curl` child of the kernel, so `net_socket`/`tun_ioctl` fire however the shell was reached; attribute later through `/proc/<pid>/ppid`.

## 4. Tuning so the interesting event is not dropped

| Knob | Default | Why it matters | Source |
|---|---|---|---|
| kernel backlog | 64 | overflow → silent `lost` | [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) |
| `-b 8192` | upstream | survives a torrent client's connect storm | [10-base-config.rules](https://github.com/linux-audit/audit-userspace/blob/master/rules/10-base-config.rules) |
| `--backlog_wait_time` | 60·HZ | wait instead of drop | [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) |
| `-r` rate limit | 0 (off) | non-zero *drops* and consults the failure flag | [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) |
| `-f` failure mode | 1 = printk | `2` = panic; only for appliances | [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) |
| `q_depth` | 2000 | auditd's queue to plugins | [auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html) |
| `overflow_action` | syslog | `suspend`/`single`/`halt` are the loud ones | [auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html) |
| `max_log_file_action` | rotate | `keep_logs` never deletes; `exec` runs a parameterless script | [auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html) |
| `flush`/`freq` | incremental_async / 50 | Red Hat recommends `freq = 100` | [shipped conf](https://raw.githubusercontent.com/linux-audit/audit-userspace/master/init.d/auditd.conf), [RHEL 9 §12.3](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) |

The `exec` contract is the most misconfigured line in the file: "You cannot pass parameters to the script", logging stops while it runs, and "The script MUST delete or rename /var/log/audit/audit.log or when logging resumes, it will retrigger executing the script" ([auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html)). The man page writes `auditdctl --signal resume`; what ships is `auditctl --signal resume` ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)) — a doc slip.

Check state with `auditctl -l` (rules, one per line) and `auditctl -s` (`enabled`, `failure`, `pid`, `rate_limit`, `backlog_limit`, `lost`, `backlog`); `pid 0` means auditd is not running ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)).

## 5. Alerting with no SIEM

**A — audisp plugin (lowest latency).** `/etc/audit/plugins.d/proxyalert.conf`:

```
active = yes
path = /usr/local/sbin/audit-alert.sh
type = always
args = proxy
format = string
```

Only `active`, `path`, `type`, `args` (max 2) and `format` are valid; the file must end in `.conf`; plugins run as root and restart up to `max_restarts` times ([auditd-plugins(5)](https://man7.org/linux/man-pages/man5/auditd-plugins.5.html)). The plugin reads one record per line on stdin:

```sh
#!/bin/sh
# /usr/local/sbin/audit-alert.sh, 0750 root:root
while IFS= read -r line; do
  case $line in
    *'key="net_socket'*|*'key="tun_ioctl'*|*'key="memfd'*|*'key="ns_net'*)
      printf '%s %s\n' "$(date -u +%FT%TZ)" "$line" >> /var/log/proxy-alert.log
      logger -t audit-alert -- "PROXY: $line" ;;
  esac
done
```

`logger` is util-linux, effectively universal. Keep the plugin fast: it holds auditd's queue (2000 events default).

**B — the shipped syslog plugin plus rsyslog `omprog`.** Debian installs `/sbin/audisp-syslog` and `/etc/audit/plugins.d/syslog.conf` ([file list](https://packages.debian.org/bookworm/amd64/auditd/filelist)); the plugin wraps events to syslog with facility/level/`interpret` on the `args` line ([audisp-syslog(8)](https://man.archlinux.org/man/audisp-syslog.8.en)). In `rsyslog.conf`:

```
module(load="omprog")
if ($msg contains 'key="tun_ioctl') then {
    action(type="omprog" binary="/usr/local/sbin/audit-alert.sh"
           template="RSYSLOG_TraditionalFileFormat")
}
```

`omprog` feeds stdin, restarts the program if it dies, and inherits the rsyslog service sandbox ([omprog](https://www.rsyslog.com/doc/configuration/modules/omprog.html)). Match record text, not facility — the plugin's default facility is **unverified**.

**C — cron plus `ausearch`.** `--start recent` means 10 minutes ago ([ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html)), so a 5-minute timer overlaps safely:

```sh
#!/bin/sh
# /usr/local/sbin/audit-sweep.sh ; cron: */5 * * * * root ...
for k in net_socket net_conn tun_ioctl ns_net memfd_exec persist etc_write; do
  ausearch --start recent -m SYSCALL -k "$k" -i 2>/dev/null
done | logger -t audit-sweep
lost=$(auditctl -s | awk '$1=="lost"{print $2}')
[ "${lost:-0}" -gt 0 ] && logger -t audit-sweep "WARNING: ${lost} audit events lost"
```

## 6. /proc as an independent second opinion

auditd says what the kernel saw; procfs says what is running now.

```sh
# 6.1 binaries executing from writable or anonymous memory
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue      # ENOENT for kernel threads
  case $exe in
    /tmp/*|/var/tmp/*|/dev/shm/*|*/run/*|*'(deleted)'|/memfd:*)
      printf '%-7s %-45s %s\n' "${p#/proc/}" "$exe" "$(tr '\0' ' ' <"$p/cmdline")" ;;
  esac
done

# 6.2 CAP_NET_ADMIN (bit 12) in CapEff
for p in /proc/[0-9]*; do
  cap=$(awk '/^CapEff:/{print $2}' "$p/status" 2>/dev/null) || continue
  [ -n "$cap" ] && [ $(( 0x$cap >> 12 & 1 )) -eq 1 ] && echo "${p#/proc/} holds CAP_NET_ADMIN"
done

# 6.3 network namespaces in use
for n in /proc/[0-9]*/ns/net; do readlink "$n"; done 2>/dev/null | sort -u

# 6.4 persistence and the preload classic
[ -s /etc/ld.so.preload ] && { echo "NON-EMPTY /etc/ld.so.preload"; cat /etc/ld.so.preload; }
ls -la /etc/cron.d /var/spool/cron /etc/systemd/system /etc/rc.local 2>/dev/null
ls -la /home/*/.config/systemd/user 2>/dev/null
```

`CapEff` is the effective capability mask in hex ([proc_pid_status(5)](https://man7.org/linux/man-pages/man7/proc_pid_status.5.html)) and `CAP_NET_ADMIN` is 12 ([capability.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/capability.h)).

Socket inode → pid → 4-tuple, stdlib only, run as root:

```python
#!/usr/bin/env python3
import glob, os
inodes = {}
for f in glob.glob('/proc/[0-9]*/fd/*'):
    try:
        t = os.readlink(f)
    except OSError:
        continue
    if t.startswith('socket:[') and t.endswith(']'):
        inodes.setdefault(t[8:-1], []).append(f.split('/')[2])
for proto in ('tcp', 'tcp6', 'udp', 'udp6'):
    try:
        rows = open('/proc/net/' + proto).read().splitlines()[1:]
    except OSError:
        continue
    for line in rows:
        p = line.split()
        if len(p) > 9 and p[9] in inodes:
            print(proto, p[1], p[2], p[3], p[9], ','.join(inodes[p[9]]))
```

The tenth field of `/proc/net/tcp` is the socket inode, and addresses and ports are hex `ADDR:PORT` ([proc_net_tcp.rst](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/networking/proc_net_tcp.rst)). Cloudflare Tunnel agents dial TCP/UDP 7844 ([Cloudflare docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall)), so a long-lived socket to that port is a flow-side tell.

For short-lived processes, **pspy** polls procfs and triggers on inotify; `-i` defaults to **100** ms, `-p` is on and `-f` off by default, `-r`/`-d` add recursive/non-recursive watches ([cmd/root.go](https://raw.githubusercontent.com/DominicBreuker/pspy/master/cmd/root.go), [README](https://github.com/DominicBreuker/pspy)). It is unprivileged by design, so it gives no socket-to-process attribution.

## 7. What auditd will not see

- **Dropped events.** Backlog 64 and rate limit 0 mean a connect storm overflows the queue. If `lost` is non-zero, "we saw nothing" is void ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)).
- **io_uring on kernels < 5.16.** `openat` through io_uring bypasses the exit filter; the dedicated filter appears at v5.16 ([v5.15](https://raw.githubusercontent.com/torvalds/linux/v5.15/include/uapi/linux/audit.h) lacks `AUDIT_FILTER_URING_EXIT`, [v5.16](https://raw.githubusercontent.com/torvalds/linux/v5.16/include/uapi/linux/audit.h) has it).
- **Containers.** Containerised proxies are audited by the host kernel but arrive with the host pid and usually an unset loginuid; attributing them needs cgroup/netns context. Exact semantics are **unverified**.
- **Tampering.** `-e 0` disables auditing until re-enabled; only `-e 2` stops it, and only until reboot ([auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)). Anyone able to write `/var/log/audit/audit.log` wins, which is what `log_group` and `-f 2` address.
- **Renamed binaries.** `exe=` matches a path, not an inode or a hash, so a `cp` defeats it.

For reporting, the behaviour maps to ATT&CK T1496.002 (Bandwidth Hijacking) and T1090 (Proxy) ([T1496.002](https://attack.mitre.org/techniques/T1496/002/), [T1090](https://attack.mitre.org/techniques/T1090/)).

## 8. Triage commands

```sh
aureport --start today --summary            # totals of the main report
aureport --start today --key --summary      # which keys fired
ausearch --start recent -k tun_ioctl -i
ausearch --start this-week -k net_socket -m SYSCALL -i
ausearch --start today -m SYSCALL -sc execve -i | grep -E 'exe="/(tmp|dev/shm|var/tmp)/'
```

`--start` accepts `now`, `recent` (10 minutes), `this-hour`, `boot`, `today`, `yesterday`, `this-week`, `week-ago`, `this-month`, `this-year`; `-m`, `-sc` and `-k` compose freely ([ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html)). `--summary` totals the elements of the main report ([aureport(8)](https://man7.org/linux/man-pages/man8/aureport.8.html)).

## Sources

audit.rules(7) <https://man7.org/linux/man-pages/man7/audit.rules.7.html> · auditctl(8) <https://man7.org/linux/man-pages/man8/auditctl.8.html> · auditd.conf(5) <https://man7.org/linux/man-pages/man5/auditd.conf.5.html> · auditd-plugins(5) <https://man7.org/linux/man-pages/man5/auditd-plugins.5.html> · ausearch(8) <https://man7.org/linux/man-pages/man8/ausearch.8.html> · aureport(8) <https://man7.org/linux/man-pages/man8/aureport.8.html> · audisp-syslog(8) <https://man.archlinux.org/man/audisp-syslog.8.en> · proc_pid_status(5) <https://man7.org/linux/man-pages/man7/proc_pid_status.5.html> · ld.so(8) <https://man7.org/linux/man-pages/man8/ld.so.8.html>

Upstream rules <https://github.com/linux-audit/audit-userspace/tree/master/rules> (10-base-config, 41-containers, 71-networking, 99-finalize) · ChangeLog <https://raw.githubusercontent.com/linux-audit/audit-userspace/master/ChangeLog> · libaudit.c <https://raw.githubusercontent.com/linux-audit/audit-userspace/master/lib/libaudit.c> · init.d/auditd.conf <https://raw.githubusercontent.com/linux-audit/audit-userspace/master/init.d/auditd.conf>

Kernel: audit_watch.c <https://raw.githubusercontent.com/torvalds/linux/master/kernel/audit_watch.c> · auditsc.c <https://raw.githubusercontent.com/torvalds/linux/master/kernel/auditsc.c> · if_tun.h <https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/if_tun.h> · capability.h <https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/capability.h> · sched.h <https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/sched.h> · fcntl.h <https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/fcntl.h> · audit.h v5.15 <https://raw.githubusercontent.com/torvalds/linux/v5.15/include/uapi/linux/audit.h> · audit.h v5.16 <https://raw.githubusercontent.com/torvalds/linux/v5.16/include/uapi/linux/audit.h> · proc_net_tcp.rst <https://raw.githubusercontent.com/torvalds/linux/master/Documentation/networking/proc_net_tcp.rst> · glibc bits/socket.h <https://raw.githubusercontent.com/bminor/glibc/master/sysdeps/unix/sysv/linux/bits/socket.h>

Distros: Debian auditd <https://packages.debian.org/bookworm/auditd> + <https://packages.debian.org/bookworm/amd64/auditd/filelist> · Debian kernel <https://packages.debian.org/bookworm/linux-image-amd64> · Ubuntu jammy <https://packages.ubuntu.com/jammy/auditd> <https://packages.ubuntu.com/jammy/linux-image-generic> · Ubuntu noble <https://packages.ubuntu.com/noble/auditd> <https://packages.ubuntu.com/noble/linux-image-generic> · RHEL 9.2 <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/9.2_release_notes/index> · RHEL 9 auditing <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening> · AL2023 packages <https://docs.aws.amazon.com/linux/al2023/release-notes/all-packages-AL2023.12.html> · AL2023 kernel <https://docs.aws.amazon.com/linux/al2023/release-notes/relnotes-2023.7.20250623.md> · Fedora audit <https://packages.fedoraproject.org/pkgs/audit/audit/fedora-43.html>

Other: Cloudflare Tunnel egress port 7844 TCP+UDP <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall> · pspy <https://github.com/DominicBreuker/pspy> and <https://raw.githubusercontent.com/DominicBreuker/pspy/master/cmd/root.go> · rsyslog omprog <https://www.rsyslog.com/doc/configuration/modules/omprog.html> · ATT&CK T1496.002 <https://attack.mitre.org/techniques/T1496/002/> · ATT&CK T1090 <https://attack.mitre.org/techniques/T1090/>

## What I could not verify

1. **RHEL 9 io_uring audit support.** The 5.14 base predates `AUDIT_FILTER_URING_EXIT`, and I found no release note confirming a backport. Treat rule 9 as unsupported there until `auditctl -l` shows it loaded.
2. **AL2023 and Fedora 43 io_uring support.** Kernels are new enough; I did not test a rule load on either.
3. **`audisp-syslog`'s default facility.** The man page lists valid facilities but not the shipped default, so the rsyslog example matches on record text instead.
4. **Container / audit-namespace semantics.** Whether a container with its own audit namespace can be kept from influencing host records, and how `auid` behaves for `docker exec` children, I could not confirm.
5. **Unprivileged `/proc/<pid>/fd` access.** Socket-inode attribution is gated by the ptrace access-mode check; the exact capability boundary is unverified here.
6. **`/etc/ld.so.preload` on stock images.** The man page calls the file optional; I did not enumerate distro manifests — always `test -e` first.
7. **`-F dir=` across a bind mount added after the rule loaded.** `-q` is documented, but the exact fsnotify behaviour in that sequence is unverified.
8. **`--backlog_wait_time` upper bound.** The man page says "less than 10 times the default value" without restating it (60·HZ); behaviour at the boundary is unverified.

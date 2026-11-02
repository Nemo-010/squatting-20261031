# Rootkits that hide the squat: how a host is made to lie to its own inspector

> **Hardened 2026-11-01 — adversarial review: D04, D09, D10, D22, D23.** `/etc/ld.so.preload` is parsed here the way glibc parses it (`#` blanks to end of line, split on space and colon), a per-user `LD_PRELOAD` is added from `/proc/<pid>/environ`, and the netlink-vs-procfs check is a per-inode diff rather than a count. The two views are not independent: both read the same kernel socket table, so the check is a hook indicator, not truth.
> The corrected checks and the residual bypasses are in
> [HARDENING.md](../HARDENING.md). Read that before relying on the commands below.

Scope: the userland and kernel hook planes a squatted host uses to erase its own proxy / miner /
botnet footprint from `ps`, `ss`, `netstat`, `ls` and `cat /proc/net/tcp`, and the free cross-view checks that
defeat them. Specimens: P2PInfect's `libs.so.1`, Kinsing's `libsystem.so` (a modified **beurk**),
Hildegard's `X86_64.so`, **libprocesshider**, the LKM **Diamorphine**. MITRE files this as **T1014
Rootkit** / **T1574.006**, analytic **AN1062**: "abnormal loading of kernel modules, direct tampering
with /dev, /proc, or LD_PRELOAD behaviors hiding processes or files"
(<https://attack.mitre.org/techniques/T1014/>, <https://attack.mitre.org/detectionstrategies/DET0377>).

## Summary

- Only three things are ever falsified: **directory listings** (`readdir`/`getdents64`), **file
  metadata** (`stat`/`lstat`/`access`), and the **text of `/proc/net/tcp`/`tcp6`**. Nothing hooks the
  socket table, only the file that renders it.
- **`/etc/ld.so.preload` is the load-bearing file.** glibc: two ways to preload, "via environment
  variable and via the file `/etc/ld.so.preload`. The latter **can also be used when security is
  enabled**" (<https://github.com/bminor/glibc/blob/master/elf/rtld.c>). Env `LD_PRELOAD` is stripped
  in secure-execution mode; the file is not. Kinsing, Hildegard and beurk all write the file.
- Precedence: `LD_PRELOAD` (1), `ld.so --preload` (2), `/etc/ld.so.preload` (3) —
  <https://man7.org/linux/man-pages/man8/ld.so.8.html>. Cheapest detection is the file read.
- **`ss` is not `netstat`.** `netstat` reads `/proc/net/tcp` (`_PATH_PROCNET_TCP`, `lib/pathnames.h:15`,
  used at `netstat.c:1229`); `ss` opens `NETLINK_SOCK_DIAG` (=4) / `SOCK_DIAG_BY_FAMILY` (=20), falling
  back to procfs only on error — and `PROC_NET_TCP` forces the procfs branch. Note it takes a
  **path**, not a flag: `generic_proc_open()` does `fopen(getenv(env))`, so `PROC_NET_TCP=1` tries to
  open a file named `1` and yields nothing. Use `PROC_NET_TCP=/proc/net/tcp`.
- **`ss -p` is the weak link even over netlink.** `user_ent_hash_build()` walks `opendir("/proc")` +
  `readdir()` + `readlink("/proc/PID/fd/N")` to map `socket:[inode]` → pid, so a `readdir` hook hides
  the *owner* while netlink still shows the *socket*
  (<https://github.com/iproute2/iproute2/blob/main/misc/ss.c>).
- `/proc/PID/maps` is the tell: **five** mapped segments per ordinary `.so` (measured), and an object
  unlinked after load becomes `path (deleted)`
  (<https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html>). A preload cannot hide from a reader
  it was never injected into. Diamorphine in turn hooks only `__NR_getdents`, `__NR_getdents64`,
  `__NR_kill` — listings, not `stat` — so an integer PID sweep still finds its processes.
- Measured false-positive trap: `readdir("/proc")` returned **3–5** numeric entries while **23**
  `/proc/<pid>` dirs were reachable by direct `stat`. That divergence is not proof of a rootkit;
  `hidepid=2` (<https://man7.org/linux/man-pages/man5/proc.5.html>) is the ordinary cause.
- Everything below is zero-cost: `lsattr`, `cat`, `ldd`, `ss`, `awk` over `/proc/*/maps`, plus
  `unhide-linux` 20240510-2 and `rkhunter` 1.4.6-14 if you want a packaged checker.

---

## 1. Three hook planes

| Plane | Mechanism | Falsified | Survives |
|---|---|---|---|
| libc, per-user | `LD_PRELOAD` from `~/.bashrc` | `fopen`/`open` of `/proc/net/tcp`, `readdir` of `/proc`, `lstat`/`unlink` by name | processes that did not inherit the var; netlink; raw sockets |
| libc, system-wide | `/etc/ld.so.preload` | same, for **every** process incl. setuid | a reader outside the loader's reach |
| kernel | LKM patching `sys_call_table` | `getdents`/`getdents64`, `kill` | `stat`, `statx`, direct `open`, netlink, eBPF |

The lie is always at the **libc boundary**, so truth is available to any caller that does not cross it.
And `/proc/net/tcp` is the wrong interface by the kernel's own admission — "these interfaces are
deprecated in favor of tcp_diag" (<https://docs.kernel.org/networking/proc_net_tcp.html>) — making the
replacement a different code path in a different process.

---

## 2. The specimens

**libprocesshider** (<https://github.com/gianlucaborello/libprocesshider>) is the minimal case:
`processhider.c` hooks `readdir`/`readdir64` only, applies one compile-time constant
(`process_to_filter`), and gates on `dirfd(dirp)` resolved via `/proc/self/fd/%d` equal to `/proc` plus
a name match from `/proc/<pid>/stat`.

**P2PInfect `libs.so.1`** is the per-user variant: it "seek[s] out `.bashrc` files … and append[s]
`export LD_PRELOAD=/home/<user>/.lib/libs.so.1`"
(<https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer>).
Hooked: `fopen`/`fopen64`, `lstat`/`lstat64`, `unlink`/`unlinkat`, `readdir`/`readdir64`. On
`fopen("/proc/net/tcp")` or `/proc/net/tcp6` it "filter[s] out any ports between **60100 and 60150**",
matching the main binary's listen range ("a random port between 60100 to 60150"). For a hidden PID it
sets `errno = 2` (ENOENT). `lstat`/`unlink` match by `ends_with`, so any file sharing the binary's
random name is hidden "regardless of if it is in the right directory". A randomly named env var is the
bypass string, and the object is generated at runtime ("no consistent hash"). Companion: `/tmp/bash`
with `argv[0]` set to `[kworker/1:0H]`.

**Kinsing `libsystem.so`** is the system-wide variant and the most instructive. The deploy script
"remov[es] the immutable file flag from `/etc/ld.so.preload` if it exists", downloads the rootkit "into
`/etc/libsystem.so`", then writes a fresh `/etc/ld.so.preload` pointing at it
(<https://www.trendmicro.com/en_us/research/20/k/analysis-of-kinsing-malwares-use-of-rootkit.html>).
It hooks **18** symbols: `access`, `rmdir`, `open`, `readdir`/`readdir64`,
`stat`/`stat64`/`__xstat`/`__xstat64`, `lstat`/`lstat64`/`__lxstat`/`__lxstat64`, `fopen`/`fopen64`,
`link`, `unlink`/`unlinkat`. Hidden literals: `kinsing`, `kdevtmpfsi`, `libsystem.so`. Three behaviours to
memorise: `is_attacker` is true when env var **`SKL`** is present, so operators work unmolested;
`hide_tcp_ports` "parse[s] files in `/proc/net/tcp` or `/proc/net/tcp6` … extracts remote IP addresses
and compares them with hidden literals"; and hooked metadata calls return **`ENOENT`** for
non-attackers but **`EPERM`** for the literal filenames — a `stat` failing `EPERM` instead of `ENOENT`
is itself a fingerprint. Trend Micro notes the actor "reuses the publicly available **beurk** rootkit
(<https://github.com/unix-thrust/beurk>), but with several custom modifications"; beurk's feature list
includes "**[libpcap] hooking undermines local sniffers**" — `tcpdump` is a target.

**Hildegard** (Unit 42) did it inside Kubernetes: it "modified the `/etc/ld.so.preload` file to
intercept shared libraries' imported functions … overwrites two functions: `readdir()` and
`readdir64()`", filtering `/proc` entries named `tmate`, `xmrig`, `ziggy`, so "`ps`, `top` and many
other container monitoring tools will be blinded"
(<https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/>). It replaces the file rather than
appending, so the inode changes. **Winnti for Linux** used "a modified copy of the open-source userland
rootkit Azazel, named `libxselinux.so`" (MITRE T1014 software table) — a naming convention that makes
filename checks worthless and package-ownership checks worth having.

**Diamorphine** (<https://github.com/m0nad/Diamorphine>) is the kernel class, "for Linux Kernels
2.6.x/3.x/4.x/5.x/6.x (x86/x86_64 and ARM64)". `diamorphine.h` defines `MAGIC_PREFIX
"diamorphine_secret"`, `SIGINVIS = 31`, `SIGMODINVIS = 63`, `SIGSUPER = 64`; the module patches
`__sys_call_table[__NR_getdents]`, `[__NR_getdents64]`, `[__NR_kill]`, and `kill -63 0` toggles its
visibility. It hides itself by `list_del(&THIS_MODULE->list)`.

---

## 3. Why `/etc/ld.so.preload` is the load-bearing file

```c
/* We have two ways to specify objects to preload: via environment
   variable and via the file /etc/ld.so.preload.  The latter can also
   be used when security is enabled.  */
```

The loader's grammar is permissive — "names of libraries to be loaded, separated by white spaces or
`:`… It may also contain comments introduced by `#`" — and `ld.so(8)` gives the scope:
"`/etc/ld.so.preload` has a system-wide effect, causing the specified libraries to be preloaded for
all programs" (<https://man7.org/linux/man-pages/man8/ld.so.8.html>). In secure-execution mode
(AT_SECURE: setuid/setgid or file caps) "preload pathnames containing slashes are ignored" and objects
load "only from the standard search directories and only if they have set-user-ID mode bit enabled" —
but that restriction is written for `LD_PRELOAD`, not for the file, which is why a rootkit parked there
also infects `sudo`, `su`, `mount`, `passwd`.

Measured here: a preload object appears **five** times in `/proc/<pid>/maps` (one per segment), `ldd
/bin/true` lists it, and after `unlink` the lines become `… (deleted)`:

```
7f081e71c000-7f081e71d000 r--p 00000000 00:51 131   /tmp/pre/libbenign.so
7f8469f6d000-7f8469f6e000 r--p 00000000 00:51 132   /tmp/pre/libgone.so (deleted)
```

Two one-way hardening facts: the immutable flag is cleared only by "the superuser or a process
possessing the `CAP_LINUX_IMMUTABLE` capability"
(<https://man7.org/linux/man-pages/man1/chattr.1.html>) — exactly what Kinsing's installer strips
first — and `kernel.modules_disabled=1` means "modules can be neither loaded nor unloaded, and the
toggle cannot be set back to false" (<https://docs.kernel.org/admin-guide/sysctl/kernel.html>).

Absent or empty is the normal state — `ls /etc/ld.so.preload` returns ENOENT here — and rkhunter's
`shared_libs` test acts only `if [ -s "${PRELOAD_FILE}" ]`, strips lines beginning `#`, and warns on
every remaining name not in `SHARED_LIB_WHITELIST` (default null; shipped example `/lib/snoopy.so`)
(<https://github.com/Rootkit-Hunter/rkhunter/blob/master/files/rkhunter>). That parser is narrower than
glibc's, which blanks `#`→EOL and splits on `:`, so read the file with `tr ':#' '\n\n'`.

---

## 4. Cross-view validation: four readers, one socket table

Nothing in the specimens hooks `socket()`, `sendmsg()` or `recvmsg()`. That is the free win.

| View | Reader | Kernel path | Defeated by |
|---|---|---|---|
| procfs | `netstat`, `lsof -i`, `cat`, P2PInfect's filter | `tcp4_seq_show()` | any `open`/`fopen` hook |
| netlink sock_diag | `ss` | `tcp_diag_dump()` | a `sendmsg`/`recvmsg` hook (none listed) |
| `AF_PACKET` | `tcpdump`, raw sockets | device tap | libpcap hooks (beurk); traffic only, no idle listeners |
| eBPF | `bpftrace`, bcc `tcpconnect` | kprobe `tcp_connect` | needs `CAP_BPF`; blind to older sockets |

Source proof: `ss.c` calls `rtnl_open_byproto(&rth, 0, NETLINK_SOCK_DIAG)` and enters the procfs path
only when netlink fails **or when `PROC_NET_TCP` / `PROC_ROOT` is set** —
`if (!getenv("PROC_NET_TCP") && !getenv("PROC_ROOT") && inet_show_netlink(f, NULL, IPPROTO_TCP) == 0)
return 0;` followed by `/* Sigh... We have to parse /proc/net/tcp... */`. Constants:
`NETLINK_SOCK_DIAG 4` (<https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h>),
`SOCK_DIAG_BY_FAMILY 20`
(<https://github.com/torvalds/linux/blob/master/include/uapi/linux/sock_diag.h>).

That env fallback is the cheapest cross-view in existence because it is the *same binary*:

```bash
ss -tlnp                 | sort > /tmp/a      # sock_diag
PROC_NET_TCP=/proc/net/tcp ss -tlnp | sort > /tmp/b   # forced procfs
comm -3 /tmp/a /tmp/b                          # rows present in only one view
```

For a third reader against `netstat -tln`, compare sorted `local:port` columns.

The `ss -p` hole survives the netlink switch. `ss -e` prints `uid:<uid> ino:<inode> sk:<cookie>`
(<https://man7.org/linux/man-pages/man8/ss.8.html>; measured here: `uid:966 ino:331120 sk:100d
cgroup:unreachable:1`). The inode is the join key to `/proc/*/fd/*` symlinks of the form
`socket:[<inode>]`, and `ss` performs that join with `opendir()`/`readdir()` plus
`/proc/<pid>/task/<tid>/comm`. A `readdir` rootkit leaves the socket row and blanks the Process column.
Manual join, integer loop, no readdir:

```bash
ino=$(ss -tne | awk '$1=="ESTAB"{for(i=1;i<=NF;i++) if($i~/^ino:/){sub("ino:","",$i);print $i;exit}}')
last=$(awk '{print $5}' /proc/loadavg)     # 5th field = "last pid created"
for p in $(seq 2 "$last"); do for f in /proc/$p/fd/*; do
  [ "$(readlink "$f" 2>/dev/null)" = "socket:[$ino]" ] && echo "$p $(tr '\0' ' ' </proc/$p/cmdline)"
done; done
```

`/proc/loadavg` field 5 is "last pid created"
(<https://github.com/torvalds/linux/blob/master/Documentation/filesystems/proc.rst>); the alternative
is `/proc/sys/kernel/ns_last_pid`. Both beat walking to `pid_max` (4194304 here).

For packets, prefer a raw `AF_PACKET` socket over `tcpdump`, since beurk hooks libpcap — and none of
the specimens hook `socket`/`recv`:

```bash
sudo python3 -c "import socket;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));[s.recvfrom(65535) for _ in range(50)]"
```

eBPF's operator-relevant limit is **start time**, not capability: `kprobe:tcp_connect` fires at call
time, so a tunnel that connected hours ago is invisible — bcc's `tcpconnect`
(<https://github.com/iovisor/bcc/blob/master/tools/tcpconnect_example.txt>) catches a new squat, not an
old one. bpftrace master requires "**Minimum kernel version: 6.1**"
(<https://github.com/bpftrace/bpftrace/blob/master/docs/dependency_support.md>). BPF iterators are a
third independent dump path whose docs note that `cat /proc/net/tcp6` and `ss` are exactly the fixed
interfaces they replace (<https://docs.kernel.org/bpf/bpf_iterators.html>).

---

## 5. Detecting the load itself

**`/proc/PID/maps`.** "If the mapping is file-backed and the file has been deleted, the string `"
(deleted)"` is appended to the pathname" (<https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html>).
A rootkit that unlinks its `.so` after load is *more* visible, not less. Sweep for an object mapped at a
non-library path:

```bash
last=$(awk '{print $5}' /proc/loadavg)
for p in $(seq 2 "$last"); do
  awk '$6 ~ /^\// && $6 !~ /^\/(usr\/)?lib/' "/proc/$p/maps" 2>/dev/null
done | sort | uniq -c | sort -rn | head -20
```

**The loader itself.** `ldd /bin/true` prints the whole link map including preloads (verified:
`/tmp/pre/libbenign.so (0x7f534a701000)`); the loader form below drops `ldd`'s shell wrapper:

```bash
/lib64/ld-linux-x86-64.so.2 --list /bin/true | grep -vE '^\s*/(usr/)?lib(64)?/'
```

**Watching the write.** `auditctl -w /etc/ld.so.preload -p wa -k ld_so_preload` (deprecated "due to
poor system performance") or `auditctl -a always,exit -F path=/etc/ld.so.preload -F perm=wa`
(<https://man7.org/linux/man-pages/man8/auditctl.8.html>). A watch "track[s] the inode internally", so
the file must exist — pre-create it empty (an empty `ld.so.preload` preloads nothing). The eBPF
equivalent, sampling the read:

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat
  /str(args->filename) == "/etc/ld.so.preload"/ { printf("%s pid=%d\n", comm, pid); }'
```

**Package ownership.** No distribution ships `ld.so.preload` or `/etc/libsystem.so`, so `dpkg -S
/etc/ld.so.preload` or `rpm -qf /etc/libsystem.so` returning "no package" is a positive signal, and
`dpkg -V` / `rpm -Va` catches the other half — a package-owned `lib*.so` whose contents were replaced.

---

## 6. The kernel class, and where in-guest detection ends

Diamorphine touches only `getdents`, `getdents64`, `kill` — not `stat`, `statx`, `open` or netlink. The
process is missing from `ls /proc` but fully alive to `test -d /proc/<pid>`, `cat /proc/<pid>/cmdline`
and every `ss` query. The `kill` channel cuts both ways: `kill -31 <pid>` and `kill -63 0` are
*commands* to the module, so a probe that toggles visibility is itself observable.

`module_hide()` is only `list_del(&THIS_MODULE->list)`, with no `kobject_del()`, so the sysfs node
persists while `/proc/modules` is empty (`/sys` is not mounted here, so this is source-derived).

`unhide` formalises the syscall-side probing: 13 elementary techniques (`checkbrute`, `checkkill`,
`checkgetaffinity`, `checkgetpgid`, `checkchdir`, `checkopendir`, `checkreaddir`…), each compared
against `/bin/ps`; standard sets `quick`, `sys proc`, `procall`, `reverse`; "exit status 1 if a hidden
or fake thread is found"; deep invocation `unhide -m -d sys procall brute reverse`
(<https://manpages.debian.org/bookworm/unhide/unhide-linux.8.en.html>). Its companion `unhide-tcp`
brute-forces every TCP/UDP port against "`/sbin/ss` (or alternatively `/bin/netstat`)", exit **4**
hidden TCP port, **8** UDP, **12** both
(<https://manpages.debian.org/bookworm/unhide/unhide-tcp.8.en.html>) — precisely the P2PInfect
60100–60150 case and Kinsing's `hide_tcp_ports`.

Past that, the honest answer is out-of-band. A module that patches `sys_call_table` can also patch
`bpf()`, `openat` and the `seq_file` ops behind `/proc/net/tcp`, and `kptr_restrict=1|2` hides pointer
printing, not the hook. Once an LKM is in the TCB, verify from a rescue boot or from the hypervisor.

---

## 7. Detection recipe (cheapest first)

**0. Anything with a `TracerPid`.** Before the load-inspection tier: a process being traced is a
process something is attached to, and in a container where nobody debugs, that is an injection or a
redactor. See §8 — and see §8.1, because this finds the *supervisor* model and misses tools that
detach after the rewrite.

```sh
awk '/^TracerPid:/{if ($2 != 0) print FILENAME, $2}' /proc/[0-9]*/status
```

Run as root; each step names its false-positive mode.

1. **`lsattr -a /etc/ld.so.preload; ls -l /etc/ld.so.preload; tr ':#' '\n\n' < /etc/ld.so.preload`**
   (~1 s). FP: `snoopy`, `tcmalloc`/`jemalloc`, some HPC/backup agents — all appear in the package
   database, which is the discriminator.
2. **`/lib64/ld-linux-x86-64.so.2 --list /bin/true | grep -vE '^\s*/(usr/)?lib(64)?/'`** (~1 s). FP:
   none beyond step 1; also surfaces `$ORIGIN`-relative objects from wrapper scripts.
3. **`dpkg -S /etc/ld.so.preload` / `rpm -qf /etc/libsystem.so`, and `stat -c '%y %n' /etc /lib /lib64`**
   (~1 s). FP: a `snoopy` built from source; package upgrades and `ldconfig` move mtimes routinely, so
   use mtime to *date* an event, not to declare one.
4. **`ss -tlnp` vs `PROC_NET_TCP=/proc/net/tcp ss -tlnp` vs `netstat -tnp`** (<1 s each). FP: the tools disagree
   harmlessly on state names and TIME_WAIT inclusion — compare sorted `local:port` columns only.
5. **`ss -tne` → inode → integer PID sweep** (seconds). FP: `readdir("/proc")` can under-report with no
   rootkit present — I measured 3–5 visible PIDs against 23 reachable. `hidepid=2` is the ordinary
   cause; container/pidns layouts look the same. Treat a mismatch as "look closer", never "rootkit".
6. **`unhide-linux -m sys proc`, then `unhide-tcp`** (seconds–minutes). FP: the man page warns the
   `sysinfo` test "may report false positives" above kernel 2.6.33 (scheduler, cgroup, systemd); `-d`
   double-checks. `unhide-tcp` exit 4/8/12 is a finding; its `-f`/`-l` attribution uses `fuser`/`lsof`,
   both `/proc`-based and therefore hookable — a hidden port with no attributable owner is the real case.
7. **The `/proc/<pid>/maps` sweep** (seconds). FP: JIT maps, `/memfd:… (deleted)`, and package upgrades
   leaving `libc.so.6 (deleted)` in long-running daemons until restart. With `ptrace_scope=1` an
   unprivileged sweep is a false-negative generator.
8. **`awk '{print $1}' /proc/modules | sort` vs `ls /sys/module`** (~1 s). Any sysfs module missing
   from `/proc/modules` is hidden. FP: built-ins also live in `/sys/module` — `-d
   /sys/module/<n>/holders` discriminates.
9. **`auditctl -a always,exit -F path=/etc/ld.so.preload -F perm=wa -k ld_so_preload`** plus the
   bpftrace `openat` one-liner (ongoing). FP: your own package upgrades; filter on
   `auid!=4294967295` (a real login session) rather than on `uid=0`.

Two rules outweigh any single check. A libc hook cannot lie to a reader that does not use libc, so the
*disagreement* between `ss` and `netstat`, or between eBPF and `/proc/net/tcp`, is the signal. And the
injected object must be **mapped** — recorded in `mm->mmap` even after the loader hides the file — so
`/proc/<pid>/maps` reports a path `stat` will deny exists. That contradiction is the highest-signal
artefact in the class.

---

## 8. Argument laundering: what a /proc scrubber leaves behind

A squatter who wants to hide *what* a process is doing has an easier job than one hiding *that it
exists*. `confmask` is the cleanest published example: it runs a command under a ptrace supervisor and
rewrites `cmdline`, `environ` and `comm` for the whole tree, keeping a presentation label in their
place while the program keeps its real `argv`.

Measured on a container sandbox with a credential in `argv`:

```
RED   ps -eo pid,ppid,comm,args
      48042  48039  ci-runner   ci-runner
      48045  48042  ci-runner   ci-runner
      48046  48045  ci-runner   ci-runner

RED   token sightings across every /proc/*/cmdline and /proc/*/environ: 0
```

The red claim holds. Blue still has four handles.

**1. The tracer.** A ptrace supervisor is a tracer, so `/proc/<pid>/status` carries a non-zero
`TracerPid` for every process in the tree. In the same run, `48045` and `48046` were both traced by
`48044`, and `48044` itself does not appear in `ps` under any label — it is the only process on the box
whose `/proc` entry was never rewritten.

```sh
awk '/^TracerPid:/ && $2 != 0 {print FILENAME, $2}' /proc/[0-9]*/status
```

**2. `exe` is not rewritten.** `readlink /proc/<pid>/exe` returned `/usr/bin/dash` and
`/usr/lib/cargo/bin/coreutils/sleep` while `comm` said `ci-runner` for both. A `comm` that disagrees
with the basename of its own `exe` is the D02 signal inverted: the corpus treats a renamed binary as
unidentifiable, but a *consistent* rename also removes the disagreement, and this tool does not produce
one.

**3. The label is padded, and the padding is measurable.** `wc -c /proc/<pid>/cmdline` returned 51 bytes
for a command with two visible tokens, and the naive `tr '\0' '\n' | wc -l` returns 42 "arguments". The
rewrite keeps the original `argv` region allocated and fills it with NULs, so a `cmdline` whose byte
length is a large multiple of its text content is a scrubbed one. Nothing legitimate produces that
shape.

```sh
# a cmdline mostly made of NUL is a rewritten one
awk '{print FILENAME}' /proc/[0-9]*/cmdline 2>/dev/null |
while read -r f; do
	n=$(tr -cd '\0' < "$f" 2>/dev/null | wc -c)
	t=$(tr -d '\0' < "$f" 2>/dev/null | wc -c)
	[ "$t" -gt 0 ] && [ "$n" -gt $((t * 2)) ] && echo "$f nul=$n text=$t"
done
```

**4. The supervisor is an ordinary process with an ordinary name.** It ran from `/tmp/confmask`, which
`readlink` on its `exe` reports like any other binary. A squatter who renames it must still keep it
running, and it carries no label of its own.

The general point for this file: **metadata laundering trades one artifact for another.** The corpus'
hook-plane taxonomy (§1) covers processes that lie about what they *are*; this covers a process that
lies about what it *does*, and the lie is bounded by the mechanism that writes it. Anything that must
attach to a process to rewrite it leaves the attachment visible, and the attachment is not forgeable
from inside the victim's namespace without root on the host.

### 8.1 Measured against a second implementation, and the tell that disappeared

The `TracerPid` detector in §8 is correct and it is also **implementation-specific**. Running the same
workload under two different masking tools on the same box shows why:

| | `comm` | `exe` | `TracerPid` | argv redacted |
|---|---|---|---|---|
| nothing (baseline) | `job.sh` | `/usr/bin/dash` | `0` | no |
| **zapper v1.1** | `job.sh` | `/usr/bin/dash` | **`0`** | **yes** |
| **zapper v1.1 stealth** | `job.sh` | `/usr/bin/dash` | **`0`** | **yes** |
| confmask 0.1.0 | `ci-runner` | `/usr/bin/dash` | **`8469`** | yes |

zapper redacted the arguments and left **no tracer behind**. Its README explains it: it uses `ptrace()`
to move the command options, rewrites the pointers in the ELF auxiliary table, and then
`PTRACE_CONTINUE`s and detaches, re-attaching only at `fork()`/`execve()`. confmask stays attached as a
supervisor for the life of the tree, which is what produces a stable non-zero `TracerPid`.

So the one-liner in §7 — `awk '/^TracerPid:/ && $2 != 0'` — finds **every confmask session and no zapper
session at all**. It detects a *supervision model*, not a *class of tool*.

What still catches zapper is the other signal in §8: `comm` says `job.sh` and `exe` says
`/usr/bin/dash`, which is ordinary, but the *arguments* the process is running are absent from a
`cmdline` that otherwise looks normal. That is a different question — "why does this process have no
arguments?" — and it does not need a tracer to ask.

Two secondary differences worth recording. The **stealth build** carries zero `zapper` strings against
thirteen in the normal build (30,600 vs 50,832 bytes), so the string-scan that identified the binary in
this corpus' first case would find nothing. And zapper's `-a` did **not** rename `comm` in this test —
it stayed `job.sh` — so its name-hiding is narrower than its README implies, while its argument
redaction works.

A design proposal for closing that gap in confmask is filed upstream as
[Nemo-010/confmask#29](https://github.com/Nemo-010/confmask/issues/29). The mechanism it turns on is
worth recording here because it is widely assumed to be privileged and is not: `prctl(PR_SET_MM,
PR_SET_MM_MAP, …)` is **unprivileged** — the `CAP_SYS_RESOURCE` check in `kernel/sys.c` sits after the
map dispatch — and one call relocates the arg/env windows, rewrites `saved_auxv` so `AT_EXECFN` matches,
and moves `start_stack`. That closes the residency tell, the exact-size tell and the `[stack]` tell at
once, from userland, without a tracer.

The general rule this sharpens: **a detector keyed to a mechanism detects the tools that use that
mechanism.** `TracerPid` catches supervisors; `comm`-versus-`exe` catches renames; absence-of-arguments
catches redactors. No single line covers the class, which is why §7's recipe is a list rather than a
one-liner.

## Sources

- MITRE T1014, T1574.006, DET0377 — <https://attack.mitre.org/techniques/T1014/>,
  <https://attack.mitre.org/techniques/T1574/006/>, <https://attack.mitre.org/detectionstrategies/DET0377>
- glibc `elf/rtld.c` <https://github.com/bminor/glibc/blob/master/elf/rtld.c>; `ld.so(8)`
  <https://man7.org/linux/man-pages/man8/ld.so.8.html>; `proc_pid_maps(5)`
  <https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html>; `proc(5)`
  <https://man7.org/linux/man-pages/man5/proc.5.html>
- `Documentation/filesystems/proc.rst`
  <https://github.com/torvalds/linux/blob/master/Documentation/filesystems/proc.rst>;
  `/proc/net/tcp` deprecation <https://docs.kernel.org/networking/proc_net_tcp.html>;
  `net/ipv4/tcp_diag.c` <https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_diag.c>
- UAPI <https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h>,
  <https://github.com/torvalds/linux/blob/master/include/uapi/linux/sock_diag.h>
- iproute2 <https://github.com/iproute2/iproute2/blob/main/misc/ss.c>; `ss(8)`
  <https://man7.org/linux/man-pages/man8/ss.8.html>
- net-tools <https://github.com/ecki/net-tools/blob/master/lib/pathnames.h>,
  <https://github.com/ecki/net-tools/blob/master/netstat.c>; lsof
  <https://github.com/lsof-org/lsof/blob/master/lib/dialects/linux/dsock.c>
- Trend Micro on Kinsing (2020-11-24)
  <https://www.trendmicro.com/en_us/research/20/k/analysis-of-kinsing-malwares-use-of-rootkit.html>
- Darktrace/Cado on P2PInfect
  <https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer>
- Unit 42 on Hildegard <https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/>
- <https://github.com/gianlucaborello/libprocesshider>, <https://github.com/unix-thrust/beurk>,
  <https://github.com/m0nad/Diamorphine>
- rkhunter <https://github.com/Rootkit-Hunter/rkhunter/blob/master/files/rkhunter>,
  <https://github.com/Rootkit-Hunter/rkhunter/blob/master/files/rkhunter.conf>
- `unhide-linux(8)` <https://manpages.debian.org/bookworm/unhide/unhide-linux.8.en.html>;
  `unhide-tcp(8)` <https://manpages.debian.org/bookworm/unhide/unhide-tcp.8.en.html>
- `auditctl(8)` <https://man7.org/linux/man-pages/man8/auditctl.8.html>; `chattr(1)`
  <https://man7.org/linux/man-pages/man1/chattr.1.html>; `sysctl/kernel`
  <https://docs.kernel.org/admin-guide/sysctl/kernel.html>
- BPF iterators <https://docs.kernel.org/bpf/bpf_iterators.html>; bpftrace kernel floor
  <https://github.com/bpftrace/bpftrace/blob/master/docs/dependency_support.md>; bcc `tcpconnect`
  <https://github.com/iovisor/bcc/blob/master/tools/tcpconnect_example.txt>
- Versions <https://sources.debian.org/src/iproute2/> 7.3.0-1, <https://sources.debian.org/src/unhide/>
  20240510-2, <https://sources.debian.org/src/rkhunter/> 1.4.6-14

## What I could not verify

- **Secure-execution mode against a setuid binary.** This sandbox sets `NoNewPrivs: 1`, so AT_SECURE
  never engages and `LD_PRELOAD` was honoured even for `/usr/bin/su`. The claim that env `LD_PRELOAD` is
  dropped while `ld.so.preload` is not rests on `ld.so(8)` and `rtld.c`, not on measurement — as does
  `dso_name_valid_for_suid()`, whose call site I read but not its body.
- **Whether `ss` really issued a netlink round-trip here.** `strace` is blocked (`ptrace(PTRACE_SEIZE):
  Operation not permitted`), so netlink-versus-procfs is from source, not a syscall trace. Likewise
  `/sys` is not mounted, so the `/sys/module`-vs-`/proc/modules` artefact is source-derived.
- **The mechanism** behind the readdir/stat divergence I measured (3–5 listed PIDs vs 23 reachable, no
  `hidepid`, no `LD_PRELOAD`). Reproducible here; cause unattributed.
- **`dpkg -S` / `rpm -qf` output strings** — neither tool is installed; the check is standard, the exact
  wording is from memory.
- **Kinsing's precise match rule** in `hide_tcp_ports` (substring, literal set, regex) — Trend Micro
  describes *what* it parses and matches, not the implementation, and I obtained no sample.
- **P2PInfect `libs.so.1` contents** — "Dynamically generated, no consistent hash": there is no fixed
  IoC, so everything above is behavioural.

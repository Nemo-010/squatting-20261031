# eBPF Runtime Detection of Outbound-Only Tunnels, Proxies and Proxyjacking on One Linux Host

Scope: a single ordinary Linux server, no commercial NDR, no appliance. Tools: **bpftrace**, **bcc**, **Tetragon**, **Tracee**. Everything below is free/open source and attaches to the kernel at runtime.

## Summary

- The attack is MITRE **T1496.002 Bandwidth Hijacking** with detection strategy **DET0028** (analytics AN0080–AN0084). Its only reliable host-level signature is *sustained outbound TCP/UDP from a process that never listens*, plus a handful of syscall fingerprints.
- Six probes cover ~everything: `execve` (execsnoop), `connect` (tcpconnect), `socket`, `openat("/dev/net/tun")`, `memfd_create`, and `setsockopt` (`SO_MARK`, `SO_BINDTODEVICE`, `IP_TRANSPARENT`).
- Cheapest layer is **bpftrace**: three or four one-liners, no daemon, seconds to deploy, and `kprobe:tcp_connect` is a documented upstream tool (`tools/tcpconnect.bt`). Packaged as `bpftrace` in Debian/Ubuntu, Fedora and Alpine.
- **bcc** adds `tcplife` (per-connection byte counters — the only free on-host way to measure *bandwidth per connection*) and `bindsnoop` (`IP_TRANSPARENT`/`SO_BINDTODEVICE`/`IP_FREEBIND` at bind time — the transparent-proxy fingerprint).
- **Tetragon** is the only one of the four that does in-kernel filtering with enforcement (`Sigkill`) and reports its own overhead per BPF program. Needs kernel **≥ 4.19**; `fentry` needs **≥ 6.1**; full path retrieval needs **≥ 5.3**.
- Measured Tetragon overhead (upstream benchmarks): **1.68 %** for tracing all process executions, **2.46 %** when also writing all exec events as JSON, **5.88 %** connection-rate loss in a worst-case `netperf TCP_CRR` test.
- **Tracee** ships ready-made signatures that map directly onto the proxyjacking chain: `fileless_execution` (TRC-105, T1620), `dropped_executable` (TRC-1022, T1036), `stdio_over_socket` (TRC-101), plus `net_tcp_connect` and `memfd_create` events. Recommended kernels 5.4/5.10/5.15/6.2/6.5.
- Proxyware is dormant for long periods, so a 60-second `interval` aggregation over `tcp_connect` beats a raw event firehose.
- Highest-signal rule for an outbound-only tunnel: `connect()` to a non-RFC1918 address from a binary in `/tmp`, `/dev/shm` or an anonymous memfd, with no corresponding `accept()` on this host.

---

## 1. What you are actually looking for

MITRE's DET0028 analytics for proxyjacking call out, verbatim, "sustained outbound traffic … potentially linked to scanning or proxyjacking. Includes curl, wget, masscan, or proxy clients", and for virtual instances "sustained outbound data rates, often to TOR, VPN, or proxy endpoints" — https://attack.mitre.org/detectionstrategies/DET0028/

Akamai SIRT observed a campaign that installs P2P proxy nodes (Peer2Profit / Honeygain) on SSH-compromised servers, stages a real `curl` in `/dev/shm` or `/tmp`, pulls a Docker image renamed `postfixd`, and kills rival bandwidth-sharing containers — https://www.akamai.com/blog/security-research/proxyjacking-new-campaign-cybercriminal-side-hustle

Kernel-visible translation:

| Behaviour | Probe | Syscall / hook |
|---|---|---|
| Attacker drops/runs tooling from tmpfs | `execve` + path filter | `sched_process_exec`, `sys_enter_execve` |
| Proxy client dials out | `connect()` | `kprobe:tcp_connect`, `security_socket_connect` |
| New socket of a given family/type | `socket()` | `sys_enter_socket` (family, type, protocol) |
| VPN/tun device creation | `openat("/dev/net/tun")` then `ioctl(TUNSETIFF)` | `security_file_open`, `sys_enter_ioctl` |
| Fileless payload | `memfd_create()` | `sys_enter_memfd_create` |
| Transparent proxy / policy routing | `setsockopt()` | `sys_enter_setsockopt` |

Constants you will need (all verified in kernel UAPI headers): `SO_BINDTODEVICE` = 25, `SO_MARK` = 36 in `include/uapi/asm-generic/socket.h`; `SO_ORIGINAL_DST` = 80 in `include/uapi/linux/netfilter_ipv4.h`; `IP_FREEBIND` = 15, `IP_TRANSPARENT` = 19 in `include/uapi/linux/in.h`. `TUNSETIFF` is `_IOW('T', 202, int)` = **0x400454ca** in `include/uapi/linux/if_tun.h`.

Why `setsockopt` matters: `SO_MARK` is for "mark-based routing without netfilter", and setting it "requires the CAP_NET_ADMIN or CAP_NET_RAW (since Linux 5.17) capability" — https://man7.org/linux/man-pages/man7/socket.7.html. `IP_TRANSPARENT` "enables transparent proxying on this socket" and likewise "requires superuser privileges (the CAP_NET_ADMIN or CAP_NET_RAW capability)" — https://man7.org/linux/man-pages/man2/IP_TRANSPARENT.2const.html. A non-root process asking for either is a hard signal.

---

## 2. Kernel floor: what works on which kernel

| Capability | Kernel | Source |
|---|---|---|
| eBPF + kprobes | 4.1 | https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md |
| BPF on tracepoints | 4.7 | same |
| BTF (`CONFIG_DEBUG_INFO_BTF`) | 4.18 | same |
| BPF trampoline / fentry-fexit | 5.5 | same |
| BPF LSM | 5.7 | same |
| ring buffer (`BPF_MAP_TYPE_RINGBUF`) | 5.8 | same |

Tool floors:

- **bcc**: "a Linux kernel version 4.1 or newer is required" — https://github.com/iovisor/bcc/blob/master/INSTALL.md
- **bpftrace** (current master): "**Minimum kernel version: 6.1**" — https://github.com/bpftrace/bpftrace/blob/master/docs/dependency_support.md. Older releases ran on 4.x-era kernels, so pin the distro package: Ubuntu 22.04 ships bpftrace **0.14.0-1** — https://manpages.ubuntu.com/manpages/jammy/man8/tcpconnect.bt.8.html
- **Tetragon**: "Tetragon needs Linux kernel version 4.19 or greater", tested on 4.19/5.4/5.10/5.15 — https://tetragon.io/docs/installation/faq/. `fentry` "requires a kernel >= 6.1 built with BTF enabled" — https://tetragon.io/docs/concepts/tracing-policy/hooks/. Full path retrieval "available only on kernels v5.3 and later" — https://tetragon.io/docs/concepts/tracing-policy/argument_types/
- **Tracee**: "a modern longterm supported kernel is needed: 5.4, 5.10, 5.15, 6.2, 6.5" — https://aquasecurity.github.io/tracee/latest/docs/install/prerequisites/

Pre-flight checks (read-only):
```bash
test -r /sys/kernel/btf/vmlinux && echo "BTF ok"
cat /sys/kernel/security/lockdown      # 'confidentiality' breaks Tetragon
cat /proc/sys/kernel/perf_event_paranoid
uname -r
```

Tetragon explicitly warns that Lockdown in `confidentiality` mode makes BPF loading fail with `EPERM` — https://tetragon.io/docs/installation/faq/

---

## 3. bpftrace: the one-liners

Verify probe argument names on *your* kernel before trusting any field name:

```bash
sudo bpftrace -lv 'tracepoint:syscalls:sys_enter_memfd_create'
sudo bpftrace -lv 'tracepoint:syscalls:sys_enter_setsockopt'
```

`-l`/`-lv` are documented in the man page, which shows the exact output shape (`int dfd`, `const char * filename`, …) — https://github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc

### 3.1 Outbound TCP with addresses and ports

Upstream's reference implementation uses `kprobe:tcp_connect` rather than the syscall tracepoint, so it gets a populated `struct sock`:

```bash
sudo bpftrace tools/tcpconnect.bt
# or inline, one line:
sudo bpftrace -e 'kprobe:tcp_connect { $sk=(struct sock*)arg0;
  if ($sk->__sk_common.skc_family==2) {
    printf("%-16s %-6d %s:%d -> %s:%d\n", comm, pid,
      ntop($sk->__sk_common.skc_rcv_saddr), $sk->__sk_common.skc_num,
      ntop($sk->__sk_common.skc_daddr), bswap($sk->__sk_common.skc_dport)); } }'
```

Source of the field layout and the `bswap()` for the big-endian destination port: https://github.com/bpftrace/bpftrace/blob/master/tools/tcpconnect.bt

Drop loopback with a numeric first-octet test (bpftrace has no CIDR predicate; do full RFC1918 exclusion in Tetragon selectors — §5). On a little-endian host the first octet of a `__be32` is the low byte:

```bash
sudo bpftrace -e 'kprobe:tcp_connect { $sk=(struct sock*)arg0;
  if ($sk->__sk_common.skc_family==2) {
    $daddr = $sk->__sk_common.skc_daddr;
    if (($daddr & 0xff) != 127) {
      printf("%-16s %d -> %s:%d\n", comm, pid,
        ntop($daddr), bswap($sk->__sk_common.skc_dport)); } } }'
```

### 3.2 execve, including the staging directories

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve {
  printf("%s %s\n", comm, str(args.filename)); }'
```

Upstream equivalent with argv: `tools/execsnoop.bt` — https://github.com/bpftrace/bpftrace/blob/master/tools/execsnoop.bt

High-signal filter for the Akamai campaign pattern (`/dev/shm`, `/tmp` execution), using only documented builtins:

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve
  /strncmp(str(args.filename), "/tmp/", 5) == 0
   || strncmp(str(args.filename), "/dev/shm/", 9) == 0/
  { printf("%-16s %d %s\n", comm, pid, str(args.filename)); }'
```

`strncmp()` and `strcontains()` are the documented string primitives — https://github.com/bpftrace/bpftrace/blob/master/docs/stdlib.md. Do **not** rely on `== "/tmp/*"` glob matching; that is not a documented feature.

### 3.3 `openat("/dev/net/tun")` — the classic tunnel

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat
  /str(args.filename) == "/dev/net/tun"/
  { printf("%s %d opened tun\n", comm, pid); }'
```

The tracepoint fields are `__syscall_nr, dfd, filename, flags, mode` — confirmed by the man page's own `-lv` output (https://github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc). WireGuard does **not** use `/dev/net/tun` (it creates an interface over rtnetlink), so pair this with process-name detection.

### 3.4 `ioctl(TUNSETIFF)` — someone is configuring a tun/tap

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_ioctl /args.cmd == 0x400454ca/
  { printf("%-16s %d TUNSETIFF\n", comm, pid); }'
```

The field is `cmd`, because the syscall is `SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)` — https://github.com/torvalds/linux/blob/master/fs/ioctl.c. `0x400454ca` is `_IOW('T', 202, int)` from `include/uapi/linux/if_tun.h`.

### 3.5 `memfd_create`

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_memfd_create
  { printf("%s %d memfd %s\n", comm, pid, str(args.uname)); }'
```

The field is `uname`, not `name`: the syscall is declared `SYSCALL_DEFINE2(memfd_create, const char __user *, uname, unsigned int, flags)` — https://github.com/torvalds/linux/blob/master/mm/memfd.c. Syscall tracepoint field names are derived from that prototype, which is why `-lv` confirmation is the right habit.

### 3.6 `setsockopt` — transparent proxy / policy routing

Levels differ: `IPPROTO_IP` is **0**, `SOL_SOCKET` is **1** (`include/uapi/linux/in.h`, `include/uapi/asm-generic/socket.h`).

```bash
# IP_TRANSPARENT (19) and IP_FREEBIND (15), level IPPROTO_IP = 0
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_setsockopt
  /args.level == 0 && (args.optname == 19 || args.optname == 15)/
  { printf("TRANSPARENT %-16s %d\n", comm, pid); }'

# SO_MARK (36) and SO_BINDTODEVICE (25), level SOL_SOCKET = 1
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_setsockopt
  /args.level == 1 && (args.optname == 36 || args.optname == 25)/
  { printf("MARK/BINDDEV %-16s %d\n", comm, pid); }'
```

Argument order `fd, level, optname, optval, optlen` is fixed by `SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)` — https://github.com/torvalds/linux/blob/master/net/socket.c

### 3.7 The "outbound-only" ratio

The cheapest discriminator — connects per process over 60 s:

```bash
sudo bpftrace -e 'kprobe:tcp_connect { @connects[comm] = count(); }
  interval:s:60 { print(@connects); clear(@connects); }'
```

If `@connects` is non-zero for a `comm` and there is no `kretprobe:inet_csk_accept` traffic for the same `comm`, that process is a pure client — the tunnel shape. `inet_csk_accept` is the hook bpftrace's own `tools/tcpaccept.bt` uses — https://github.com/bpftrace/bpftrace/blob/master/tools/tcpaccept.bt

---

## 4. bcc: bandwidth per connection, and bind-time socket options

bcc's tools are shipped in `/usr/share/bcc/tools` (`apt install bpfcc-tools` / `dnf install bcc-tools`).

- `tcpconnect` — all `connect()`s with saddr/daddr/dport: "The overhead of this tool should be negligible, since it is only tracing the kernel functions performing connect. It is not tracing every packet and then filtering." — https://github.com/iovisor/bcc/blob/master/tools/tcpconnect_example.txt
- `tcplife` — per-session lifespan **and byte counts**; this is the DET0028 "sustained outbound data rate" signal done on-host. It requires the `sock:inet_sock_set_state` tracepoint (kernel **4.16**), falling back to `tcp_set_state()` — https://github.com/iovisor/bcc/blob/master/tools/tcplife.py
- `bindsnoop` — reports `IP_FREEBIND`, `IP_TRANSPARENT`, `IP_BIND_ADDRESS_NO_PORT`, `SO_REUSEADDR`, `SO_REUSEPORT` and `SO_BINDTODEVICE` set before `bind()`. That is the transparent-proxy fingerprint in one column — https://github.com/iovisor/bcc/blob/master/tools/bindsnoop_example.txt
- `execsnoop` — new processes with argv
- `tcpconnlat` — connect latency, useful to spot long-haul tunnel endpoints

Concrete:

```bash
sudo /usr/share/bcc/tools/tcpconnect -t
sudo /usr/share/bcc/tools/tcplife -T
sudo /usr/share/bcc/tools/bindsnoop -t
sudo /usr/share/bcc/tools/execsnoop
```

---

## 5. Tetragon: the same detections, with in-kernel filtering and kill

Install on a plain host (systemd, no Kubernetes):

```bash
curl -LO https://github.com/cilium/tetragon/releases/download/v1.8.0/tetragon-v1.8.0-amd64.tar.gz
tar -xvf tetragon-v1.8.0-amd64.tar.gz && cd tetragon-v1.8.0-amd64/
sudo ./install.sh
sudo systemctl status tetragon
```

Policies are picked up from `/etc/tetragon/tetragon.tp.d/` (`--tracing-policy-dir`), or one file via `--tracing-policy` — https://tetragon.io/docs/installation/package/ and https://tetragon.io/docs/reference/daemon-configuration/

**Free without any policy:** Tetragon's `process_exec`/`process_exit` sensors are always on and emit `binary`, `arguments`, `cwd` and `exec_id`. `cwd` is documented as the field that "helps to identify hidden malware execution from a temporary folder, which is a common pattern used in malwares" — https://tetragon.io/docs/use-cases/process-lifecycle/process-execution/. Proxyjacking droppers from `/tmp` and `/dev/shm` show up here before you write a single line of YAML. Network visibility, by contrast, requires a TracingPolicy.

### 5.1 Outbound connect to non-private space, with kill

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "proxyjacking-outbound"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
        - "169.254.0.0/16"
      matchActions:
      - action: Sigkill
```

Shape taken from upstream `tcp-connect-only-private-addrs.yaml` (which uses `NotDAddr` + `Sigkill`) — https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/tcp-connect-only-private-addrs.yaml. `sock` supports `SAddr, DAddr, SPort, DPort, Protocol, Family, State` — https://tetragon.io/docs/concepts/tracing-policy/argument_types/

### 5.2 UDP/QUIC egress

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp-connect"
spec:
  kprobes:
  - call: "security_socket_connect"
    syscall: false
    args:
    - index: 0
      type: "socket"
    - index: 1
      type: "sockaddr"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_UDP"
      - index: 1
        operator: "Family"
        values:
        - "AF_INET"
        - "AF_INET6"
```

Signature is `int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)` — https://github.com/torvalds/linux/blob/master/security/security.c, so index 0 is the `socket`, 1 the `sockaddr`, 2 `addrlen` (an upstream example filters index 1 on `Family` — https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/security-socket-connect.yaml).

Two caveats from upstream docs: `sockaddr` "does not support destination operators (`DAddr`, `DPort`)" — https://tetragon.io/docs/concepts/tracing-policy/argument_types/ — and the `Protocol` operator's accepted value spelling (`IPPROTO_UDP` vs numeric `17`) appears in no example I found. For destination-port matching on UDP, use a `sock`-typed hook (`udp_connect`/`udp_sendmsg`) or filter in userspace.

### 5.3 `/dev/net/tun` open

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tun-device-open"
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/dev/net/tun"
```

`int security_file_open(struct file *file)` — https://github.com/torvalds/linux/blob/master/security/security.c. The `file` + `Prefix` selector idiom is the one Tetragon's own `filename_monitoring.yaml` uses — https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/filename_monitoring.yaml

### 5.4 `memfd_create`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "memfd-create"
spec:
  kprobes:
  - call: "sys_memfd_create"
    syscall: true
    args:
    - index: 0
      type: "string"
    - index: 1
      type: "uint32"
```

For syscall kprobes, write the symbol *without* the arch prefix (`sys_memfd_create`, not `__x64_sys_memfd_create`); Tetragon adds it — https://tetragon.io/docs/concepts/tracing-policy/hooks/

### 5.5 `setsockopt` for SO_MARK / IP_TRANSPARENT

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "transparent-proxy-sockopts"
spec:
  kprobes:
  - call: "sys_setsockopt"
    syscall: true
    args:
    - index: 1
      type: "int"     # level
    - index: 2
      type: "int"     # optname
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values: ["0"]        # IPPROTO_IP
      - index: 2
        operator: "Equal"
        values: ["19"]       # IP_TRANSPARENT
```

Argument indices are fixed by `SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, …)`. Note the docs' warning that hooking a syscall whose argument is a userspace pointer opens a TOCTOU window, and that hooking the later LSM/`__sys_` function avoids it — https://tetragon.io/docs/concepts/tracing-policy/hooks/

### 5.6 Reading and measuring

```bash
sudo tetra --server-address unix:///var/run/tetragon/tetragon.sock getevents -o compact
sudo tail -f /var/log/tetragon/tetragon.log
tetra tracingpolicy list
sudo tetra debug progs          # per-program Cnt/Time/Ovh(%)
```

`Ovh` is documented as "system wide overhead of the BPF program" and stats need `sysctl kernel.bpf_stats_enabled=1` (they are off by default because they add overhead) — https://tetragon.io/docs/troubleshooting/bpf-progs-stats/

---

## 6. Tracee: signatures that already exist

Minimal host-run policy covering the proxyjacking chain:

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: proxyjacking
spec:
  scope:
    - global
  rules:
    - event: net_tcp_connect
    - event: security_socket_connect
    - event: memfd_create
    - event: sched_process_exec
    - event: fileless_execution
    - event: dropped_executable
    - event: stdio_over_socket
    - event: openat
      filters:
        - data.pathname=/dev/net/tun
```

Run with `tracee --policy ./policy.yaml` — https://aquasecurity.github.io/tracee/latest/docs/policies/usage/cli/

Why these: `net_tcp_connect` is "a high-level event derived from the `security_socket_connect` LSM hook … avoids TOCTOU", carrying `dst_ip`, `dst_port` and DNS results, and it warns "the event generates data for each connection attempt, which can be substantial in high-traffic environments" — https://aquasecurity.github.io/tracee/latest/docs/events/builtin/man/misc/net_tcp_connect/. `fileless_execution` (TRC-105, T1620) and `dropped_executable` (TRC-1022, T1036) cover the dropper stage; `stdio_over_socket` (TRC-101, T1059.004) covers reverse shells.

The `openat` filter field is `pathname`, not `filename`, as in Tracee's own example policy (`data.pathname=/tmp*`) — https://aquasecurity.github.io/tracee/latest/docs/policies/usage/cli/

---

## 7. Overhead, side by side

| Tool | Documented cost | Source |
|---|---|---|
| bpftrace `kprobe:tcp_connect` | "overhead of this tool should be negligible … not tracing every packet" | bpftrace `tools/tcpconnect.bt` / bcc `tcpconnect_example.txt` |
| bcc `tcpconnect` | same, negligible; traces only connect functions | https://github.com/iovisor/bcc/blob/master/tools/tcpconnect_example.txt |
| Tetragon, all exec events | **1.68 %** overhead; 2.46 % with JSON to disk; ~1.5 M events @ 2.6 K events/s | https://isovalent.com/blog/post/tetragon-release-10 |
| Tetragon, network (worst case `netperf TCP_CRR`) | connection rate **−5.88 %**, ~26,250 req/s | same |
| Tetragon, FIM with in-kernel filter matching nothing | "nominal", near-baseline | same |
| Tracee | no published percentage found — **unverified** | — |

Rule of thumb: an unfiltered `sys_enter_setsockopt` or `sys_enter_openat` on a busy box is the danger zone; a `tcp_connect`-only probe is not.

---

## 8. Deployment order that costs nothing

1. `bpftrace tools/tcpconnect.bt` for 10 minutes. Anything non-RFC1918 from an unfamiliar `comm` is your lead.
2. Add the `interval:s:60` aggregation and the `execve` watch on `/tmp` + `/dev/shm`.
3. `tcplife` for 60 s to get bytes/second per PID — confirm "bandwidth", not just "connections".
4. `bindsnoop -t` if you suspect a transparent proxy; `IP_TRANSPARENT`/`SO_BINDTODEVICE` outside your known LB is essentially proof.
5. Only then install Tetragon and convert 1–4 into `TracingPolicy` with `Sigkill`, so the 1.68 % overhead is amortised and you get enforcement plus process ancestry.

---

## Sources

- https://tetragon.io/docs/use-cases/process-lifecycle/process-execution/ — always-on `process_exec`, `cwd` field
- https://github.com/torvalds/linux/blob/master/fs/ioctl.c — ioctl `cmd` arg name
- https://github.com/bpftrace/bpftrace/blob/master/docs/stdlib.md — `strncmp`, `strcontains`, `ntop`
- https://attack.mitre.org/techniques/T1496/002/ — Bandwidth Hijacking
- https://attack.mitre.org/detectionstrategies/DET0028/ — DET0028 / AN0080–AN0084
- https://attack.mitre.org/techniques/T1090/ — Proxy
- https://www.akamai.com/blog/security-research/proxyjacking-new-campaign-cybercriminal-side-hustle — campaign TTPs
- https://tetragon.io/docs/installation/faq/ — kernel 4.19 min, kernel config, BTF, Lockdown
- https://tetragon.io/docs/installation/package/ — systemd install, log paths
- https://tetragon.io/docs/reference/daemon-configuration/ — `--tracing-policy`, `--tracing-policy-dir`
- https://tetragon.io/docs/concepts/tracing-policy/hooks/ — kprobe/fentry/tracepoint, fentry ≥ 6.1, `sys_` prefix
- https://tetragon.io/docs/concepts/tracing-policy/argument_types/ — `sock`, `sockaddr`, `file`, path limits (5.3)
- https://tetragon.io/docs/concepts/tracing-policy/selectors/ — matchArgs/matchBinaries/followChildren
- https://tetragon.io/docs/troubleshooting/bpf-progs-stats/ — `tetra debug progs`, `kernel.bpf_stats_enabled`
- https://tetragon.io/docs/use-cases/network-observability/ — connect event shape
- https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/tcp-connect-only-private-addrs.yaml
- https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/filename_monitoring.yaml
- https://isovalent.com/blog/post/tetragon-release-10 — 1.68 % / 2.46 % / 5.88 %
- https://github.com/bpftrace/bpftrace/blob/master/docs/dependency_support.md — min kernel 6.1
- https://github.com/bpftrace/bpftrace/blob/master/docs/tutorial_one_liners.md
- https://github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc — `-l`, `-lv`, `-e`, `interval`
- https://github.com/bpftrace/bpftrace/blob/master/tools/tcpconnect.bt
- https://github.com/bpftrace/bpftrace/blob/master/tools/execsnoop.bt
- https://github.com/bpftrace/bpftrace/blob/master/tools/tcpaccept.bt
- https://github.com/iovisor/bcc/blob/master/INSTALL.md — kernel 4.1
- https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md — feature→version table
- https://github.com/iovisor/bcc/blob/master/tools/tcpconnect_example.txt
- https://github.com/iovisor/bcc/blob/master/tools/bindsnoop_example.txt
- https://github.com/iovisor/bcc/blob/master/tools/tcplife.py — inet_sock_set_state 4.16
- https://aquasecurity.github.io/tracee/latest/docs/install/prerequisites/ — kernels 5.4–6.5
- https://aquasecurity.github.io/tracee/latest/docs/policies/usage/cli/ — `--policy`
- https://aquasecurity.github.io/tracee/latest/docs/events/builtin/man/misc/net_tcp_connect/
- https://aquasecurity.github.io/tracee/latest/docs/events/builtin/man/security/fileless_execution/
- https://aquasecurity.github.io/tracee/latest/docs/events/builtin/man/security/dropped_executable/
- https://aquasecurity.github.io/tracee/latest/docs/events/builtin/man/security/stdio_over_socket/
- https://man7.org/linux/man-pages/man7/socket.7.html — SO_MARK, SO_BINDTODEVICE + CAP_NET_ADMIN
- https://man7.org/linux/man-pages/man2/IP_TRANSPARENT.2const.html
- https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/socket.h
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h — TUNSETIFF
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter_ipv4.h — SO_ORIGINAL_DST
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h — IP_TRANSPARENT
- https://github.com/torvalds/linux/blob/master/mm/memfd.c — `uname` arg name
- https://github.com/torvalds/linux/blob/master/net/socket.c — setsockopt arg order
- https://github.com/torvalds/linux/blob/master/security/security.c — `security_file_open`

---

## What I could not verify

- **No Tracee overhead percentage.** Tracee documents profiling tooling (`--server pprof`, the `evt stress` harness) but publishes no "% CPU" figure comparable to Tetragon's 1.68 % — https://github.com/aquasecurity/tracee/blob/main/docs/contributing/performance.md
- **No published bpftrace/Tetragon RSS figure for a bare Linux host.** The Tetragon docs' sample `systemctl status` shows ~151.7 MB, but that is one container image on one machine; treat as illustrative only.
- **Exact minimum kernel for each historical bpftrace release.** Current master says 6.1; the Debian bullseye man page says "4.x". The precise release-by-release floor was not confirmed from release notes.
- **`args.level` numeric values for `IPPROTO_IP` vs `SOL_SOCKET`** (0 vs 1) — standard UAPI, but I did not fetch a man page confirming both for this document; confirm with `-lv` and `/usr/include` before shipping the one-liner.
- **bpftrace `==` glob matching on `str()`** — no documented wildcard string comparison exists in the standard library, so §3.2 uses `strncmp()` instead; I did not test whether any given release happens to accept globs.
- **`tcp_connect` symbol availability** — it is a `static` function in `net/ipv4/tcp_output.c`; kprobes on static symbols need `CONFIG_KPROBES` and a resolvable symbol. bpftrace handles it in practice, but I could not test on this sandbox.
- **Tetragon `TracepointNamespaced`, CEL `matchCEL` semantics for sock arguments** — documented at a high level only; not verified in a running instance.
- **`dev_queue_xmit`/`skb`-based byte counting in Tetragon** as an alternative to `tcplife` — exists as an example policy but I did not confirm the emitted fields.
- No detection was validated against a live sample; every rule here is documentation-derived, and all syscall argument indices were cross-checked against kernel source rather than executed.

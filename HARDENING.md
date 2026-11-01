# Hardening pass — 2026-11-01

The refutation sweep in this repository's issues names, one detection family at a time, the cheapest
way past it. This file is the answer to that sweep: what was fixed, what was corrected because the
original claim was wrong, and what is left open because no host-side detector can separate the
workload from legitimate use.

It is written for the person who will run these checks, not for a marketing page. Where a fix is
partial, the residual bypass is named in the same row.

## How the sweep was triaged

Every issue got one of three outcomes:

- **fixed** — the check, rule or script now closes the named bypass, or closes enough of it that the
  remaining step is a different class of attack (for example, kernel compromise).
- **corrected** — the original detection claim was wrong, overstated, or measuring the wrong thing.
  The corpus now says so, and the check is either demoted to what it actually is or replaced.
- **known limitation** — after hardening, the signal is still identical to legitimate behaviour, or
  it lives outside the guest. The issue stays open and carries the `known-limitation` label. These
  are listed in full below.

Two claims in the sweep itself were also checked against source and found imprecise. They are
corrected here rather than repeated:

- **D23** said `IORING_OP_SOCKET`, `BIND`, `SENDMSG` and `CONNECT` are all auditable. In
  `io_uring/opdef.c`, `IORING_OP_SOCKET` carries `.audit_skip = 1`, as do `SEND` and `RECV`. Only
  `CONNECT`, `BIND`, `SENDMSG`, `OPENAT` and `OPENAT2` reach the audit filter. `bind` is in the
  kernel but is not yet in every `uringop_table.h`, so the shipped rule omits it rather than risk
  aborting the whole ruleset load.
- **D17** implied `saddr_fam` covers `sendmsg`. It does, but only when `msg_name` is non-NULL: the
  audit record is produced by `audit_sockaddr()`, reached through `move_addr_to_kernel()`, which
  `sendmsg_copy_msghdr()` skips when the message has no address. A connected `sendmsg` therefore
  matches no family-filtered rule. That gap is stated in the rules file.

## Cross-cutting limits that no check here closes

1. **Kernel-level compromise (P04).** An LKM, or an eBPF program attached ahead of the operator's,
   defeats every in-guest view at once: `/proc`, `ss`, audit and the operator's own probes. The only
   survivors are counters the guest cannot reach — provider billing, provider flow logs, a second
   host's records. Nothing in `checks/` changes this.
2. **Provider-side data.** Egress allowances, billing and abuse reports are outside the guest. They
   are the only tamper-proof view of a relay's volume, and a host operator does not control them.
3. **Indistinguishable workloads.** A real VPN, a real CI job, a real seedbox, a real restream and an
   employee's real remote desktop produce the same signals as their abused counterparts. These are
   the `known limitation` issues.
4. **Forwarded and offloaded traffic.** `meta skuid` needs a socket in the same netns; forwarded
   packets have no UID; macvlan, ipvlan and SR-IOV traffic does not cross the host interface
   counters. The nft forward-chain counters are the only in-host handle on routed bytes.

## The sweep, issue by issue

`fixed` = bypass closed in `checks/`. `corrected` = claim withdrawn or demoted. `known limitation` =
issue stays open.

| # | detection family | status | what changed, and what remains |
|---|---|---|---|
| D01 | `/proc/<pid>/exe` sweep | fixed | `triage.sh` classifies every image by whether its owner can replace it, instead of matching a list of staging directories. Adds inline-interpreter (`-c`/`-e`/`-m`) detection, executable anonymous mappings, a literal scan that needs no `go`/`strings`, and a coverage line that says how many processes were not inspectable. P03/P04 (hook, kernel) remain. |
| D02 | kernel-thread `comm` impersonation | known limitation | The kernel-thread case is closed and stays: a name matching `kworker*` with a resolvable image is always a lie. The general case cannot be closed — `comm` is a free-form 16-byte string, so a binary renamed `sshd` is indistinguishable from `sshd`. |
| D03 | Go/Rust build metadata | fixed | The metadata check is now a triage lead, not an attribution: `triage.sh` greps relay literals from any flagged image, which covers stripped Go, Rust and C builds and needs no toolchain. A legitimate `cloudflared` still looks like a squatted `cloudflared`; only destination and purpose separate them. |
| D04 | `/etc/ld.so.preload` | fixed | Parsed the way glibc parses it (`elf/rtld.c`: `#` blanks to end of line, entries split on space and colon), not the way rkhunter does. Adds per-process `LD_PRELOAD`/`LD_AUDIT` from `/proc/<pid>/environ`, which catches the per-user hook that never touches `/etc`. Deleted and writable-path libraries in `/proc/<pid>/maps` are reported. LKM case remains. |
| D05 | persistence recency + `lastlog` | fixed | The watch list now includes `crontab`, user units, `profile.d`, `pam.d`, `ld.so.conf.d`, `supervisor`, `at`, and per-user systemd units. mtime is compared with ctime, and packaged files are excluded from the backdating inference because archive extraction legitimately sets mtime to build time. Live-off-the-land edits remain a lead, not a catch. |
| D06 | listener inventory + port table | corrected | The port table is gone as a scoring rule. `triage.sh` prints every listener with its image and package owner (`dpkg`/`rpm`/`pacman`/`apk`), which answers the only useful question: did the operator install it. Dial-out-only families have no row and never will. |
| D07 | established sessions / `:7844` | fixed | The 7844 filter is kept as one vendor's edge, not as the family. `triage.sh` now groups every established TCP session by owning image and prints UDP sockets separately, so QUIC/MASQUE/hysteria are visible. Destination-based detection of CDN fronting is not possible from the host. |
| D08 | netns enumeration | fixed | Namespaces are grouped by inode with their pids, and the script now asks the runtime that should own them: `docker`, `podman`, `crictl`, `nerdctl`, `lxc`, `machinectl`, and the systemd scope list. Identification still needs an orchestrator; a bare inode count is not a finding. |
| D09 | netlink vs procfs | corrected | Count comparison replaced with a per-inode set diff, so churn does not create alarms and a filtered view cannot hide behind an unchanged total. The script now states what the sweep said: both views are accessors over one in-kernel table, so this is a hook indicator, not truth. |
| D10 | `ss -p` and the manual inode join | corrected | The join is kept, with the warning that it produces a confident wrong answer against `SCM_RIGHTS`: it names the holder, not the author. `cross-check.sh` says so in the output. Attribution that survives fd passing needs cgroup or eBPF, not `/proc/*/fd`. |
| D11 | `AF_PACKET` sweep | corrected | Moved out of the squatting path and labelled as what it is: a sniffer detector. Raw `AF_INET`/`AF_XDP` and eBPF XDP capture are named as not covered. |
| D12 | systemd `IPAccounting` per unit | fixed | `egress-watch.sh` samples services, scopes and slices in one `systemctl show --all` call, keeps per-unit deltas, warns on counter resets instead of discarding them, and compares the sum of unit deltas with the host interface counter. Thresholds come from `/etc/default/egress-watch`. Non-recursion is handled by summing leaves; a unit that exists only between samples is still missed, and the reset warning is the only trace. |
| D13 | nft per-UID counters | fixed | Kept as an inventory, with a second dynamic set counting forwarded bytes per output interface — the only netfilter handle on traffic with no socket. The file now states the three limits: netns mismatch, uid 0 as one bucket, and `nft flush ruleset` from root. |
| D14 | conntrack asymmetry | corrected | The asymmetry inference is withdrawn. Reply-heavy is a download, and a relay is often roughly balanced. `conntrack -L` stays as a peer and volume inventory, not as a tunnel detector. |
| D15 | vnstat / interface counters | fixed | `egress-watch.sh` sums every non-loopback interface, with a `/proc/net/dev` fallback, instead of one interface chosen by hand. macvlan/ipvlan/SR-IOV egress has no host counter and is named as the residual. |
| D16 | nethogs / bandwhich | corrected | Demoted to a triage tool. The "unknown TCP bucket should be near zero" claim is removed: on any container host it is not, and the failure mode is silent. |
| D17 | auditd socket/connect/bind | fixed | Adds `sendto,sendmsg` with `saddr_fam` (unconnected UDP, the normal QUIC/dnstt shape), `AF_PACKET`/`AF_VSOCK`/`AF_XDP` families, 32-bit twins, and `execveat`. The connected-`sendmsg` gap is documented in the file because audit cannot see it. Containers still carry an unset `loginuid`. |
| D18 | auditd `TUNSETIFF` | corrected | The rule is kept; the "highest-value rule" label is removed. WireGuard and every rtnetlink-created interface never call it, and userspace proxies need no interface at all. |
| D19 | netns creation rules | fixed | `setns(fd, nstype)` is now filtered on `a1&0x40000000`, which removes the noise that trained operators to ignore it. `unshare` and `clone` are filtered for both `CLONE_NEWNET` and `CLONE_NEWUSER`. `clone3` flags cannot be filtered by audit, so `probes.bt` reads `struct clone_args` instead of shipping a blanket rule that would flood on every `pthread_create`. |
| D20 | memfd + `execveat` | fixed | `-S execveat` is now in the ruleset, so the exec of a memfd payload is recorded even though `a4` (the flags) is not exposed. `probes.bt` prints the same event with the fd and flags. |
| D21 | `/etc` and persistence watches | fixed | Expanded to `usr/lib/systemd/system`, `profile.d`, `ld.so.conf.d`, `pam.d`. A `mount`/`move_mount` rule catches the bind-mount-over-a-watched-tree case (P09), which the inode-mark watches cannot see. The `dir=` mount-point caveat is in the file. `/etc` write noise is unchanged and still needs filtering by key. |
| D22 | module load / `-e 2` | corrected | Kept, with the ceiling stated: boot-time loads predate the rules, `audit=0` disables the subsystem, `-e 2` does not survive a reboot, and the userland class needs no module at all. |
| D23 | auditd io_uring filter | fixed | The rule now names `connect,sendmsg,openat,openat2`, and a separate `io_uring_setup` rule catches ring creation. `SOCKET`, `SEND` and `RECV` are `audit_skip` in the kernel and cannot be audited; `bind` is left out because the audit userspace opcode table does not resolve it everywhere. Data-plane volume through a ring remains invisible to audit. |
| D24 | audit backlog and `lost` | fixed | Backlog raised, `-r 0` (no rate limit) and `--loginuid-immutable` added. The operational fix is in the README: read `auditctl -s` at the moment of an alert, not on a five-minute sweep. `-f 2` is offered as an option in the file's comments, not forced, because it can halt the host. |
| D25 | `tcp_connect` probe | fixed | `probes.bt` adds `udp_sendmsg`, `execveat`, `clone3` and `io_uring_setup`, so the probe set is no longer TCP-only. Pre-existing flows are still invisible until they reconnect, and fd passing still attributes to the holder. |
| D26 | connect-vs-accept ratio | known limitation | A SOCKS relay is a server: it accepts from the local client and inside the tunnel. Adding an accept is one loopback listener. There is no residual signal to harden. |
| D27 | the six-probe set | fixed | `probes.bt` replaces it: `execveat`, `openat`/`openat2` still, `io_uring_setup`, `clone3` flags, TCP and UDP connects. The `setsockopt` volume probe is dropped because it fires on options, not on intent. |
| D28 | `tcplife` / `bindsnoop` | corrected | `tcplife` is described as a state-transition tracer, not a byte counter, with the already-established connection gap. `bindsnoop` is removed from relay detection: an outbound-only relay never binds. `ss -tin` is the free per-socket byte view. |
| D29 | Tetragon | corrected | The verdict is kept (best available), and the operational requirements are stated: both a TCP and a UDP policy, a liveness check, and a kernel that allows BPF. `Sigkill` is a restart loop for a supervised payload, not a block. |
| D30 | Tracee signatures | corrected | Removed as relay coverage. `fileless_execution`, `dropped_executable` and `stdio_over_socket` are a reverse-shell/dropper pack; the payload this corpus describes has no malware signature by design. |
| D31 | JA3/JA4 | known limitation | uTLS reproduces Chrome; REALITY reproduces the borrowed site's handshake. The fingerprint is a library fingerprint and the squat's design goal is to match it. The only residue is an allow-list of expected fingerprints per host, which is an inventory problem. |
| D32 | SNI / QUIC / WireGuard / STUN signatures | corrected | Kept as default-configuration signatures. Each has a published option that erases it (REALITY SNI, h3 mimicry, salamander, AmneziaWG, Gecko). STUN is removed as a detector. |
| D33 | BitTorrent handshake / DHT / tracker | corrected | Kept for default clients. MSE/PE `required` and a private tracker with DHT/PEX/LSD off erase every constant; the absence of DHT is the private-tracker signal, which is the population the file is about. |
| D34 | MSE/PE first-flight shape | corrected | The "port is neither 80 nor 443" clause is removed as a detector: it is under the attacker's control and it was the only specific part. Shape remains a weak triage signal. |
| D35 | SOCKS / stratum constants | corrected | Kept for default tools. `network-gaps.sh` adds the missing HTTP CONNECT case and names SOCKS-over-TLS and Stratum-over-TLS as erasing the constants. A relay that terminates SOCKS locally never puts it on the wire. |
| D36 | DNS entropy | corrected | The threshold is a starting point, not a control; a dictionary-plus-counter encoding stays under it. `network-gaps.sh` adds DoH/DoT endpoints and the DoH-proxy process case, which remove the DNS log entirely. |
| D37 | RITA beaconing / long connections | corrected | Beaconing is removed as a relay detector: a relay is client-driven and bursty. Long connections with steady bytes are kept as an inventory item, with the false-positive class stated. |
| D38 | Zeek WebSocket / `capture_loss` | corrected | The WebSocket shape is a notebook detector, not a squat detector. `percent_lost` is stated as the sensor's own coverage, not the network's: GRO/LRO, a dropped ring buffer and a tap that was never installed all report clean. |
| D39 | Tor exit / Onionoo | fixed | `external-vantage.sh` now queries both address families and states that the bulk exit list is IPv4-only, so an IPv6-only exit is unlisted. Churn is stated: a short-lived exit is unlisted for most of its life. |
| D40 | Shodan InternetDB | corrected | Reframed as an exposure check. A dial-out-only relay publishes no port, and scan freshness is not a promise. |
| D41 | CT / passive DNS | corrected | Reframed as exposure. A relay needs no name; CDN universal TLS logs the CDN's name, not the tenant's. |
| D42 | RDAP / PTR / ASN | fixed | `external-vantage.sh` extracts the abuse contact from the RDAP entity graph and, when there is none, prints the fallback chain (IANA whois, RIR whois, PeeringDB) instead of silently producing nothing. |
| D43 | DNSBL / AbuseIPDB / Shadowserver | corrected | Reframed as a lagging indicator the business model is designed to outrun. The `127.255.255.0/24` error-code trap is kept as a warning. |
| D44 | endlessh / Cowrie | corrected | Moved to entry detection, where they belong. A squat installed with credentials or through an exposed service never touches SSH. |
| D45 | canarytokens / `chattr +i` / atime | corrected | `chattr +i` is demoted to a deletion guard, which is what it is. atime's `relatime` behaviour is stated. The token-domain blocking bypass is named, and auditd/inotify is the read tripwire. |
| D46 | `systemd.path` | corrected | The fix is in the report: set `TriggerLimitIntervalSec=0` / `TriggerLimitBurst=0`, monitor `systemctl --failed`, and know that dotfiles are ignored and that `PathExists=` fires on a transition, not on a read. |
| D47 | auditd read watches | corrected | Kept as the right tool, with the three bypasses stated: bind mount over the watched tree, `mmap` (no read syscall), and io_uring `READV` (`audit_skip`). inotify overflow is named. |
| D48 | Jupyter runtime artifacts | corrected | Reframed as attribution of a careless user, not detection. A terminal tab writes no IPython history; `IPYTHONDIR` and `JUPYTER_RUNTIME_DIR` are user-controlled; the files are deleted on clean shutdown. |
| D49 | notebook cgroup / allow-list | fixed | The control that survives is `IPAddressAllow` with no resolver in the list; the report no longer recommends allowing a resolver, because a resolver is a general-purpose tunnel egress (P21). Scope enforcement at spawn is kept; `systemd --user` and rootless podman are named as escapes. |
| D50 | Docker/kubelet API exposure | fixed | `triage.sh` now checks the Unix sockets — `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock` and the rootless per-user socket — with their modes, because those are the API that is always there. A kubelet client certificate or service-account token defeats the exposure check and is named. |
| D51 | Kubernetes object / RBAC / metrics | corrected | One-shot sweeps are replaced by snapshot-diff guidance: an edited DaemonSet image is a one-field diff on an old object. `hostNetwork` pods are named as invisible to cAdvisor's veth metric, and static pods as having no mirror object. |
| D52 | torrent daemon / seedbox shape | known limitation | Name and port are free. `read_bytes` is a page-cache measurement. The only durable signal is sustained one-way egress, which is a byte counter, and a private-tracker seeder inside a provider's allowance is indistinguishable from a legitimate mirror. |
| D53 | CI runner detection | known limitation | A self-hosted runner is a legitimate runner. Unsetting `GITHUB_ACTIONS` and running detached is enough, and the `meta` IP ranges only answer "did this come from GitHub-hosted infrastructure". Names and env are demoted to triage leads. |
| D54 | RDP/VNC listeners and logon telemetry | known limitation | The listener and configuration checks are exact and stay. The behavioural half cannot separate a valid RDP session from a valid RDP session: type 10 is what every legitimate logon is, and the actor who owns the box owns the log. |
| D55 | open relays / reflectors | corrected | The SMTP self-test is kept for open SMTP. API mail (SendGrid/SES/Telegram/Discord over 443) has no SMTP socket and is named as the normal path. A resolver restricted to a trusted list still recurses for a tenant, so "closed to the test" is not closed. |
| D56 | restreaming / IPTV | corrected | The origin counters (`nclients`, `bytes_out`) are the only strong item and exist only when the operator's media server is the origin. A push to a CDN moves the fan-out off the host, and `ffmpeg -i -` removes the URL from the command line. |
| D57 | provider idle reclamation / allowances | known limitation | This is provider-side, outside the guest. The 95th-percentile rule is a duty-cycle exemption by construction: an hour a day at full rate is inside it. A host operator cannot see the provider's billing, and the provider's rule is not tunable from the host. |
| D58 | the censor-side classifier | known limitation | Not a detection the operator can run, and not available to query. It is the design driver for REALITY/uTLS/XHTTP, which is exactly why D31-D38 lose. Kept as explanation, not as a control. |
| D59 | coverage gaps | fixed | `network-gaps.sh` adds HTTP CONNECT, `ssh -D/-R/-w`, DNS-tunnel clients, DoH/DoT, ICMP counters and raw sockets, vsock, io_uring users and user namespaces. `baseline.sh` provides the missing method for "traffic that does not match the unit's declared purpose". Provider flow logs are named as the view the guest cannot edit. TLS-in-TLS remains a stated non-capability. |

## Known limitations (issues left open)

These are the eight that survive hardening because the signal is identical to legitimate use, or
because it is outside the guest. They are labelled `known-limitation` and stay open.

### D02 — `comm` is not identity

`prctl(PR_SET_NAME)` sets 16 bytes; `exec -a` sets `argv[0]`; the binary can simply be named
`sshd`. The kernel-thread case (`kworker*` with an image) is a tautology and stays, but no name-based
rule can distinguish a renamed relay from the daemon it is named after. The only name-independent
identity is the image inode and its package ownership, which D01 and D06 now use — and which a
`pip install --user` payload shares with legitimate software.

### D26 — a proxy is a server

Connect-vs-accept is a shape heuristic on a name. A SOCKS relay accepts from its local client and
inside the tunnel; a loopback health endpoint supplies an accept for any window. Nothing remains to
harden once the payload has accepts.

### D31 — the TLS fingerprint is the browser's

uTLS reproduces Chrome's ClientHello; REALITY forwards unauthenticated probes to a real site, so
JA4 and JA4S match the borrowed site. The squat's design goal is exactly this. An allow-list of
expected fingerprints per host is an inventory control, not a flow detector.

### D52 — a private seedbox is a mirror

Sustained one-way egress inside a provider's allowance is what a legitimate mirror, a backup target
and a package cache also produce. The name and port are free; the disk signature is page-cache
dependent. For a provider whose policy does not name torrents, there is no positive signal left.

### D53 — a self-hosted runner is a runner

Unset `GITHUB_ACTIONS`, rename the agent, start detached, and the remaining checks describe a
legitimate CI runner. GitHub's `meta` ranges answer a different question (hosted or not). This is a
supply-chain and account-ownership problem, not a host-detection problem.

### D54 — a valid RDP session is a valid RDP session

Type 10 logon, NLA, a working desktop: the events are the same for the employee and the squatter.
The listener and configuration checks are exact; the behavioural half cannot be.

### D57 — the only tamper-proof detector is outside the guest

Provider billing and abuse reports cannot be hooked, forged or uninstalled from inside the host —
which is exactly why the business model is account churn. The 95th-percentile idle rule ignores the
top 5 % of samples, so a bursty workload is inside it by construction. A host operator cannot read
the provider's rule or the provider's flow logs.

### D58 — the other detector in the path is not available to you

The censor-side classifier is a network-side system the operator neither runs nor can query. Its
value in this corpus is explanatory: it is why flow-shape detection loses, and why "indistinguishable
from a browser" is a design goal. Nothing here can be hardened against it because it is not ours.

## What changed in the repository

| file | change |
|---|---|
| `checks/triage.sh` | rewritten: writability classification, interpreter and anonymous-exec detection, no-toolchain literal scan, glibc-exact preload parsing, per-process linker hooks, package-owner listener column, runtime sockets, expanded persistence with ctime, coverage accounting |
| `checks/cross-check.sh` | rewritten: per-inode set diff instead of counts, inode-to-pid join with the holder-vs-author warning, preload environment |
| `checks/network-gaps.sh` | new: HTTP CONNECT, `ssh -D/-R/-w`, DNS tunnels, DoH/DoT, ICMP, vsock, io_uring, user namespaces, and a list of what is not visible |
| `checks/overlay-nets.sh` | new: mesh/overlay squat indicators — TUN interfaces, mesh process names, state directories and units, mesh-written nftables rules, coordination-endpoint flows (research/overlay-mesh-networks.md) |
| `checks/baseline.sh` | new: per-unit egress baseline, declared purpose and allowance, drift report |
| `checks/egress-watch.sh` | rewritten: services+scopes+slices, reset warnings, host-vs-unit comparison, configurable thresholds |
| `checks/egress-watch.service` | `EnvironmentFile=-/etc/default/egress-watch` |
| `checks/egress-watch.timer` | randomised delay |
| `checks/accounting.nft` | forwarded-traffic per-interface counters; documented limits |
| `checks/50-proxyjack.rules` | `sendto,sendmsg`, more families, 32-bit twins, `execveat`, filtered `setns`, user namespaces, `mount`, more persistence dirs, `bpf`, io_uring network opcodes, backlog and rate settings |
| `checks/probes.bt` | new: `execveat`, `clone3` flags, `io_uring_setup`, UDP and TCP connects |
| `checks/external-vantage.sh` | rewritten: both address families, abuse-contact extraction with fallback, exposure-vs-relay framing |
| `checks/README.md` | rewritten to match |
| `REPORT.md` | detection tiers corrected: asymmetry withdrawn, resolver allow-list removed, `chattr +i` demoted, `systemd.path` limits, JA4 framed as indistinguishable |
| `research/*.md` | a corrective note at the top of each deep dive that the sweep touched |

## Verification

Run in the environment this pass was written in (Linux, no systemd, no bpftrace, non-root):

- `triage.sh` — executed end to end; the preload parser was tested against a fixture with comments,
  spaces and colon separators; the ctime/package-owner path was exercised (the test host's file was not
  owned by its package database, which is the output the check is supposed to give).
- `cross-check.sh` — executed; inode sets agreed on an idle host; the `ino:0` comparison bug was
  found and fixed during the pass.
- `network-gaps.sh` — executed; the ICMP counter parsing was corrected against `/proc/net/snmp`
  (the key field carries the colon).
- `egress-watch.sh` — executed with a temporary state directory; `/proc/net/dev` fallback verified
  (the sysfs counters are absent in a container).
- `baseline.sh` — `record` and `report` executed with a temporary directory.
- `external-vantage.sh` — executed against the live Electrosphere; RDAP abuse extraction returned a
  real contact for the test address.
- `accounting.nft` — parsed with `nft -c`; the first draft used `chain fwd`, which is a reserved word,
  and was renamed.

Not executed here, because the environment does not have them:

- `50-proxyjack.rules` — no root auditd. Syntax was checked against `auditctl(8)`, the audit userspace
  opcode table, `io_uring/opdef.c` and `net/socket.c`; load it with `augenrules --load` and verify
  with `auditctl -l` before applying `-e 2`.
- `probes.bt` — no bpftrace. Probe names and tracepoint fields were checked against
  `include/trace/events/syscalls.h` and the kernel opcode definitions. Run `bpftrace -d` first.
- `egress-watch.sh` against real systemd accounting — the container has no systemd units.

Facts re-checked first-hand while writing this (not relayed from the sweep):

- glibc `/etc/ld.so.preload` parsing: `elf/rtld.c`, `#` blanks to end of line, split on space and
  colon.
- `saddr_fam` population: `net/socket.c`, `move_addr_to_kernel()` call sites for `bind` (1974),
  `connect` (2181), `sendto` (2273) and `sendmsg` (2619, only when `msg_name` is non-NULL).
- io_uring auditability: `io_uring/opdef.c` — `SOCKET`, `SEND`, `RECV` carry `.audit_skip = 1`;
  `CONNECT`, `BIND`, `SENDMSG`, `OPENAT`, `OPENAT2` do not.
- io_uring opcode enum and the audit userspace `uringop_table.h` (no `bind`/`socket` entry).
- `PR_SET_MM_EXE_FILE = 13`, `CLONE_NEWNET = 0x40000000`, `CLONE_NEWUSER = 0x10000000`,
  `AF_PACKET = 17`, `AF_VSOCK = 40`, `AF_XDP = 44` (kernel UAPI headers).
- `auditctl(8)`: the `io_uring` filter and `-q mount-point,subtree` both exist.

## Using the hardened checks

```sh
sudo sh checks/triage.sh            # image paths, preload, sockets, runtime, persistence
sudo sh checks/cross-check.sh       # do two kernel views agree, per inode
sudo sh checks/network-gaps.sh      # the channels the old corpus did not check
sudo sh checks/baseline.sh record   # what normal looks like, before an incident
sudo sh checks/baseline.sh report   # what changed, with declared-purpose comparison
sudo sh checks/external-vantage.sh  # what the outside world says (exposure, not relay)
```

Install the accounting and rules as before, but read the comments in each file first: every file now
names the bypass it does not close, so a clean run is not mistaken for a clean host.

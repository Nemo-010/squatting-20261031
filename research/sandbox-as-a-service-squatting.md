# Squatting a vendor's GPU notebook sandbox: root in the guest, the GPU as the prize

> **First-hand case, 2026-11-01, sanitised.** One hour of tenant-privileged operation inside a
> free-tier, GPU-equipped notebook sandbox from a platform called **VendorX**. Nothing was exploited:
> every capability below was handed to the platform's own tenant. Platform names, addresses, pod
> identifiers, tunnel hostnames and key material have been replaced (`VendorX`, `192.0.2.x`,
> `203.0.113.x`, `XXXXX.tunnel.invalid`).
>
> The case has two lessons and they point in opposite directions. On the abuse side, the corpus'
> prize lane — relaying with no socket footprint — is *closed* here by the isolation model, and the
> lane it falls back to is the most visible one. On the detection side, the platform's only guardrail
> is a mining string-match against one file, and the cheapest thing that would have caught this run
> is a directory listing rather than any network signal.
>
> **Citations.** The evidence tree is not part of this repository — it is one real host's state, and
> even sanitised it is not something to publish. Citations name its files (`devbox-recon/NN-name.txt`,
> `DEVBOX_REPORT.md`, `CASE.md`, `ALLOWLIST-SUMMARY.md`) so the reasoning can be audited by anyone
> holding the tree. Every claim below is written to stand without it: the commands, the error classes
> and the control being exercised are all in the text.

*Scope: a Linux workload inside a gVisor (`runsc`) pod on a notebook-as-a-service platform, observed
from inside that guest and with the platform's own in-guest guardrail readable. No NDR, no commercial
agent, no node access.*

## Summary

- **The tenant is root.** `uid=0(root)` on issue, with a capability set that removes `CAP_SYS_ADMIN`,
  `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF` and `CAP_PERFMON`. The boundary that matters is the pod,
  not the user.
- **The prize is the GPU, not the CPU.** 20 vCPU and 160 GiB are the advertised grant; a 96 GB
  datacentre GPU with a working CUDA stack on a free tier is the scarce good. Disk is not a
  constraint at all — the overlay reports 8 EB and 100 GB allocations succeed.
- **Every single-host detection tier in this corpus is unavailable or tautological here.** No
  systemd, so no `IPEgressBytes`; no auditd; `ss` cannot open `NETLINK_SOCK_DIAG`, so the socket view
  is raw `/proc/net/tcp`; cgroup v1 mounts no `net_cls`/`net_prio`. And the tenant *is* the operator,
  so in-guest introspection is a tool the squatter runs on themselves.
- **The socket-less relay lane is closed.** No `TUN`, no raw sockets, no `iptables`. The squat falls
  back to a loopback userspace proxy plus one long-lived outbound TLS session, which is the most
  inspectable shape the corpus knows.
- **Egress policy is per-port and per-destination, not per-allowlist.** A 913-domain registry list
  sits beside the tree and enforces nothing observable; a host that listens on every port is the
  cheapest instrument for telling the port control from the destination control.
- **Ingress survives the destination policy by edge pinning.** Two tunnel services were unreachable on
  22 and 443 by timeout; a third worked on 443 once one reachable address was pinned out of its
  round-robin set, with `HostKeyAlias` keeping host-key verification sane against a literal address.
- **The platform's guardrail is a mining detector that cannot be turned into a squat detector.** 15
  literal substrings, one file, 300-second poll, fail-open, enforced by a name-based `pkill`. This run
  was not mining and never put a line in that file; it passed by construction.
- **What would have caught it is cheaper than what it defends against.** A file that appears after
  boot in the notebook tree, a DNS answer the filtering middlebox already logged, and one long-lived
  outbound session to a single address — all D0–D2, none of which needs anything inside the guest.

## 1. What the case proves

### 1.1 Assumptions that collapse

| Corpus assumption | Collapse | Evidence |
|---|---|---|
| Relay squatting wants a socket-less lane (L3/tun) to stay out of socket inventory | Unavailable: `!cap_net_admin`, `!cap_net_raw`, `!cap_sys_admin`; no `/dev/net/tun`, no `iptables`, no raw sockets. A tmpfs inside a user namespace is namespace-local and buys nothing | `devbox-recon/08-privileges.txt`, `devbox-recon/31-mount-loop.txt` |
| A registry or egress allowlist bounds where a squat can talk | Not enforced in any way this tree demonstrates: 913 domains, no tunnel/relay/VPN/mesh name among them, while arbitrary destinations on 443 are reachable | `ALLOWLIST-SUMMARY.md`, `devbox-recon/50-portmap.txt` |
| Storage is a limiting resource a defender can watch | Void: `statfs` reports 2^51−1 blocks (a sentinel), 10/50/100 GB `fallocate` all exit 0, no block devices exist at all | `devbox-recon/25-storage.txt`, `devbox-recon/33-capacity.txt`, `devbox-recon/04-blockdevices.txt` |
| Squatting requires crossing a tenancy boundary | It does not: the tenant holds `UID 0` in the guest on issue, so there is no crossing to detect | `devbox-recon/01-identity.txt` |
| A platform code guardrail terminates a misused notebook | Only if the misuse is mining **and** lives in one file **and** is present at a 300-second tick | `devbox-recon/32-suspicious.txt` |
| The unit of arbitrage is CPU-hours | It is GPU-hours: `torch.cuda.is_available()` is true, 96 GB, driver and CUDA present | `devbox-recon/61-gpu.txt` |

### 1.2 Assumptions that hold

| Assumption | Status | Evidence |
|---|---|---|
| Process-hiding artefacts are the highest-signal squat indicator | Holds and hardens: a THC-style process hider present in the notebook tree seven minutes after boot, never executed, is the one artefact here with no legitimate reading | `devbox-recon/14-app.txt`, `DEVBOX_REPORT.md:1043` |
| Flow-level heuristics are the surviving detection layer | Holds by elimination: with no in-guest accounting, flow is the only channel. Volume is small and the destination is a legitimate CDN edge, so the heuristic must be precise, not broad | `research/network-flow-heuristics-proxyjacking.md` |
| The notebook kernel is the tenancy unit | Holds, and is all that is left: the application is PID 1 and one file is the platform's entire view of intent | `devbox-recon/32-suspicious.txt` |
| Container-layer containment works | Partly. Rootless podman fails on `newuidmap` EPERM; `proot` runs a pulled rootfs with no kernel isolation, so containment is a policy statement, not a mechanism | `devbox-recon/87-proot.txt`, `devbox-recon/100-proot-container.txt` |

### 1.3 The structural read

**The GPU is the prize.** 20 vCPU and 160 GiB match the advertised tier, so a workload using all of
both is not anomalous *for this tier*. A 96 GB datacentre GPU on a free tier is. This is the
GPU-arbitrage problem of `research/hpc-slurm-gpu-squatting.md` with the scheduler removed: the lease
is the notebook session, the grant is the device, and the accounting that would notice (Slurm's
`TRES`) exists nowhere here.

Two negatives follow from the isolation model rather than from policy. The capability set removes
every kernel-side relaying lane — no DNAT, no `mirred`, no sockmap redirect, no tun fd — so a relay
must live in userspace where `/proc/net/tcp` sees it (`research/no-socket-relays.md` lanes A–C are all
unavailable). And the sentinel overlay removes capacity as a signal: no fill-rate, no quota, no
ENOSPC.

## 2. Egress and ingress, measured

Three mechanisms came out of the hour and all three generalise past this vendor.

### 2.1 Port-policy triage: three outcomes, three different controls

A host listening on every TCP port was the probe. The result was neither "everything open" nor
"everything closed", which is the usual failure of a boolean port check:

| Result | Meaning | Control implicated |
|---|---|---|
| `TimeoutError` | packets dropped before any reply | a filter on port and/or destination |
| `ConnectionRefused` | RST returned | the far end is not listening — **not** a filter |
| connect succeeds | path works | nothing |

7844 and 7835 time out against every destination tried; 21, 25, 1080 and 3389 are refused; most other
ports connect (`devbox-recon/50-portmap.txt`, `devbox-recon/47-ports.txt`). A refused 1080 is routinely
logged as "SOCKS is blocked" when no control plane ever acted. Only a timeout implicates a filter, and
only a timeout that repeats across destinations implicates a *port* filter rather than a *destination*
filter.

**Cheapest variant:** one listener bound to every port on a host you control, and a script that dials
`target:port` over a fixed list and records the exception class rather than a boolean.

### 2.2 Edge pinning: a timeout may mean "this edge", not "this service"

Two SSH-based tunnel services were unreachable on both 22 and 443 by timeout
(`devbox-recon/85-alt-tunnels.txt`). A third succeeded on :443 once one reachable address was pinned
out of its round-robin A records. The shape of the working invocation:

```console
$ for ip in $(getent ahostsv4 a.tunnel.example | awk '{print $1}' | sort -u); do
>   timeout 4 bash -c "echo > /dev/tcp/$ip/443" && echo "$ip OPEN"; done
192.0.2.20 OPEN

$ ssh -4 -p 443 -T -o HostKeyAlias=a.tunnel.example \
>     -R 0:127.0.0.1:8080 root@192.0.2.20
Allocated port 6 for remote forward to 127.0.0.1:8080
Your tunnel will expire in 60 minutes.
https://XXXXX.tunnel.invalid
```

(`devbox-recon/88-tunnel-ips.txt`, `devbox-recon/93-tunnel-pin.txt`, `devbox-recon/94-tunnel-verify2.txt`,
`devbox-recon/95-tunnel-script.txt`.)

`HostKeyAlias` is the part people get wrong: verification is against the *name* the key was issued
for, while the connection goes to a literal address, so pinning does not require disabling host-key
checking. The same shape explains the Cloudflare result from the other side — its transport port is
blocked globally, so the quick tunnel dies at its precheck and the issued URL serves 530
(`devbox-recon/44-cloudflared-run.txt`, `devbox-recon/45-cloudflared-verify.txt`). Blocked at the
port, not at the edge.

**Generalisation:** any service whose name resolves to a set is a candidate. Resolve, dial each record,
pin the first that answers. A timeout against a name collapses into an address-level fact the moment
the set is enumerated. Why one edge is filtered remains unproven; a destination-range filter, a bad
anycast path and per-record blocking are all consistent with what was seen.

### 2.3 A DNS-layer filter is not defeated by changing resolvers

The filtering middlebox is identifiable from inside by its own TLS material: a certificate whose
subject names the filtering product, and a `Website Filtered` block page on the intercepted host
(`devbox-recon/43-tunnel-pre.txt`, `devbox-recon/46-dnsmiddlebox.txt`). It answers authoritatively for
named domains while relaying a genuine address for others, so pointing at a different public resolver
changes nothing: the client is never talking to the destination.

What worked was a path that leaves before the middlebox sees the name. Tor bootstrapped in about nine
seconds; the filtered control plane answered `200` through it, `git ls-remote` succeeded through it,
and an HTTP proxy wrapper on loopback made it usable per command (`devbox-recon/59-tor.txt`,
`devbox-recon/62-tor-deep.txt`, `devbox-recon/75-privoxy.txt`, `devbox-recon/83-tor-exec.txt`).

Two limits worth recording. Tor does **not** unblock 7844 — it defeats name-based filtering, not
port-based (`devbox-recon/62-tor-deep.txt`). And a global proxy variable breaks the direct access that
already works, so the proxy has to be opt-in per command.

## 3. The platform's guardrail, as read from inside

`/usr/local/_vendorx/malicious_code.py` plus a polling wrapper, both readable from the guest
(`devbox-recon/32-suspicious.txt`, described at `DEVBOX_REPORT.md:1053`).

| Property | Value | Consequence |
|---|---|---|
| Patterns | 15 substrings, case-insensitive | vocabulary-bound |
| Target | one path, `/vendorx/notebook.py` (81 bytes) | everything else is unscanned |
| Cadence | `sleep 300` | sub-300-second workloads escape |
| On read error | `return True` | fail-open |
| On empty or missing file | `return True` | the default state is a pass |
| Enforcement | `pkill -9 -f "vendorx.*notebook.py"`, fallback `pkill -9 -f "vendorx"` | name-based |
| On violation | `exit 42` from the poller | the platform would have to read a child's exit code |

The vocabulary is entirely mining: `xmrig`, `cpuminer`, `minerd`, `stratum+tcp`, `cryptonight`,
`monero`, `donate-level`, `mining-pool`, `blockchain-mining`, plus pool hostnames. That is a coherent
list for a GPU platform, because mining is what burns the cost centre the platform sells.

**What it structurally cannot see**, in the order that matters:

1. **Anything not spelled in `notebook.py`.** Every action in this run went into a shell, into helper
   scripts under `/usr/local/bin`, and into argv. The notebook stayed at four lines with an empty cell
   for the entire session (`devbox-recon/14-app.txt`). The control's only input was empty.
2. **Anything with a different vocabulary.** A tunnel, a SOCKS proxy, a Tor client and an `ssh -R`
   share no term with that list. Neither does a process hider.
3. **Anything shorter than 300 seconds**, anything that removes itself, anything that empties the file.
4. **Anything the enforcement misses**, because the remediation resolves its target by name from
   inside the same namespace it is policing.

One detail dates the list: the first entry is `prvietedu/probable-memory`. That is not a mining
indicator and does not match a plausible string anyone would type. A blacklist with a dead first entry
has not been tested against its own target.

### 3.1 Eight ways past it

The eight below are what remains once the workload *is* mining-shaped — that is, once the naive case
is gone and the list would otherwise apply. Labelled by what they actually defeat.

**(a) Payload never in `notebook.py` — detection bypass.** The file set has cardinality one. A payload
in `/tmp`, in `~/.cache`, in a package or inside a `proot` rootfs is unread, and a notebook is a stub,
so four lines is the natural state.

**(b) Opaque blob fetched and executed — detection bypass.** The match is a literal substring on text.
A base64 or gzip blob contains no literal and its decoded form is never read. The fetch is an ordinary
HTTPS GET, indistinguishable from a dependency download.

**(c) Package build step that fetches — detection bypass.** A PEP 723 script block names dependencies;
resolution and build run code the checker never reads. The machinery is live here: `export_deps.sh`
runs `uv export --script /vendorx/notebook.py` and prunes about sixty preinstalled packages
(`devbox-recon/32-suspicious.txt`).

**(d) `.pyc` — detection bypass, twice over.** The checker calls `read_text(encoding="utf-8")` on a
path. Point it at a compiled module and the decode raises; the bare `except` returns `True`. Bytecode
is compressed *and* the read would fail if it were not.

**(e) `memfd` + `execveat` — detection bypass.** A payload with no path on disk has no file to read
and its `/proc/pid/exe` link is the anonymous description. Whether `runsc` permits `memfd_create` and
`execveat` here is untested; a deleted-open file has the same effect against a path-based reader.

**(f) argv and environment cleared, process renamed — detection bypass.** Both kill paths are `pkill -f`
on command lines. A process that rewrites its `argv` region and sets its task name matches neither.
The tool is present and was never used: it advertises `-a <name>`, `-f` (follow children) and `-E`
(keep the environment), and contains `PTRACE_GETEVENTMSG` (`devbox-recon/14-app.txt`). `-E` is the
tell — plain `execve` already clears the environment, so the option exists to remove the post-exec
fingerprint.

**(g) The 300-second window and the pass conditions — detection bypass.** Write, run, delete inside one
interval; the poller reads a missing file and returns `True`. A guardrail with a bare `except` is
defeated by any input it cannot parse, so an unparseable or blank file is the cheapest bypass of all.
This is also the only bypass here with a clean timing signature: a sawtooth mtime against a 300-second
grid.

**(h) Enforcement resolves by name — enforcement bypass; detection stays intact.** When the checker
does fire, the poller finds its target with `pgrep -f "vendorx"`. Run the application under any other
name and both patterns miss; the script takes its own `else` branch, prints `Could not find vendorx
process. Sandbox may continue running.`, exits 42, and the workload keeps running. Worse, the poller's
own command line contains `_vendorx` in its path, so `pkill -9 -f "vendorx"` can match the enforcement
process itself — on a reading of the script (not an observed run) the kill lands before `exit 42` is
reached, ending the enforcement loop rather than the squat. The strategic point does not depend on
which of those happens: **detection fired, enforcement missed.** A control whose remediation looks up
its own target by name, inside the namespace it is policing, is advisory.

## 4. The play

How a tenant would squat a VendorX-class notebook sandbox with near-zero detection. Command *shapes*,
not invocations, and the observable each one leaves.

**Phase 1 — acquire with no payment trail.** *Decision:* treat the session as burnable. The tier is
free, the application is PID 1, the only tenant-visible identity is a read-only token file, so nothing
survives and nothing is worth defending. *Observable:* an account taking the GPU tier first and never
running an interactive cell. Acquisition-side, not in-sandbox.

**Phase 2 — egress past the port policy.** *Decision:* no tunnel. Most ports are allowed; the
exceptions are narrow enough to design around, and a tunnel costs a 60-minute lifetime, a rotating URL
and extra loopback listeners. *Observable:* loopback listeners on 9050/8118 and a session-start
consensus fetch.

**Phase 3 — ingress past the destination policy.** *Decision:* if a callback is genuinely needed, pin
an edge rather than take the resolver's first answer, and pin on 443, the port the policy treats most
permissively. *Observable:* one long-lived outbound TCP to a pinpointed address on 443, plus a public
URL that redirects to a login page. The address is the tell; the URL is not.

**Phase 4 — stay inside the tenant's namespace.** *Decision:* loopback only, tenant UID only, nothing
touching another party. This is less a constraint than the property that makes the squat unremarkable:
a session that talks only to public endpoints on 443 and binds only on loopback is a development
session.

**Phase 5 — decide whether to hide processes, and price it.** *Decision:* **do not**. Cost: the
binary's presence, size, strings and hash are the one artefact here with no legitimate reading, and it
appeared seven minutes after boot untouched. Benefit: it defeats `pkill -f`, which is already defeated
by not being named the expected thing (§3.1h) — a high-signal artefact traded for a bypass already
held. The cheap substitution is to set the task name and rewrite `argv` from inside the interpreter.

**Phase 6 — make the resource shape unremarkable.** *Decision:* do not conceal usage; conform it.
20 vCPU and 160 GiB are the advertised grant, so a saturating job is not anomalous for this tier. The
GPU is different: a four-line stub with the device at steady saturation is the one shape that reads as
abuse. Bursts with idle gaps, matching an evaluation-or-training cadence; host RAM below the ceiling so
no OOM event records a footprint. *Observable:* `nvidia-smi` utilisation, power draw and process list —
the pattern, not the level.

**Phase 7 — handle the guardrail.** *Decision:* keep the notebook at four lines permanently and treat
it as configuration, not code: fetch one opaque blob at session start, execute it from a directory the
checker does not read, let the stub name a dependency rather than a payload. Skip the timing trick
(§3.1g) — the only bypass with a clean sawtooth signature against a fixed grid. *Observable:* one
session-start fetch; a stub that never changes.

**Phase 8 — the persistence question.** *Decision:* **none on the host**; there is nothing durable to
persist to. PID 1 is replaced every session, the device is session-scoped, and holding the GPU means
holding the account rather than the host. Durable artefacts are the bootstrap blob and whatever the
workload produces. *Observable:* the same cold-start fetch to one destination across successive
short-lived sandbox identities — the strongest flow-side signature the play emits.

### 4.1 Where this breaks

1. **Ingress lifetime.** A free tunnel expires in about 60 minutes and the URL changes on restart.
   Anything needing a stable callback fails; the fallback is beaconing from inside the sandbox, which
   the platform already permits as ordinary egress.
2. **The empty notebook with a pegged device.** Every bypass in §3.1 targets the *file* control. None
   touches the resource control. A sandbox whose declared workload is one empty cell and whose GPU is
   busy for the session's duration is the residual observable, and no payload-relocation trick reduces
   it.
3. **Tenant-namespace-only works only while accounting lives outside the guest.** The whole play
   depends on there being no counter it cannot see. One byte counter on the pod's veth, or a socket
   counter in host eBPF, closes phases 2, 3 and 8 at once, and nothing inside the guest can detect or
   evade it. The evidence that this is absent is exactly the evidence that makes the squat work: no
   systemd, no auditd, `ss` cannot open netlink.

## 5. Who can see what

Three parties. They do not see the same system, and two of them cannot act on what they see.

| | platform | tenant (root in guest) | outside |
|---|---|---|---|
| **sees** | pod lifetime, pod UID, sandbox and notebook IDs, GPU assignment, image, clone rate, the pod's veth, the DNS middlebox's answer stream, the NAT pool | every process, every file, `/proc/net/tcp`, the GPU, the guardrail itself | one TLS session to an edge on :443; the tunnel URL; the HTTP origin behind it |
| **cannot see** | anything inside the sentry: process names, files, per-socket attribution below pod granularity | the node, other tenants, the platform API, its own NAT mapping, the DNS query log | which sandbox, which tenant, or that a sandbox is involved |
| **tiers available** | 1 (pod granularity), 4 (node-side flow, if mirrored), 5 | 0 only | 4, 5 |
| **tiers unavailable** | 0, 2, 3, 6, 7 | 1, 2, 3, 4, 6 | 0, 1, 2, 3, 7 |

**The platform** is the only party with a tamper-proof view and it is coarse. The pod is a cgroup v1
hierarchy keyed on the pod UID (`devbox-recon/08-privileges.txt`), with `pids` capped at 104
(`devbox-recon/02-resources.txt`). `runsc` implements the syscall surface in userspace, so from the
node the workload is a small set of sentry processes. The platform can answer "how many bytes did this
pod send", "how long did it live", "which device was it given", "what did it resolve". It cannot answer
"which process sent them", because there is no host-side `/proc` entry for a process inside the sentry.

**Tier 1 as written is unavailable.** `IPAccounting=` is a systemd unit property (HARDENING D12) and
there is no systemd (`DEVBOX_REPORT.md:29`, `:1081`). The fallback, per-UID nftables counters (D13),
needs `CAP_NET_ADMIN` in the counted namespace and the guest has `!cap_net_admin`. Note also that the
cgroup v1 mount list contains exactly `cpu, cpuacct, cpuset, devices, job, memory, pids` — **no
`net_cls`, no `net_prio`** (`devbox-recon/05-mounts.txt`). There is no network accounting primitive
inside this sandbox at any level. The meter has to live on the node or it does not exist.

**The tenant's view is complete and worthless.** `ss` fails at the netlink layer
(`devbox-recon/21-listeners.txt:1`), so the inventory is `/proc/net/tcp` with hex addresses and a
hand-rolled inode-to-PID join. `!cap_audit_control` and `!cap_audit_read` remove auditd (D17, D19–D24);
`!cap_bpf` and `!cap_perfmon` remove `probes.bt` (D25, D29, D30); `!cap_net_raw` removes `AF_PACKET`,
so no `tcpdump`, no Zeek, no Suricata (D11, D38). One working tier, and the sharp point is that the
tenant is the squatter: every artefact this corpus teaches a defender to read is produced *by* the
operator and read *by* the operator.

**Outside** sees a NAT-pool address from a GPU-rental ASN holding one long-lived TLS session to a
tunnel edge (`devbox-recon/105-egress-identity.txt`). The origin is reached over the already-established
outbound channel, so no inbound packet reaches the pod's veth and the outside-in port diff of
`research/external-vantage-and-honeypots.md` is structurally blind: the exposed service is not a port on
any address an outside party can see.

## 6. What would have caught this case

Cheapest first. "Fires?" means: with the evidence captured in this tree, would the check have produced
a hit on *this* run.

| # | signal | vantage | check | fires? | cost |
|---|---|---|---|---|---|
| 1 | file that appears after boot and is executable | in-guest (the existing poller) | `find /vendorx -type f -newer /dev/termination-log -printf '%TT %m %s %p\n'` | **yes** — the process hider is 50832 B, mode 0755, mtime 12:16 against 12:09 for every platform-written file (`devbox-recon/10-vendorx.txt:9`) | D2, ~10 lines, no dependencies |
| 2 | DNS answer for a tunnel-service domain | platform (the middlebox) | log query over the answer stream for tunnel/mesh FQDNs, keyed by sandbox ID | **yes** — the middlebox already classified the tunnel service (`devbox-recon/46-dnsmiddlebox.txt`); nothing consumed the log | D0–D2, one query on a log that exists |
| 3 | long-lived single-destination outbound :443 | platform (node) | established TCP to one peer, older than 15 minutes, surviving a third of the pod's life | **yes** — `ssh -4 -p 443 … -R 0:127.0.0.1:8080 root@192.0.2.20` held for the session (`devbox-recon/106-status.txt`) | D2–D4, needs node access |
| 4 | non-loopback listener inside a notebook pod | in-guest poller | `/proc/net/tcp` rows with `st=0A` on `0.0.0.0` | **yes** — `0.0.0.0:2222` and `0.0.0.0:8080` (`devbox-recon/106-status.txt`) | D2, 5 lines |
| 5 | GPU allocated to an empty notebook | platform | utilisation joined to the notebook's cell count | **weak yes** — `0MiB / 97887MiB`, `0%`, `No running processes found` (`devbox-recon/61-gpu.txt`) against one cell with `"code_hash": null` (`__vendorx__/session/notebook.py.json`) | D3–D4, needs the datasets joined |
| 6 | unexpected process name | in-guest | `comm` outside the declared runtime set | **partly** — PID 1688, `[kwo5.K5???l??A]?.Y?`, 12:19 (`devbox-recon/13-secrets-run.txt`). Fires because the operator was careless; D02 says a rename erases it | D2, 5 lines |
| 7 | egress bytes per sandbox | platform | `container_network_transmit_bytes_total` delta per pod | **no** — ~70 packages, one Tor bootstrap and a rootfs pull sit inside what a real notebook downloads; the 1.3 GB in `103-final-state.txt` is disk, not traffic | D2 to run, expensive to tune |
| 8 | sandbox lifetime and clone rate | platform | group by account, alert on N per hour | **no** — one sandbox, 46 minutes (`devbox-recon/04-blockdevices.txt` stamps the filesystem at 12:09, `103-final-state.txt` at 12:55) | D1, needs doctrine |

Four notes matter more than the table.

**Row 1 is the cheapest real detection available and it is not in this corpus.** The guardrail poller
already opens a file every 300 seconds; pointing it at a directory instead of one file costs nothing and
would have had the process hider by 12:20. It is also the only row that fires on *intent* rather than on
traffic — a ptrace-capable binary sitting in a notebook tree has no legitimate reading, and it does not
need to have been executed for that to hold (`DEVBOX_REPORT.md:1043`).

**Row 2 is free and unrepeatable.** The middlebox already classifies tunnel, VPN, proxy and Tor
categories by name and produced an answer for the tunnel service on this run. The caveat is that Tor
erases the name entirely (`devbox-recon/59-tor.txt`), so row 2 catches the direct attempt and not the
bypass — which is exactly how the hour went: attempt first, bypass second.

**Row 3 must not be written as an asymmetry test.** HARDENING D14 withdrew that inference and this case
confirms it: a relay is roughly balanced. The durable part is cardinality and age — one destination, one
port, held for the pod's life, to an address outside the registry list.

**Three corpus checks score zero on this host, and should say so.** `checks/triage.sh` is a process
sweep; the finding here is a file and a socket, and it would have printed packaged owners and a clean
exit. `checks/egress-watch.sh` dies at its first `systemctl`. `checks/cross-check.sh` is worse than
useless: its premise is a netlink-versus-procfs inode diff, netlink is unavailable, so every procfs
inode becomes "unexplained". It should detect the unsupported transport and refuse to compare.

## 7. The detection playbook

### 7.1 Platform side

**P0 — free, today, on logs that already exist.** Query the filtering middlebox for tunnel, relay, mesh
and VPN category answers, keyed by sandbox, over 30 days.

```sql
-- shape, not syntax: adapt to whatever the middlebox exports
SELECT sandbox_id, qname, category, count(*) AS n, min(ts), max(ts)
FROM dns_answers
WHERE category IN ('tunnel','proxy','vpn','remote-access')
  AND ts > now() - interval '30 days'
GROUP BY 1,2,3
ORDER BY n DESC;
```

Treat it as a leads queue, not an alert: it does not fire on the Tor bypass and it will fire on real
users of real VPNs.

**P1 — node-side flow.** Enumerate pods, list established TCP held longer than N minutes to a single
destination, subtract the registry list. Any :443 session that has survived a third of the pod's
lifetime, from a pod with no declared tunnel, is the finding. Verify that the sentry's outbound sockets
are visible from the node before relying on this; see §10.

**P2 — per-pod bytes.** Scrape `container_network_transmit_bytes_total`, build a 7-day per-notebook
baseline, alert on an order-of-magnitude delta. Do not set a MB-per-hour threshold; the numbers here are
unremarkable.

**P3 — file integrity, and this is the highest-value change.** Extend the poller that already runs every
300 seconds. Snapshot the notebook tree at pod start; on each tick, list files whose mtime exceeds the
boot stamp or whose mode is executable where the manifest says it should not be.

**P4 — GPU utilisation against declared work.** Join per-device utilisation to the notebook that owns
the allocation. A 96 GB device at 0 % for the life of a notebook whose only cell is empty is a true
statement about waste; it is not evidence of a relay, and the correlation must be built with that in
mind.

**P5 — account economics.** Sandbox-lifetime and clone-rate limits, plus per-account GPU-hour caps.
This is where provider-side allowances (D57) actually bind: the 95th-percentile idle rule is a
duty-cycle exemption by construction, so an hour a day at full rate is inside it.

### 7.2 Tenant side

Everything here is bookkeeping, and the reader should know why: **the tenant is the squatter.** These
checks tell a legitimate tenant what their own sandbox contains. They are not a defence against a
hostile tenant, because that tenant runs them.

```sh
# socket inventory without ss, from /proc/net/tcp (state 0A = LISTEN)
awk 'NR>1 && $4=="0A" {split($2,a,":"); printf "%d.%d.%d.%d:%d\n",
  strtonum("0x" substr(a[1],7,2)), strtonum("0x" substr(a[1],5,2)),
  strtonum("0x" substr(a[1],3,2)), strtonum("0x" substr(a[1],1,2)),
  strtonum("0x" a[2])}' /proc/net/tcp
```

```sh
# files newer than the sandbox itself; /dev is stamped at pod creation
find /vendorx /workspace /usr/local/bin -xdev -type f -newer /dev/termination-log \
     -printf '%TT %m %s %p\n' 2>/dev/null
```

Then `dpkg -S` (or the distro equivalent) on every listener and every non-manifest binary: package
ownership is the only name-independent identity available (D01, D06).

### 7.3 If I had one hour at VendorX

| minutes | action | why |
|---|---|---|
| 0–10 | pull 30 days of middlebox DNS answers for tunnel/mesh/VPN categories, grouped by sandbox | the only existing log that already records this behaviour |
| 10–25 | add per-pod transmit bytes to the metrics scrape; record today, baseline for a week, alert later | no number exists yet, and every threshold invented without a baseline is wrong |
| 25–40 | point the existing 300 s poller at the notebook *directory* instead of one file; alert on new executables and mtime newer than boot | closes the single-input hole with no new agent and no new dependency |
| 40–50 | check whether the sentry's sockets are visible from the node; if they are, row 3 is a 20-line script | decides whether node-side flow exists before anyone builds it |
| 50–60 | write down retention for DNS answers and pod byte counters | a detection whose log rolls off in 24 hours has to run hourly or it is decorative |

Ignore, in that hour: port scans on the pod's `/32` (ingress arrives over the outbound channel; there
is nothing to scan), the `:7844` signature (blocked at this platform before the tenant even tried),
JA3/JA4 deny-lists (D31), and any notebook source scan wider than the mining list.

## 8. What this changes in the corpus

### 8.1 Corrections

**`research/jupyter-multitenant-detection.md` needs a scope warning.** Its per-notebook metering is
built on `IPAccounting=` and on `nft … socket cgroupv2`. On a sandbox-as-a-service host neither
attaches: no systemd, `!cap_net_admin`, and cgroup v1 mounting no `net_cls`/`net_prio`. The meter must
move to the pod's veth, which is a different chapter.

**`research/proxy-tunnel-host-artifacts.md` needs three additions.** Its `ss -p` privilege caveat is not
the failure mode here — the failure is `ss` failing to open `NETLINK_SOCK_DIAG` at all, which also
invalidates the netlink half of `cross-check.sh`. Its port table's 7844 row is one vendor's edge; the
family that worked here was `ssh -R` over 443, with no listening socket and no distinctive port. And
its flow-based lane needs the pod-side caveat: on `runsc` there is no `AF_PACKET` inside the guest.

**`research/network-flow-heuristics-proxyjacking.md` is a node-side file.** Every recipe in it begins
with `tcpdump` or a tap; `!cap_net_raw` means none of it runs from inside a sandbox. That belongs in the
summary, not a footnote.

**`research/external-vantage-and-honeypots.md`** should say, next to the outside/inside port diff, that
the diff cannot see an `ssh -R` tunnel: the inbound request arrives on the established outbound session
and never touches the pod's veth.

**`HARDENING.md` gained a D60 for this case: "the tenant is the operator".** Where the party with root
inside is the party being detected, every in-guest tier is adversarial input and only provider-side
counters survive. That is stronger than D57 (the provider is outside the guest); it says the guest's own
telemetry is under the wrong party's control.

### 8.2 New checks

**`checks/workspace-integrity.sh`** — tenant side, no dependencies, drops into the existing poller. It
closes the "payload under a writable path" gap for a notebook tree (D01) and nothing else: it does not
close D02 (a renamed binary that is also packaged looks packaged), D26, D31, D52, D53, D54 or D57.

The platform-side checks in §7.1 are sketches, not files: P1 needs node access and P2 needs a metrics
scrape, so neither can be a read-only script that runs where this corpus' other checks run.

## 9. Detector cost

Scale: **D0** the log exists and someone can query it; **D1** the log exists but nothing collects it;
**D2** one query or script against existing data; **D3** new collection inside the sandbox; **D4** new
collection outside the sandbox; **D5** instrumentation the platform does not have.

| Phase | Cheapest real detection | Cost |
|---|---|---|
| 1 Acquire | GPU tier requested first, no interactive cell, disposable identity | D1 |
| 2 Egress | loopback listener on a proxy port in a process snapshot | D0 |
| 3 Ingress | long-lived outbound TCP to one pinned address on 443; public URL reappearing under a new pod | D2 |
| 4 Namespace | nothing distinguishing by design | D5 |
| 5 Process hiding | presence of a ptrace-capable binary in the notebook tree with no invocation | D2 |
| 6 Resource shape | device utilisation against declared workload | D1 |
| 7 Guardrail | sawtooth mtime on the inspected path against a fixed grid | D1 |
| 8 Persistence | the same bootstrap destination across successive sandbox identities | D4 |

The shape of the table is the finding: the cheapest detections are D0–D2, none need to touch the guest,
and the corpus' preferred recipe is D4-or-worse and unattachable here. The play is arranged so that the
cheap detections land on ordinary behaviour.

## 10. Tests that would settle what is unproven

1. **Per-record reachability on the tunnel service.** Resolve the A set repeatedly, dial every record on
   443 and 22, hold a tunnel open and time its lifetime. Settles whether one edge is filtered, several
   are, or the set rotates.
2. **`fallocate` under the sentinel overlay.** Allocate 1 TB, write a byte every GiB, then compare `df`
   and `du`. Settles whether 8 EB is a ceiling, lazy allocation, or silent failure.
3. **One deliberate guardrail violation under a renamed PID 1.** Is `exit 42` reached, does the sandbox
   terminate, does the poller's own `pkill` remove it first? The highest-value test here; it converts
   §3.1h from inference to fact.
4. **`memfd_create` and `execveat` under `runsc`.** `os.memfd_create`, `fexecve`, then read
   `/proc/self/exe`. Settles §3.1e on this kernel.
5. **`.pyc` readability.** `read_text(encoding="utf-8")` on a real `.pyc`, and confirm the exception
   class is the one the bare `except` catches.
6. **Is the file set really one path?** Put a blacklisted literal in three other files under the
   notebook tree and see whether the poller reacts.

## Sources

**Primary, this case.** `CASE.md`; `ALLOWLIST-SUMMARY.md`; `DEVBOX_REPORT.md:29`, `:497-510`, `:1043`,
`:1053`, `:1081`; `devbox-recon/01-identity`, `02-resources`, `03-df`, `04-blockdevices`, `05-mounts`,
`06-network`, `08-privileges`, `10-vendorx`, `13-secrets-run`, `14-app`, `20-netprobe`, `21-listeners`,
`25-storage`, `26-host-scripts`, `31-mount-loop`, `32-suspicious`, `33-capacity`, `43-tunnel-pre`,
`44-cloudflared-run`, `45-cloudflared-verify`, `46-dnsmiddlebox`, `47-ports`, `50-portmap`, `59-tor`,
`61-gpu`, `62-tor-deep`, `75-privoxy`, `83-tor-exec`, `85-alt-tunnels`, `87-proot`, `88-tunnel-ips`,
`93-tunnel-pin`, `94-tunnel-verify2`, `95-tunnel-script`, `100-proot-container`, `103-final-state`,
`105-egress-identity`, `106-status`; `__vendorx__/session/notebook.py.json`.

**Corpus.** `REPORT.md` §3, §4; `HARDENING.md` D01, D02, D06, D07, D09, D11, D12, D13, D14, D17, D25,
D26, D31, D36, D37, D38, D52, D53, D54, D57, D58; `research/no-socket-relays.md`,
`research/jupyter-multitenant-detection.md`, `research/proxy-tunnel-host-artifacts.md`,
`research/network-flow-heuristics-proxyjacking.md`, `research/hpc-slurm-gpu-squatting.md`,
`research/overlay-mesh-networks.md`, `research/rootkits-that-hide-the-squat.md`,
`research/kubernetes-and-container-squatting.md`, `research/external-vantage-and-honeypots.md`;
`checks/README.md` and every file it lists.

**Kernel and vendor documentation for the mechanisms cited.** `proc_pid_comm(5)`, `proc_pid_exe(5)`,
`proc_pid_cmdline(5)`; `ss(8)` for `NETLINK_SOCK_DIAG` and the `PROC_NET_TCP` path form;
`/proc/net/tcp` in `docs.kernel.org/networking/proc_net_tcp.html`; `memfd_create(2)`, `fexecve(3)`;
`PR_SET_NAME(2const)`; `systemd.resource-control(5)` for `IPAccounting=`; the nftables man page for
`socket cgroupv2`; `capabilities(7)`; the gVisor documentation for `runsc` and pod-level resource
handling; Cloudflare Tunnel's configuration documentation for the 7844 transport model, cited as the
reason that rule does not generalise.

## What I could not verify

- **Whether the node can see the sentry's outbound sockets.** `runsc` proxies outbound TCP through host
  sockets, which should make them visible to node-side `ss` or `conntrack`. Nothing here ran on a node
  and the tree contains no node-side output.
- **Whether the platform scrapes per-pod network bytes at all.** Every file in `devbox-recon/` is
  guest-side; no platform metric, counter or API response appears anywhere in it.
- **Whether the guardrail poller was running.** The process capture is a `ps aux | head -30` at 12:32;
  it shows the dependency poller and one `sleep 300`. A second could be past the truncation. Absence
  here is not evidence.
- **Whether `exit 42` terminates a sandbox**, and whether the poller's `pkill -9 -f "vendorx"` kills its
  own parent first. Both are readings of the script, not observations.
- **Why one tunnel edge is filtered and others are not.** Observed, cause unknown: a destination-range
  filter, a bad anycast path and per-record blocking all fit.
- **`memfd_create` / `execveat` under `runsc`.** §3.1e is a general technique, not a verified capability
  of this host.
- **The real ceiling behind the 2^51−1 sentinel.** Whether a 1 TB write fails, and how, is untested.
- **What the process at PID 1688 was.** `[kwo5.K5???l??A]?.Y?`, 1.3 GB VSZ, started 12:19. Either a
  rename or terminal corruption in the capture; the tree does not say.
- **The provenance of the process hider.** Present at 12:16, seven minutes after boot, never executed.
  Base image, platform canary, or dropped by something else in the tree — unknown, and the most
  interesting open question in the case.
- **Whether VendorX exposes per-sandbox GPU or byte accounting to anyone.** The D3–D5 ratings rest on an
  absence inside the guest, not on proof of absence platform-side.
- **The 15th blacklist pattern** (`prvietedu/probable-memory`): mangled indicator, placeholder, or a
  domain that changed hands. Not looked up.

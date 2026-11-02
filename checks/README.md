# checks

Runnable implementations of the cheap tiers in `REPORT.md`, hardened against the refutation sweep.
Read **[HARDENING.md](../HARDENING.md)** first: it says which bypass each file closes and which it
does not.

Three are strictly read-only (`triage.sh`, `cross-check.sh`, `network-gaps.sh`, `overlay-nets.sh`;
`external-vantage.sh` writes only to a temp file). `egress-watch.sh` keeps one small state file under `/var/lib/egress-watch`,
`baseline.sh` keeps its baseline under `/var/lib/egress-baseline`, and four files are meant to be
installed (`50-proxyjack.rules`, `accounting.nft`, the `egress-watch` unit pair, `probes.bt`).

| file | what it does | needs |
|---|---|---|
| `triage.sh` | host sweep: image writability, inline interpreters, anonymous exec mappings, linker hooks, listeners with package owner, runtime sockets, netns and scopes, persistence with ctime, coverage accounting | `procps`, `iproute2`, `coreutils`, `find`; root for full coverage |
| `cross-check.sh` | per-inode diff of the netlink and procfs socket views, inode-to-pid join, deleted libraries, linker hooks | `iproute2` |
| `network-gaps.sh` | the channels the old corpus did not check: HTTP CONNECT, `ssh -D/-R`, DNS tunnels, DoH/DoT, ICMP, vsock, io_uring, user namespaces; plus the no-socket relay lanes — tun-fd sweep, `ss -0/-w/--xdp` complements, L3 tunnel terminators (`ip -d link show`, `/proc/modules`, xfrm), kernel-side DNAT/tc/bpftool surfaces (root) | `procps`, `iproute2`; `nft`, `tc`/iproute2, `bpftool`, `bpftrace` optional |
| `overlay-nets.sh` | mesh/overlay squat indicators: TUN interfaces, mesh processes, state dirs and units, mesh-written nftables rules, coordination-endpoint flows | `procps`, `iproute2`; `nft` and `conntrack` optional |
| `baseline.sh` | per-unit egress baseline, declared purpose and allowance, drift report | systemd ≥ 235 (falls back to host counters) |
| `external-vantage.sh` | asks keyless external services what they see of this host, both address families, with abuse-contact extraction | `curl`, `python3` |
| `workspace-integrity.sh` | notebook-tree sweep: files that post-date the sandbox, executables that belong to no package. The cheapest detection in `research/sandbox-as-a-service-squatting.md`, and the only one there that fires on intent rather than on traffic | `find`, `coreutils`; one of `dpkg`/`rpm`/`pacman`/`apk` for ownership (says so when there is none) |
| `egress-watch.sh` + `.service` + `.timer` | samples `IPEgressBytes` for services, scopes and slices, warns on resets, compares against the host interface counter | systemd ≥ 235, Linux ≥ 4.11 |
| `accounting.nft` | per-UID egress counters plus forwarded bytes per interface; no daemon | nftables, kernel with `meta skuid` |
| `50-proxyjack.rules` | auditd rules for socket/connect/sendto/TUNSETIFF/namespaces/memfd/execveat/mount/persistence/io_uring | auditd ≥ 3.1 for the uring filter |
| `probes.bt` | bpftrace set: exec/execveat, clone3 namespaces, io_uring setup, TCP and UDP connects | bpftrace, `CAP_BPF`/root |

## Order to run them in

```sh
sudo sh checks/triage.sh            # what is on the box right now
sudo sh checks/cross-check.sh       # is the box's own tooling telling the truth
sudo sh checks/network-gaps.sh      # the channels the old checklist missed
sudo sh checks/overlay-nets.sh      # mesh/overlay VPN squat indicators
sh checks/external-vantage.sh       # what the outside world thinks of this IP
sh checks/workspace-integrity.sh    # notebook tree: what appeared after boot
```

Then, if you want history rather than a snapshot:

```sh
sudo sh checks/baseline.sh record
sudo sh checks/baseline.sh declare nginx.service web 50
install -m 0755 checks/egress-watch.sh /usr/local/bin/egress-watch
install -m 0644 checks/egress-watch.service checks/egress-watch.timer /etc/systemd/system/
systemctl enable --now egress-watch.timer
```

and, deliberately, one of:

```sh
install -m 0640 checks/50-proxyjack.rules /etc/audit/rules.d/50-proxyjack.rules && augenrules --load
nft -f checks/accounting.nft
bpftrace checks/probes.bt
```

## Notes on the checks that look wrong until you know why

- **`cloudflared` never listens on 7844.** It dials out. A listener scan finds nothing; the check is on
  *established* sockets. That covers one vendor's edge and nothing else: ngrok, Pinggy, `ssh -R`,
  tailscaled DERP and every CDN relay use 443.
- **`PROC_NET_TCP` takes a path, not a flag.** In `ss.c`, `generic_proc_open()` does
  `fopen(getenv(env))`, so `PROC_NET_TCP=1` tries to open a file called `1` and prints a header with
  zero rows. The correct form is `PROC_NET_TCP=/proc/net/tcp ss -Htan`.
- **`ss -p` needs root.** Attribution resolves owners by reading `/proc/<pid>/fd`, which is gated by a
  ptrace access-mode check. Without root you get sockets and inodes but no process names.
- **A kernel thread has no `/proc/<pid>/exe`.** So `comm` of `[kworker/0:1]` with a resolvable `exe` is
  always a lie. The converse is not true: a process named `sshd` with a resolvable `exe` is not a
  finding, and no name-based rule can make it one.
- **`IPAccounting=` undercounts TCP.** It sums `skb->len` before GSO segmentation (systemd issue
  #34775: a 10 KB upload reports 11,001 bytes). Use deltas as a trend, not as a bill.
- **A counter reset looks like a quiet unit.** `egress-watch.sh` warns instead of discarding it,
  because `Restart=always` plus a supervisor that cycles the payload is the cheapest way to hide bytes.
- **`chattr +i` is a write tripwire, not a read tripwire**, and `atime` is unreliable for reads under
  `relatime`. Neither is in these scripts for that reason.
- **`systemd.path` stops watching after its trigger limit.** Set `TriggerLimitIntervalSec=0` and
  `TriggerLimitBurst=0`, and monitor `systemctl --failed`, or the tripwire is a liability.
- **`workspace-integrity.sh` says "unknown", not "unpackaged", when it cannot query a package
  database.** A host with no usable `dpkg`/`rpm`/`pacman`/`apk` would otherwise report every binary in
  the tree as unowned, which is a false positive on every file — the same failure mode as running
  `cross-check.sh` on a kernel that cannot open netlink.

## What these scripts will not tell you

Nothing here identifies intent. A padded, multiplexed TLS tunnel to a reputable CDN is one encrypted
flow on 443, and every check above can only tell you that the bytes exist and which unit produced them.
The junction of "unexplained egress" and "process whose binary lives somewhere writable" is the signal;
either half alone is noise. The cases where even that junction is legitimate are listed as known
limitations in `HARDENING.md` — a private seedbox, a self-hosted CI runner, a valid RDP session, a
browser-shaped TLS fingerprint — and no amount of additional host tooling separates them.

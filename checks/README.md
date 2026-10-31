# checks

Runnable implementations of the cheap tiers in `REPORT.md`. Three are strictly read-only
(`triage.sh`, `cross-check.sh`, and `external-vantage.sh`, which writes nothing outside `/tmp`).
`egress-watch` keeps one small state file per unit under `/var/lib/egress-watch`, and two files are
meant to be installed (`50-proxyjack.rules`, `accounting.nft`).

| file | what it does | needs |
|---|---|---|
| `triage.sh` | 10-minute host sweep: exes in writable memory, kernel-thread impersonation, `ld.so.preload`, 7844 sessions, listeners, packet sockets, netns, containers, recent persistence edits | `procps`, `iproute2`, `coreutils`, `find`; root for full owner resolution |
| `cross-check.sh` | diffs the netlink socket view against the procfs view, both through `ss`; flags disagreement and deleted shared objects | `iproute2` |
| `external-vantage.sh` | asks four keyless external services what they see of this host: Tor, Onionoo, Shodan InternetDB, RDAP | `curl`, `python3` |
| `egress-watch.sh` + `.service` + `.timer` | samples `IPEgressBytes` per running unit every 5 min, logs above threshold | systemd ≥ 235, Linux ≥ 4.11 |
| `accounting.nft` | per-UID egress counters in one dynamic set; no daemon | nftables, kernel with `meta skuid` |
| `50-proxyjack.rules` | auditd rules for socket/connect/TUNSETIFF/netns/memfd/persistence | auditd |

## Order to run them in

```sh
sh checks/triage.sh              # what is on the box right now
sh checks/cross-check.sh         # is the box's own tooling telling the truth
sh checks/external-vantage.sh    # what the outside world thinks of this IP
```

Then, if you want history rather than a snapshot:

```sh
install -m 0755 checks/egress-watch.sh /usr/local/bin/egress-watch
install -m 0644 checks/egress-watch.service checks/egress-watch.timer /etc/systemd/system/
systemctl enable --now egress-watch.timer
```

and, deliberately, one of:

```sh
install -m 0640 checks/50-proxyjack.rules /etc/audit/rules.d/50-proxyjack.rules && augenrules --load
nft -f checks/accounting.nft
```

## Notes on the checks that look wrong until you know why

- **`cloudflared` never listens on 7844.** It dials out. A listener scan finds nothing; the check is on
  *established* sockets, which is why `triage.sh` uses `ss -tnp state established '( dport = :7844 or
  sport = :7844 )'`.
- **`PROC_NET_TCP` takes a path, not a flag.** In `ss.c`, `generic_proc_open()` does `fopen(getenv(env))`,
  so `PROC_NET_TCP=1` tries to open a file called `1` and prints a header with zero rows. The correct
  form is `PROC_NET_TCP=/proc/net/tcp ss -Htan`.
- **`ss -p` needs root.** Attribution resolves owners by reading `/proc/<pid>/fd`, which is gated by a
  ptrace access-mode check. Without root you get sockets and inodes but no process names.
- **A kernel thread has no `/proc/<pid>/exe`.** So `comm` of `[kworker/0:1]` with a resolvable `exe` is
  always a lie — that is the second check in `triage.sh`.
- **`IPAccounting=` undercounts TCP.** It sums `skb->len` before GSO segmentation (systemd issue
  #34775: a 10 KB upload reports 11,001 bytes). Use deltas as a trend, not as a bill.
- **`chattr +i` is a write tripwire, not a read tripwire**, and `atime` is unreliable for reads under
  `relatime`. Neither is in these scripts for that reason.

## What these scripts will not tell you

Nothing here identifies intent. A padded, multiplexed TLS tunnel to a reputable CDN is one encrypted
flow on 443, and every check above can only tell you that the bytes exist and which unit produced
them. The junction of "unexplained egress" and "process whose binary lives somewhere writable" is the
signal; either half alone is noise.

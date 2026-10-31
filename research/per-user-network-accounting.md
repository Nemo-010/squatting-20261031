# Per-process and per-user network accounting on one Linux host: what actually measures a quiet proxy relay

The question this answers: *who on this box is pushing traffic I did not sanction?* Not "is there a
malicious packet" — a CDN-fronted tunnel has no malicious packet — but "which UID, cgroup or process
produced these bytes". Everything below is available on a stock Linux server with packages from the
distro; nothing here needs an appliance, a licence, or a second machine.

Sources: kernel docs, man pages, systemd docs and source, upstream project READMEs. Where a number
could not be confirmed it is marked **unverified**.

## Summary

- Four independent measurement layers exist and they fail differently: **socket-owner matching**
  (nft/iptables), **cgroup accounting** (systemd `IPAccounting=`), **flow accounting** (conntrack),
  and **interface counters** (vnstat). None of them sees forwarded traffic or another netns.
- `iptables -m owner` and nft `meta skuid` match **locally generated packets only** — "This match is
  only valid in the OUTPUT and POSTROUTING chains. Forwarded packets do not have any socket
  associated with them." A container doing NAT'd forwarding, or a WireGuard/TUN relay, is invisible
  to this layer.
- `meta cgroup` in nftables reads the **cgroup v1 net_cls classid**, not a cgroup v2 path
  (`NFT_META_CGROUP` is guarded by `CONFIG_CGROUP_NET_CLASSID` and calls `sock_cgroup_classid()`).
  cgroup v2 has no net_cls controller, so `meta cgroup` reads zero on a pure v2 host. Use
  `socket cgroupv2 level N "<path>"` instead — added in **Linux 5.13**.
- systemd `IPAccounting=` is the cheapest per-service signal that requires no packet capture at all:
  `systemctl show <unit> -p IPIngressBytes -p IPIngressPackets -p IPEgressBytes -p IPEgressPackets`.
  Added in systemd **235**, backed by **Linux 4.11** cgroup-eBPF hooks.
- It is **not recursive** across slices, is **not available for per-user services**, and
  **systematically undercounts TCP** because it accumulates `skb->len` before GSO/TSO
  segmentation — an open defect (systemd issue #34775: a 10 KB upload reports `IPEgressBytes=11001`).
  Treat it as a trend line, never as a bill.
- conntrack gives per-flow byte and packet counts in both directions, but only if
  `net.netfilter.nf_conntrack_acct` is enabled — it is **0 (disabled) by default**.
- vnstat/nethogs/bandwhich/iftop are interface- or process-scoped and give you no durable
  per-UID history; they are for *triage now*, not for *noticing next Tuesday*.
- The detection that actually works on a squatted host is the **combination**: a per-service
  `IPEgressBytes` trend that does not match the service's purpose, plus one `ss` check for
  outbound-only connects, plus the host-artifact sweep. No single layer is sufficient.

---

## 1. Layer one: matching on the socket owner

### 1.1 iptables `-m owner`

iptables-extensions(8), verbatim:

> This module attempts to match various characteristics of the packet creator, for locally generated
> packets. This match is only valid in the OUTPUT and POSTROUTING chains. Forwarded packets do not
> have any socket associated with them. Packets from kernel threads do have a socket, but usually no
> owner.

Options: `--uid-owner username|userid[-userid]`, `--gid-owner`, `--suppl-groups`,
`--socket-exists`.

The accounting use is a counter per UID:

```sh
iptables -N ACCT_OUT
iptables -A OUTPUT -j ACCT_OUT
iptables -A ACCT_OUT -m owner --uid-owner 1001 -j RETURN
```

That only counts; to *see* it you need `iptables -nvL ACCT_OUT -x`, and the counters reset on
reload. This is why nftables is the better host for the same idea.

### 1.2 nftables `meta skuid` / `meta skgid`

nft(8) defines `meta skuid` as "UID associated with originating socket" and `meta skgid` likewise.
Kernel side, `nft_meta_get_eval_skugid()` in `net/netfilter/nft_meta.c` requires `skb_to_full_sk()`,
`sk_fullsock()`, the same netns, and a live `sk->sk_socket->file`, then returns
`from_kuid_munged(sock_net(sk)->user_ns, file->f_cred->fsuid)`. Consequences worth knowing: a closed
socket cannot match, and a process inside a different netns is not visible.

Verified-parseable accounting constructs (each checked with `nft -c -f` against nftables 1.1.7, exit
0):

```
table inet acct {
    counter u1001 { }

    set suids {
        type uid
        flags dynamic
    }

    map muids {
        type uid : counter
        flags dynamic
    }

    chain out {
        type filter hook output priority 0; policy accept;

        meta skuid 1001 counter
        meta skuid 1001 counter name "u1001"
        update @suids { meta skuid counter }
        update @muids { meta skuid counter }
    }
}
```

These two forms are **not** valid and fail the parser:

```
meta skuid update @suids { counter }        # unexpected update
update @muids { meta skuid : counter }      # unexpected counter
```

The dynamic set is the useful one: it creates one element per UID the first time that UID sends a
packet, each carrying its own counter, so you never have to pre-know the UIDs. Read it with
`nft -j list set inet acct suids` and diff on a timer. nftables wiki (Counters) notes a counter holds
packets and bytes "since the last reset" and that `nft reset counters` zeroes them; the `comment`
attribute needs nftables 0.9.7 with kernel 5.10.

### 1.3 cgroup matching, and the `meta cgroup` trap

`meta cgroup` is "control group id" in the man page, and it is widely assumed to be cgroup v2. It is
not. In `net/netfilter/nft_meta.c`:

```c
case NFT_META_CGROUP:
    ...
    *dest = sock_cgroup_classid(&sk->sk_cgrp_data);
```

guarded by `#ifdef CONFIG_CGROUP_NET_CLASSID`. And `net/core/netclassid_cgroup.c` registers
`net_cls_cgrp_subsys` with `.legacy_cftypes = ss_files` — net_cls is a **cgroup v1 legacy**
subsystem. `Documentation/admin-guide/cgroup-v2.html` lists no net_cls or net_prio controller. On a
v2-only host, `meta cgroup` therefore matches 0.

The v2-correct form is the socket expression, `net/netfilter/nft_socket.c`:

```
socket cgroupv2 level NUM "path"
```

added by netfilter commit `e0bb96db96f8` ("netfilter: nft_socket: add support for cgroupsv2",
2021-04-20) — so **Linux 5.13** — and later fixed for the input path by `05ae2fba821c`
("netfilter: nft_socket: make cgroup match work in input too"). `level` is an ancestor index: per
nft(8), for path `a/b`, level 1 is `a` and level 2 is `b`. `level > 255` is refused with EOPNOTSUPP.

```
socket cgroupv2 level 2 "system.slice/jupyter-alice-singleuser.service" counter
```

This is the construct to rate-limit or police a tenant, because it survives the tenant renaming
their binary:

```
socket cgroupv2 level 2 "system.slice/jupyter-alice-singleuser.service" \
    limit rate over 2 mbytes/second drop
```

Caveat from the kernel source: sockets do not migrate between cgroups. A socket keeps the cgroup it
was created in, so this control must be applied at spawn time; retrofitting it onto a running UID
does nothing for the already-open tunnel.

---

## 2. Layer two: cgroup eBPF accounting via systemd

### 2.1 What it is

systemd.resource-control(5):

> Takes a boolean argument. If true, turns on IPv4 and IPv6 network traffic accounting for packets
> sent or received by the unit. When this option is turned on, all IPv4 and IPv6 sockets created by
> any process of the unit are accounted for.

> Note that this functionality is currently only available for system services, not for per-user
> services.

> Added in version 235.

The mechanism is the cgroup-eBPF hook: per the systemd author's own description, the options are
"thin wrappers around kernel functionality introduced with Linux 4.11: the control group eBPF
hooks". systemd compiles a `BPF_PROG_TYPE_CGROUP_SKB` program per unit (`src/core/bpf-firewall.c`)
which does

```c
BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offsetof(struct __sk_buff, len), ...);
/* xadd into map */
```

against a two-entry array map (`MAP_KEY_PACKETS` = 0, `MAP_KEY_BYTES` = 1). Reading is a map lookup;
`systemctl status` and `systemd-run --wait` surface the same numbers.

### 2.2 Reading it

```sh
systemctl show nginx.service -p IPIngressBytes -p IPIngressPackets \
                             -p IPEgressBytes  -p IPEgressPackets
```

and for a whole host:

```sh
systemctl show -p IPEgressBytes --all --value | paste -sd+ | bc   # crude sum, see caveat
```

Enable it globally without touching every unit by putting it in a drop-in for the slice, or per
service:

```ini
# /etc/systemd/system/proxy-suspect.service.d/acct.conf
[Service]
IPAccounting=yes
```

### 2.3 The three limits that matter

**(a) It does not undercount only slightly — it undercounts TCP structurally.** The counter
accumulates `skb->len` at the cgroup hook, before the stack splits a large GSO/TSO segment into
MTU-sized frames. systemd issue **#34775** ("IPAccounting does not account for GSO packets and
undercounts tcp flows", still **open**) demonstrates it on systemd 256.7-1 / kernel 6.11.3:

```
$ systemd-run --wait -p IPAccounting=yes -p RemainAfterExit=yes \
    sh -c "head -c10k /dev/urandom | curl -F 'f:1=<-' http://1.1.1.1"
$ systemctl show run-u1707.service | grep Egress
IPEgressBytes=11001
IPEgressPackets=8
```

8 packets for 10 KB — the flow was carried in a handful of GSO frames rather than ~8×1400-byte
segments, and 11,001 bytes were counted for 10,240 bytes of payload plus headers. The reporter's own
bpftrace measurement at `net_dev_start_xmit` counted 11,209 bytes, and the conclusion in the issue is
that "IpEgressBytes systematically undercounts tcp flows", plus the note that "nftables counters
undercount in exactly the same way, as there are no netfilter hooks that run late enough to observe
the split". So: a factor-of-something error, direction unknown at runtime. Use it to compare units
against each other, not to predict an invoice.

**(b) It is not recursive.** systemd's author, on the feature's introduction: "IP accounting is
currently not recursive. That means you cannot use a slice unit to join the accounting of multiple
units into one. This is something we definitely want to add, but requires some more kernel work
first." Slices did get their own accounting programs later (CHANGES WITH 238: "IPAccounting= may now
be enabled also for slice units"), but summing a slice's number and its children's numbers is
double-counting, not aggregation.

**(c) It is unavailable for per-user managers.** The man page sentence above is normative: a rootless
`systemctl --user` JupyterHub cannot use it at all. That is exactly the deployment most likely to be
squatted, so plan on `systemd-run --scope` from the root-owned spawner, or on nft counters.

### 2.4 `IPAddressAllow=` / `IPAddressDeny=` — the allow-list flip

Same hook, different program. Set `IPAddressDeny=any` on `-.slice` or `system.slice` and then
allow-list per service:

```ini
# /etc/systemd/system/-.slice.d/egress.conf
[Slice]
IPAddressDeny=any

# /etc/systemd/system/myapp.service.d/egress.conf
[Service]
IPAddressAllow=any
```

Semantics from the man page: for ingress the *source* is checked, for egress the *destination*;
symbolic values are `any`, `localhost`, `link-local`, `multicast`; rules combine with the parent
slices; the feature needs eBPF cgroup support and "will have no effect" without it.

The direct anti-squatting use: a service that has no business talking to the Electrosphere gets
`IPAddressDeny=any` and only its database peer allow-listed. A tunnel cannot then be installed into
it even if the process is compromised. Do not apply this to a unit that must bind loopback and reach
a resolver, and note the documented caveat that for socket-activated services the socket unit and
service unit are accounted separately with no propagation.

### 2.5 Turning it into an alert with no daemon

`systemd.timer` + a shell script is enough, and it keeps a baseline so you are not tuning thresholds
by hand:

```sh
#!/bin/sh
# /usr/local/bin/egress-watch
STATE=/var/lib/egress-watch
mkdir -p "$STATE"
for u in $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'); do
    cur=$(systemctl show "$u" -p IPEgressBytes --value)
    [ -n "$cur" ] || continue
    f="$STATE/${u%.service}"
    prev=$(cat "$f" 2>/dev/null || echo "$cur")
    d=$((cur - prev))
    echo "$cur" > "$f"
    # 50 MiB in one interval is already 6.7 Mbit/s sustained
    [ "$d" -gt 52428800 ] && logger -t egress-watch "$u emitted $d bytes since last run"
done
```

```ini
# /etc/systemd/system/egress-watch.timer
[Unit]
Description=per-unit egress sampler

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

Note the counter resets when a unit restarts, so a negative delta must be treated as a restart, not
as a wraparound of a 64-bit value (it cannot wrap). The `logger` line lands in the journal, which on
most distros is the only alerting channel you need for a single box.

---

## 3. Layer three: conntrack flow accounting

Enable it first — it is off by default. docs.kernel.org/networking/nf_conntrack-sysctl.html:

> **nf_conntrack_acct** - BOOLEAN. 0 - disabled (default), not 0 - enabled
> Enable connection tracking flow accounting. 64-bit byte and packet counters per flow are added.

```sh
sysctl -w net.netfilter.nf_conntrack_acct=1       # /proc/sys/net/netfilter/nf_conntrack_acct
```

Then, per conntrack(8), `-L -o extended` prints "the /proc/net/nf_conntrack format, with additional
information":

```sh
conntrack -L -o extended -p tcp | grep ESTABLISHED | sort -k1
conntrack -L -o extended --src-nat
conntrack -L -f ipv6 -o extended
conntrack -S                       # in-kernel counters and error stats
```

The counters appear as `packets=N bytes=N` on both the original and reply tuples (kernel
`seq_print_acct()` in `net/netfilter/nf_conntrack_standalone.c` prints `packets=%llu bytes=%llu`).
That gives you the one thing the cgroup layer cannot: **bytes per remote peer, per direction**.

Properties: per-flow, so it dies with the flow; no history; and it costs memory per tracked
connection. On a busy host the conntrack table is where this bites, not the counters.

`-z` zeroes counters but "requires `-L`". `ktimestamp` needs `net.netfilter.nf_conntrack_timestamp`.

What to look for: a single long-lived flow to `:443` carrying tens of GB in the **reply→original**
direction while the original direction is nearly silent. That asymmetry is a tunnel or a seeder. A
legitimate client upload is asymmetric the other way.

---

## 4. Layer four: interface counters and live process views

**vnstat(1)** — persistent history, no packet capture:

> keeps a log of 5 minute interval, hourly, daily, monthly and yearly network traffic
> it isn't a packet sniffer. The traffic information is read from the proc(5) or sys filesystems

Per-interface only, so it answers "the box is pushing 30 Mbit out" and nothing about who. Useful as
a canary, and it keeps months of history by default:

```sh
vnstat --oneline; vnstat -h; vnstat --json d | python3 -m json.tool | head
vnstat --alert output exit type d condition above limit 25 GiB   # exits nonzero, cron-friendly
```

**nethogs** — groups bandwidth by process, "heavily relies on /proc, most features are only available
on Linux", and it has an explicit **"unknown TCP"** bucket for bytes it cannot attribute. That bucket
itself is a signal: on an idle server it should be near zero. Non-root needs
`setcap cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace+pe`.

**bandwhich** — "sniffs a given network interface and records IP packet size, cross referencing it
with the /proc filesystem"; needs `cap_sys_ptrace,cap_dac_read_search,cap_net_raw,cap_net_admin+ep`.
Best of the four for "which process talks to which host right now".

**iftop** — per-host, "must be run with sufficient permissions ... on most systems this means that it
must be run as root"; `-t` for text mode, `-n` no DNS, `-P` show ports. Good for catching one noisy
peer, useless for history.

**`ss`** is the cheapest single check and covers what the accounting layers cannot: outbound-only
sessions and their duration.

```sh
ss -Htnp state established                    # process + peer, no DNS
ss -Htnp state established '( dport = :7844 or sport = :7844 )'   # cloudflared
ss -Htup                                       # UDP: QUIC, uTP, WireGuard
ss -tn state time-wait | wc -l                 # many short flows = proxying, not browsing
```

---

## 5. What each layer cannot see — the section that decides your design

| Layer | Blind to |
|---|---|
| `-m owner` / `meta skuid` | forwarded/NAT'd traffic, containers in another netns, kernel-thread sockets, anything already closed |
| `meta cgroup` | everything on a cgroup-v2-only host (reads net_cls classid, which is v1) |
| `socket cgroupv2` | sockets created before the rule existed; pods whose cgroup path you do not know |
| systemd `IPAccounting=` | forwarded traffic, per-user managers, other netns, and ~all large TCP flows' true size (GSO) |
| conntrack | history (flow-scoped), traffic that never traverses conntrack (raw sockets, some tunnelled L2), and it is off until you enable it |
| vnstat | per-process attribution, other interfaces you did not configure |
| nethogs/bandwhich | encrypted payload, and any traffic whose socket they lose (the "unknown" bucket) |
| **all of them** | *intent*. A CDN-fronted TLS tunnel is one encrypted flow to a reputable IP on 443. Every layer above can tell you the bytes; none can tell you they are a proxy. |

That last row is why the byte counters are the *triage* step and not the detection. The detection
step is correlating an unexplained egress trend with a process-level fact: a binary under `/tmp` or
`/dev/shm`, a `(deleted)` exe, an outbound-only session to a tunnel endpoint, or a service that
declares no such purpose.

## Sources

- iptables-extensions(8) — owner match: <https://man7.org/linux/man-pages/man8/iptables-extensions.8.html>
- nft(8) — meta/socket expressions: <https://manpages.debian.org/trixie/nftables/nft.8.en.html>
- `net/netfilter/nft_meta.c`, `net/netfilter/nft_socket.c`, `net/core/netclassid_cgroup.c`:
  <https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nft_meta.c>,
  <https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nft_socket.c>,
  <https://raw.githubusercontent.com/torvalds/linux/master/net/core/netclassid_cgroup.c>
- cgroup v2 controllers: <https://docs.kernel.org/admin-guide/cgroup-v2.html>
- systemd.resource-control: <https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html>
- systemd IP accounting introduction (Linux 4.11, non-recursive):
  <https://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html>
- systemd issue #34775 (GSO undercount): <https://github.com/systemd/systemd/issues/34775>
- systemd issue #20356 (per-user managers excluded): <https://github.com/systemd/systemd/issues/20356>
- nf_conntrack sysctls: <https://docs.kernel.org/networking/nf_conntrack-sysctl.html>
- conntrack(8): <https://man.archlinux.org/man/conntrack.8.en>
- vnstat(1): <https://man.archlinux.org/man/vnstat.1.en>
- nethogs: <https://github.com/raboof/nethogs>
- bandwhich: <https://github.com/imsnif/bandwhich>
- iftop(8): <https://man.archlinux.org/man/iftop.8.en>
- nftables wiki, Counters: <https://wiki.nftables.org/wiki-nftables/index.php/Counters>

## What I could not verify

- The exact kernel version that first exposes `AUDIT_FILTER_URING_EXIT`-adjacent behaviour is a
  sibling question; for this file, only the nft and accounting paths were pinned.
- Whether `systemd-run --scope -p IPAccounting=yes` works for an arbitrary non-service session:
  the property is a service/scope property and scopes are units, but the man page's "system services
  only" sentence is about *system vs user managers*, not about scopes, and I did not find a
  normative statement that a root-created scope from a user session is accounted. Treat as
  **unverified**; test on the target host with the `systemctl show` read-back before relying on it.
- The precise per-packet accounting map layout in `bpf-firewall.c` was read from source comments and
  instruction construction rather than from an upstream design document.
- Whether `meta cgroup` returns zero vs an error on a `CONFIG_CGROUP_NET_CLASSID=y` but
  net_cls-unmounted host: source suggests the classid is simply 0 when no v1 hierarchy sets it, but
  I did not test it.
- A factor to correct `IPEgressBytes` into real bytes: none is published; issue #34775 is open and
  the GSO fix PR was closed without the accounting change.

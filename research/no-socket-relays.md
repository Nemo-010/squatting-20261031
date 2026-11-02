# Relays with no socket-inventory footprint

**A relay does not need a listening socket on this host, and the family that needs none is the one
lane the corpus so far treats as fragments.** `ss -Htulpn` — the inventory `checks/triage.sh` and
`checks/cross-check.sh` run — is complete for relays whose accepting processes own their sockets,
and systematically incomplete for three others. In lane A the relay terminates inbound connections
inside a userland TCP/IP stack and moves packets through a `/dev/net/tun` fd (or `AF_PACKET`): the
*inbound* footprint is zero sockets, while its *outbound* egress sockets are ordinary and do show in
`ss`. In lane B the kernel relays with no userspace socket at all — nftables DNAT, tc `mirred`,
eBPF sockmap — so no process ever opens a server socket. In lane C the host terminates an L3 tunnel
(GRE, SIT, IPIP, VXLAN, Geneve, IPsec/XFRM) and forwards what comes out of it: the terminator is a
kernel module and an interface, not a listener.

Fragments already in the corpus: one line in `research/open-relays-amplification-reflectors.md` §10
("`nft list ruleset` (or `iptables -t nat -S`) for `DNAT` rules you did not write", framed only as a
container-escape check); `HARDENING.md` D11 ("Raw `AF_INET`/`AF_XDP` and eBPF XDP capture are named
as not covered"); `tun2socks` appearing only as a process-name string
(`checks/network-gaps.sh:38`, and one `grep -rlE` pattern in
`research/jupyter-multitenant-detection.md:68`); the unverified `/etc/sing-box/config.json` path in
`research/proxy-tunnel-host-artifacts.md:247` (this round pins the correct shape — see §2); and
D18's concession (HARDENING.md:75) that "WireGuard and every rtnetlink-created interface never call
it, and userspace proxies need no interface at all". A grep sweep for
`vxlan|geneve|gre|sit|ipip|xfrm|sockmap|erspan` over the corpus finds no substantive hit (this
round; incidental matches only).

## Summary

- **Lane A: the *inbound* listener footprint is zero sockets; egress is normal.** The tun fd is not
  an `anon_inode:` — it lives at a real misc-device node, verified in
  `drivers/net/tun.c`: `tun_miscdev` with `.nodename = "net/tun"` and
  `MODULE_ALIAS("devname:net/tun")`, so `readlink /proc/<pid>/fd/*` shows the literal
  `/dev/net/tun` path (or the bind-mounted path under which it was opened).
- **The corpus's TUNSETIFF ioctl rule (`a1=0x400454ca`, `checks/50-proxyjack.rules`) fires only
  after the device exists** — the fd is already open, before the ioctl; the magic is verified equal
  to `_IOW('T',202,int)` = `0x400454ca`, recomputed from `/usr/include/linux/if_tun.h` line 34, and
  the device is misc major 10 `/ minor 200` (`include/linux/miscdevice.h`:
  `#define TUN_MINOR 200`).
- **The `ss`-family complement is `ss -0` (PACKET), `ss -w` (RAW), `ss --xdp`** — verified in
  `ss(8)`: `-0, --packet` is "Display PACKET sockets", `-w, --raw` is RAW, and `-A` takes `raw`,
  `packet_raw`, `packet_dgram`. In this round's non-root sandbox run, `ss -0p` printed no Process
  column.
- **Lane B: nftables DNAT, tc `mirred`, TPROXY and eBPF sockmap leave no userland server socket**;
  TPROXY is the partial case (its receiver is a real userspace socket, attributable). `bpftool net
  show` documents its own coverage: XDP, tcx, netkit, old-style tc, flow_dissector and netfilter
  attachments, and explicitly defers sockmap's `sk_msg` programs to "other tools"
  (`tools/bpf/bpftool/Documentation/bpftool-net.rst`).
- **Sockmap attach types verified in `include/uapi/linux/bpf.h` (lines 1145–1148):
  `BPF_SK_SKB_STREAM_PARSER`, `BPF_SK_SKB_STREAM_VERDICT`, `BPF_SK_MSG_VERDICT`**; the kernel doc
  says the verdict program "is essentially the redirect program" and that inserting a socket
  "replaces its socket callbacks" with an `sk_psock` — in-kernel byte-stealing between sockets
  (`docs.kernel.org/bpf/map_sockmap.html`).
- **The modern NAT hook symbol is `nf_nat_inet_fn`, not `nf_nat_ipv4_fn`** (which does not exist in
  kernel master); family wrappers `nf_nat_ipv4_pre_routing/out/local_fn/local_in` in
  `net/netfilter/nf_nat_proto.c` each call it. That is the correct bpftrace kprobe name.
- **Lane C ports and modules, first-hand from sources**: VXLAN UDP **4789** IANA but **8472** as the
  Linux driver default (`drivers/net/vxlan/vxlan_core.c:46`: "The IANA assigned port is 4789, but
  the Linux default is 8472"); Geneve **6081** (`include/net/geneve.h`: `GENEVE_UDP_PORT 6081`);
  GRE-in-UDP **4754/4755** (RFC 8086). Module names from the kernel Makefiles: `ip_gre`, `ip6_gre`,
  `sit`, `ipip`, `ip_tunnel`, `gre`, `fou`, `ip_vti`, `vxlan`, `geneve`, `esp4`, `esp6`.
- **`ip tunnel` covers only the `ip_tunnel` family** — modes verified in `ip-tunnel(8)`: `ipip |
  gre | sit | isatap | vti | ip6ip6 | ipip6 | ip6gre | vti6 | any` — so it *misses* vxlan/geneve;
  the lane needs the generic `ip -d link show`. Type `tun` matches TAP devices too, because
  `tun_link_ops.kind = "tun"` covers both (`drivers/net/tun.c`).
- **"TLS-in-TLS is a stated non-capability" cites literature that exists and measures the
  opposite**: Xue, Kallitsis, Houmansadr, Ensafi, *Fingerprinting Obfuscated Proxy Traffic with
  Encapsulated TLS Handshakes*, USENIX Security 2024, deployed inside a mid-size ISP serving
  upwards of one million users. See the named section below; it is a network-side detector and
  claims no host-observable artifact, so the corpus's operational default stands.

Test environment used for live probes in this file: Linux (Artix kernel 7.2.11-artix1-1, x86_64),
non-root, no systemd, `bpftool`/`bpftrace`/`conntrack`/`tcpdump` absent, 122 modules loaded, no
tunnel modules among them. Every live output below is quoted from that run; capabilities that need
root are named as such rather than assumed.

## 1. What "no socket result" means, per lane

| lane | who terminates inbound | what `ss -Htulpn` sees | the right enumerator |
|---|---|---|---|
| A — userland TCP/IP stack | the process, over a tun fd | its *outbound egress* sockets only | `ss -0`/`-w`/`--xdp`, `/proc/*/fd` for `/dev/net/tun`, `ip -d link`, route/rule diffs |
| B — kernel data path | the kernel (nft DNAT, tc, sockmap) | nothing at all (TPROXY: one receiver) | `nft list ruleset`, `tc filter show`, `bpftool prog/map/net show` |
| C — L3 tunnel terminator | the kernel module (gre/sit/vxlan/…) | nothing at all | `ip -d link show` type sweep, `/proc/modules`, `ip xfrm state` |

Lane A's asymmetry carries a corpus lesson: ingress and egress live in different socket *roles*.
Egress is mandated — the relay must open upstream sockets, which are ordinary `AF_INET` sockets
visible to `ss -tnp`. Attribution of those sockets has the D10 shape: `/proc/<pid>/fd` names the
*holder*, not the author, once fds travel over `SCM_RIGHTS`.

## 2. Lane A: userland TCP/IP stacks and tun-mode relays

**Mechanism, verified from `drivers/net/tun.c`** (raw source fetched this round, master branch):
`open("/dev/net/tun")` then `ioctl(fd, TUNSETIFF, &ifr)` creates the device and binds it to the fd —
`tun_chr_ioctl` case `TUNSETIFF` → `tun_set_iff`; permission comes from `tun_permitted()` (ns
`CAP_NET_ADMIN`, or the device's `TUNSETOWNER` uid/gid match). The userspace side then `read()`s and
`write()`s IP packets. TCP state is either a userland stack or a guest kernel attached via the fd.
`f0ps = &tun_fops`, `tun_chr_open` allocates the per-fd `tun_file` with a socket-like backend
(`&tfile->socket`), and `_tun_chr_show_fdinfo` exists under `CONFIG_PROC_FS`; `tun_get_socket()`
classifies by `file->f_op == &tun_fops`, which is the robust kernel-side identity userspace cannot
reach — userspace gets `readlink` (the stored path) and `fdinfo` (the inode numbers).

**The tools.**

- **sing-box `tun` inbound** (SagerNet). Docs list the full Linux artifact set:
  `interface_name` (the tun device name), `netns` (runs inside a netns owned by the user, no root
  required), `auto_route` ("Set the default route to the Tun"), `iproute2_table_index` default
  **2022**, `iproute2_rule_index` default **9000**, `auto_redirect` (nftables fast path; fallback
  rule index default **32768**, "checked after system default rules (32766: main, 32767: default)"),
  connection marks default `0x2023`/`0x2024`/`0x2025`/`0x2026`, nfqueue default **100**
  (`docs/configuration/inbound/tun.md` at SagerNet/sing-box, fetched this round). **Detection
  anchors: `ip rule show` priority 9000 and `ip route show table 2022`.** Also resolved in this
  round: the shipped unit runs `ExecStart=/usr/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box
  run` (`release/config/sing-box.service`), and `-C` is `--config-directory`
  (`cmd/sing-box/cmd.go`, "-C", "set configuration directory path") — so the correct path claim is
  `/etc/sing-box/*.json` (a directory glob), replacing the unverified single-file guess at
  `research/proxy-tunnel-host-artifacts.md:247`.
- **tun2socks** (xjasonlyu). README verified: "Transparently routes all network traffic from any
  application through a proxy", "Gateway Mode: Acts as a Layer 3 gateway to route traffic from
  other devices on the same network", and "User-Space Networking: Leverages the **gVisor** network
  stack" — TCP state lives in a userland gVisor netstack, i.e. the zero-socket-ingress shape.
  `checks/network-gaps.sh` currently knows this tool only as a process-name case.
- **hev-socks5-tunnel** (heiher). README verified: "A simple, lightweight tunnel over Socks5 proxy
  (tun2socks)", IPv4/IPv6 dual stack, TCP + UDP redirect — also name-only in the gap check today.
- **redsocks** (darkk) belongs to lane B's partially attributable class, not here: verified README,
  "transparent TCP-to-proxy redirector … redirect any TCP connection to SOCKS or HTTPS proxy using
  your firewall" — the firewall does the DNAT/REDIRECT, and redsocks itself is a real local
  listener.

**Detection, cheapest order, each with its false-positive gate.**

1. **fd sweep for the char device.** For each pid, `readlink /proc/<pid>/fd/*` and report any
   target containing `/dev/net/tun`; where `readlink` is denied (other users' processes), read
   `/proc/<pid>/fdinfo` and match the device pair major 10 / minor 200. The fd exists *before*
   `TUNSETIFF` — the ioctl is the second step — so this catches the setup window even where the
   ioctl audit race loses it. FP: every legitimate VPN and container runtime, KVM-with-tap,
   `qemu`/`libvirt`, `ssh -w` sessions;holes: a bind-mounted alternate path shows under whatever
   path the process opened (the fdinfo device pair closes that).
2. **The ioctl rule this corpus already has** — `checks/50-proxyjack.rules`:
   `-a always,exit -F arch=b64 -S ioctl -F a1=0x400454ca -k tun_ioctl`. Reload `augenrules` after
   any edit; D18's scope caution stands for every rtnetlink-created interface.
3. **`ss -0` / `ss -w` / `ss --xdp`** — the complement to `ss -Htulpn`. Verified live, non-root:
   two `p_dgr` rows printed (`ss -0` == `-f link`; iproute2 `misc/ss.c`:
   `sock_name = s->type == SOCK_RAW ? "p_raw" : "p_dgr"` for `AF_PACKET`, `"xdp"` for `AF_XDP`).
   FP: tcpdump/libpcap, any capture service — the sniffing class the corpus labels D11, one step
   from the relay.
4. **`ip -d link show` type sweep** — `type tun` matches TAP too (`.kind = "tun"` for both; TUN
   mode's `dev->type = ARPHRD_NONE` prints as `link/none` — source-derived, not observed live: no
   tun device on the test host). FP: the corpus's own overlay list (`tailscale0`, `wt0`, `zt*`,
   `nebula1`, `ygg0`), every container veth.
5. **route/rule diffs against the baseline** — the sing-box defaults above make a diff concrete:
   priority 9000 rules, table 2022, fallback rule 32768. Compare `ip rule show` and `ip route show
   table all` with `checks/baseline.sh`'s record. FP: any CNI or failover policy routing — this is
   a baseline-diff question, not a signature.

**Bypass per lane.** Rename the binary (`sing-box` → `python3`)); pass the tun fd over
`SCM_RIGHTS` to a sleep-loop (the corpus's D10 story verbatim: attribution then names the holder);
leave the cgroup-of-record ambiguous by daemonizing; hide inside a netns (sing-box documents a
`netns` option); or drop the tun device entirely and run the data plane over `AF_PACKET` — which
moves the artifact into `ss -0` territory, not `-Htulpn`. What survives rename and `SCM_RIGHTS`:
the fd inventory (1). What survives all of it: nothing on the host, which is the corpus's D57
position; the fd check is the strongest goodbye this lane gets.

## 3. Lane B: kernel-side relaying with no userspace socket at all

**nftables DNAT — the broker's port-forwarding path.** A privileged tenant adds
`nft add rule īnat prerouting dnat to <colluder>:<port>`: inbound traffic is rewritten before any
userspace process exists; no socket is opened for it on this host at all. In `nft(8)`
(Debian bookworm current) both `dnat to <addr>[:port]` and `tproxy to {address | :port}` are
documented first-class statements. The kernel-side hook symbol is verified:
`nf_nat_inet_fn` (`net/netfilter/nf_nat_core.c`, `EXPORT_SYMBOL_GPL`), invoked per family from
`nf_nat_ipv4_pre_routing/out/local_fn/local_in` wrappers in `net/netfilter/nf_nat_proto.c` — use
`bpftrace -e 'kprobe:nf_nat_inet_fn { @[comm] = count(); }'` as the fingerprint source for NAT
-rate counters; REDIRECT lives separately in `net/netfilter/nf_nat_redirect.c`.

**TPROXY — the partially attributable case.** Verified from
`Documentation/networking/tproxy.rst`: packets are marked and delivered to a *transparent* local
socket, and "From Linux 4.18 transparent proxy support is also available in nf_tables". The
receiver is a real userspace listener (possibly bound with `IP_TRANSPARENT` to a non-local
"stolen" address — so it shows only against *all* listeners, not only the port-mapped ones; D10
attribution caveat applies as usual).

**tc bpf / `mirred`.** Verified from `tc-mirred(8)`:
`tc ... action mirred DIRECTION ACTION [dev DEVICENAME | blockid BLOCKID]`, actions
`{ mirror | redirect }`, "mirroring is what is sometimes referred to as Switch Port Analyzer
(SPAN)" and "Redirecting is similar to mirroring except that the behaviour is to mirror to the
first N - 1 ports in the block and redirect to the last one". A `redirect` *moves* the packet off
the source interface onto the target one — a kernel relay between a host NIC and a veth into a
container/VM, with no userspace process in the path at all. Detection: `tc filter show dev
<iface> ingress|egress` (verified unprivileged-read in this sandbox; empty) and `bpftool net show`.

**eBPF sockmap/sk_msg — the in-kernel byte-stealer, piece by piece.**

- Attach types in `include/uapi/linux/bpf.h` (lines 1145–1148), verified raw: `BPF_SK_SKB_STREAM_
  PARSER`, `_BPF_SK_SKB_STREAM_VERDICT`, `BPF_SK_MSG_VERDICT`; also `_BPF_SK_SKB_VERDICT` for
  the stream verdict on newer kernels. There is no `BPF_SK_MSG_STREAM_*` pair — the MSG family
  pairs with `VERDICT` only.
- `docs.kernel.org/bpf/map_sockmap.html`, verified: "The parser program determines how much data
  has been parsed and therefore how much data needs to be queued to come to a verdict. The verdict
  program is essentially the redirect program and can return a verdict of `__SK_DROP`,
  `__SK_PASS`, or `__SK_REDIRECT`." Inserting a socket "_replaces its socket callbacks" with a
  `struct sk_psock`; the redirect helpers are `bpf_msg_redirect_map`/`bpf_msg_redirect_hash`.
  This is relay of bytes *inside* the kernel between two existing userland sockets — no userland
  data plane. What it cannot do: create the ingress endpoint (that is still somebody's socket,
  usually a client in a neighbor netns).
- **Detector bias**: `bpftool net show`'s own doc lists what it covers — XDP, tcx, netkit,
  old-style tc, flow_dissector, netfilter attachments — and says "For `sk_{filter, skb, msg,
  reuseport}` … bpf programs, users should consult other tools", i.e. sockmap programs are
  *invisible* to `bpftool net`; they live in `bpftool prog show` + `bpftool map show` (commands
  verified in `tools/bpf/bpftool/Documentation/bpftool-prog.rst` / `-map.rst`).

**Detection recipe-lane-B commands, each with its FP gate:**

- `nft list ruleset` (root): under this sandbox's non-root run it failed with
  `netlink: Error: cache initialization failed: Operation not permitted` (quoted verbatim; the
  exit status was masked by the pipeline, so treat the error line, not the code). FP:
  docker/k8s SNAT+MASQ chains.
- `iptables -t nat -S` (legacy/nft-compat): same failure mode, quoted —
  `iptables v1.8.13 (nf_tables): Could not fetch rule set generation id: Permission denied (you
  must be root)`.
- `tc filter show dev <iface> ingress|egress`: read works non-root (verified, empty). FP: every
  CNI shaping/filtering tree.
- `bpftool prog show`, `bpftool map show`, `bpftool net show` (root CAP_BPF): authoritative for
  lane B; **not run here** — bpftool absent in the sandbox. FP: any eBPF observability attach
  (Tetragon, Tracee, Cilium), which the corpus's own detection file also runs.
- `nft monitor rules` (or `nft -j monitor destroy rules`): verified in `nft(8)` ("The monitor
  command allows you to listen to Netlink events produced by the nf_tables subsystem"); a
  long-running monitor is the practical offset to the honest limitation that a ruleset cannot be
  diffed against a baseline that was never taken.

**Bypass per lane.** A privileged tenant unloads/reloads its ruleset (`nft flush ruleset`). The
ruleset survives in netlink state only — no file, so `inotify` cannot help. The remedy is the
corpus's existing one: snapshot `nft list ruleset` at provision time in `checks/baseline.sh` and
diff, or run `nft monitor rules` as a service. The `-S bpf` audit rule in
`checks/50-proxyjack.rules` already fires on every new program load and is the other net-benefit
net. TPROXY's socket survives everything except careful listener review.

## 4. Lane C: L3 tunnel transports with fingerprints the corpus lacks

| transport | port/protocol | host artifact | module | source |
|---|---|---|---|---|
| GRE | IP proto **47** | `gre0`/`greN` interface | `ip_gre` | `net/ipv4/Makefile`: `obj-$(CONFIG_NET_IPGRE) += ip_gre.o` |
| SIT / 6in4 | IP proto **41** (IPv6-in-IPv4) | `sit0` | `sit` | `net/ipv6/Makefile`: `obj-$(CONFIG_IPV6_SIT) += sit.o` |
| IPIP `_tunl0` | IP proto **4** | `tunl0` | `ipip` | `net/ipv4/Makefile`: `obj-$(CONFIG_NET_IPIP) += ipip.o` |
| GRETAP/ERSPAN_* | IP proto **47**, ether-typed | Ethernet `greN`-style dev | `ip_gre` (same build) | `net/ipv4/Makefile` |
| VXLAN | UDP **4789** IANA; **8472** Linux default | `vxlanN` device | `vxlan` | `vxlan_core.c:46`: "The IANA assigned port is 4789, but the Linux default is 8472" |
| Geneve | UDP **6081** | `geneveN` device | `geneve` | `include/net/geneve.h`: `#define GENEVE_UDP_PORT 6081` |
| GRE-in-UDP (`fou`) | UDP **4754**/**4755** | module `fou` only | `fou` | RFC 8086 §3.2.2; `net/ipv4/Makefile`: `obj-$(CONFIG_NET_FOU) += fou.o` |
| IPsec/XFRM | ESP, IP proto **50** | `xfrm` state/policy | `esp4`/`esp6` (plus `xfrm4_tunnel`) | `net/ipv4/Makefile`: `obj-$(CONFIG_INET_ESP) += esp4.o`; `ip-xfrm(8)` |

**The inventory sweep.** `ip -d link show` prints the link `type` for each: `gre/sit/ipip/vti/
gretap/erspan` (the `ip_tunnel` family) plus `vxlan/geneve/xfrm`. Verified that the legacy
command's surface is narrower — `ip-tunnel(8)` modes:
`MODE := { ipip | gre | sit | isatap | vti | ip6ip6 | ipip6 | ip6gre | vti6 | any }` — so
`ip tunnel show` *misses* vxlan/geneve; the lane needs the generic listing. Module presence is a
one-line check (this sandbox, quoted: `grep -E '^(ip_gre|ip6_gre|sit|ipip|ip_tunnel|gre|fou|vxlan|
geneve|esp4|esp6)' /proc/modules` → no match across 122 loaded modules).

**What is genuinely invisible everywhere except the packet path.**

- `/proc/net/protocols` lists *socket families*, not netdev drivers — verified on this host (rows
  seen: `PACKET` with 2 sockets, `XDP`, `NETLINK`, `TCPv6`, `UDPv6`, `RAWv6`, `PINGv6`, `MPTCP*`,
  `AF_VSOCK`, `ALG`, `BNEP`, `SCO`, `L2CAP`, `HCI`, `MCTP`, `UNIX*`). No GRE/SIT row exists on a
  clean host, and none is created by loading those modules, because the transports are not socket
  families. Read it for the *socket-level* lanes (raw/AF_PACKET/XDP counts), not for lane C.
- `/proc/net/snmp`'s `Ip:` row — verified locally: header fields `Forwarding DefaultTTL InReceives
  InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos …` — counts IP-layer forwarding with no
  per-protocol attribution. Proto-41/47 traffic appears as `InUnknownProtos` only when nothing on
  the host consumes it, and as ordinary `InReceives` when a local module does. So
  `checks/network-gaps.sh`'s ICMP counter block has no proto-47 equivalent; per-transport
  counters live in nftables, not in `/proc/net/snmp`.
- `ip xfrm state` / `ip xfrm policy` need capability: verified non-root failure here —
  `RTNETLINK answers: Operation not permitted / Dump terminated`, exit 1. As root this is the
  one authoritative view of an IPsec-terminated squat.
- `conntrack -L` (DNAT reply tuples) is *not* installed in this sandbox; its shape is relayed
  from `research/open-relays-amplification-reflectors.md` §7's recipe, not re-run here.

**Bypass per lane.** Wrap a fixed-proto tunnel in UDP: `ip fou add port PORT ipproto 47` moves GRE
behind UDP dport 4754-on (syntax verified in `ip-fou(8)`, "Foo-over-UDP receive port
configuration", with the `gue` sibling), erasing the first byte of the signature; VXLAN/Geneve over
arbitrary UDP ports erase the port constant (Geneve accepts any port; VXLAN commonly runs on the
driver default 8472, but the port is arbitrary in `ip link add … type vxlan id N dst-port`). What
each bypass does: move *where* the squat hides. It does not remove the forward-traffic
counter (D13's nft counter set), and it does not touch the one tamper-proof detector — the
provider's outside view (D57).

## Detection recipe (cheapest first)

Ordered by cost and FP noise; Unprivileged-read rows are live-verified against this round's
sandbox, root-gated rows are named as such.

1. `ip -d link show` — read the type column. FP: container veths, docker bridges, the corpus's own
   overlay device names (`tailscale0`, `wt0`, `zt*`, `nebula1`, `ygg0`). Anything with `type tun`,
   `gre`, `sit`, `ipip`, `vti`, `ip6gre`, `gretap`, `erspan`, `vxlan`, `geneve`, `xfrm` that you
   did not create is a lead.
2. `grep -E '^(ip_gre|ip6_gre|sit|ipip|ip_tunnel|gre|fou|vxlan|geneve|esp4|esp6)' /proc/modules` —
   a loaded tunnel module is a single-line finding. FP: legitimate VPN with kernel IPsec; VXLAN
   underlay infra in CNI deployments.
3. fd sweep: for `/proc/[0-9]*/fd/*` readlink, match any target containing `/net/tun`; fall back
   to `/proc/<pid>/fdinfo` device-pair major 10 / minor 200 where readlink is denied. FP: every
   container/KVM backend, `ssh -w`, the operator's own VPN client.
4. `ss -0p` and `ss -wp` plus `ss --xdp` — complements `ss -Htulpn`. FP: tcpdump/libpcap,
   Wireshark, any legit AF_PACKET sensor.
5. `ip rule show` / `ip route show table all` compared with `checks/baseline.sh`'s record —
   priority 9000 rules and table 2022 that appeared since baseline map to `auto_route`. FP: any
   CNI/failover policy routing, which is why this is a baseline-diff and not a signature.
6. `nft list ruleset` (root) and `grep -E 'dnat|redirect|tproxy'`. FP: docker/k8s SNAT chains.
   Cannot be read without root (verified failure message above).
7. `tc filter show dev <each-iface> ingress|egress` (non-root read verified). FP: every CNI
   shaping/filtering, standard `fq_codel`.
8. `bpftool prog show`, `map show`, `net show` (root, CAP_BPF). FP: Tetragon/Tracee/Cilium and the
   corpus's own runtime tools. Rely on `prog`/`map` for sockmap — `net`'s doc says it does not
   cover `sk_msg`.
9. `ip xfrm state && ip xfrm policy` (root). FP: a branch-office VPN, provider IPsec backhaul.
10. `bpftrace -e 'kprobe:nf_nat_inet_fn { @[probe] = count(); }'` — per-family NAT hook (verified
    symbol). FP: every docker/K8s NAT this host legitimately does; exclude your own baseline rate.
11. `nft monitor rules` as a service, seeded from `checks/baseline.sh`. FP: operator-authored
    churn — that is why you snapshot at provision time, not at request time.

## Where the academic work on TLS-in-TLS actually is

The two dismissal sentences (`checks/network-gaps.sh:136-148`, "TLS-in-TLS … has no constant to
match. It is only visible as a statistical shape"; `HARDENING.md` D59, "TLS-in-TLS remains a
stated non-capability") assert a position the literature states more precisely:

- **There is published measurement with a real deployment**: *Fingerprinting Obfuscated Proxy
  Traffic with Encapsulated TLS Handshakes*, Diwen Xue (University of Michigan), Michallis
  Kallitsis (Merit Network), Amir Houmansadr (UMass Amherst), Roya Ensafi (University of Michigan),
  **USENIX Security 2024** (<https://www.usenix.org/conference/usenixsecurity24/presentation/xue>;
  PDF mirror
  <https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf>). Verified
  one-sentence result: "the traffic of obfuscated proxies, even with random padding and multiple
  layers of encapsulations, can be reliably detected with minimal collateral damage by
  fingerprinting encapsulated TLS handshakes", deployed "within a mid-size ISP serving upwards of
  one million users". "Encapsulated TLS handshakes" is the general family of which TLS-in-TLS is
  the canonical case. The paper also warns "existing obfuscations based on multiplexing and
  random padding alone are inherently limited, due to their inability to reduce the size of
  traffic bursts or the number of round trips within a connection."
- **The corpus already cites the adjacent predecessor** — `REPORT.md` §3.5 cites Wu et al.,
  *How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic*, USENIX Security
  2023 (<https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi>): deployed
  November 2021, "applies crude but efficient heuristics to exempt traffic … the fingerprints of
  common protocols, the fraction of set bits, and the number, fraction, position and longest run
  of printable ASCII characters", roughly **0.6 %** collateral and about **26 %** probabilistic
  blocking of connections to popular datacenter ranges (the paper's measurements, per REPORT.md).
- **What the literature does not name**: no checked source claims a *host-observable* artifact of
  the tunnel itself — both detectors are network-side classifiers at an ISP/censor vantage point,
  not host sensors. Until a study names a host-visible fingerprint, the corpus's operational
  default stands as written; the correction owed is only citational: the two sentences should cite
  the above instead of standing unsourced, and the network-vs-host framing should be named as
  D58's position on record.

## What this changes in the corpus (adopt-or-not list, no repo edits made)

- `checks/network-gaps.sh`: add `ss -0`/`-w`/`--xdp` complements, the `/dev/net/tun` fd sweep with
  the major-10/minor-200 fallback, an `ip -d link show` tunnel-type sweep (`ip tunnel` misses
  vxlan/geneve), `nft list ruleset` / `tc filter show` / `bpftool prog,net,show` listing stubs
  (root-gated, marked as such), the `nf_nat_inet_fn` bpftrace one-liner, and a `nft monitor rules`
  reference.
- The two TLS-in-TLS sentences gain their citation (Xue et al. 2024) and the D58 network-side
  framing.
- `tun2socks`/sing-box stop being name-only: the artifact set of §2 (fd inventory, tun-type device
  sweep, rule-priority 9000/table-2022, `/etc/sing-box/*.json` as a directory glob rather than a
  single guessed `config.json`).

## Sources

- kernel (torvalds/linux, master branch, fetched 2026-11-01): [drivers/net/tun.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/tun.c) · [include/uapi/linux/bpf.h](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h) · [include/linux/miscdevice.h](https://raw.githubusercontent.com/torvalds/linux/master/include/linux/miscdevice.h) · [net/netfilter/nf_nat_core.c](https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nf_nat_core.c) · [net/netfilter/nf_nat_proto.c](https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nf_nat_proto.c) · [net/ipv4/Makefile](https://raw.githubusercontent.com/torvalds/linux/master/net/ipv4/Makefile) · [net/ipv6/Makefile](https://raw.githubusercontent.com/torvalds/linux/master/net/ipv6/Makefile) · [drivers/net/geneve.h line](https://raw.githubusercontent.com/torvalds/linux/master/include/net/geneve.h) · [drivers/net/vxlan/vxlan_core.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/vxlan/vxlan_core.c) ·
  [Documentation/networking/tproxy.rst](https://docs.kernel.org/networking/tproxy.rst) · [docs.kernel.org/bpf/map_sockmap.html](https://docs.kernel.org/bpf/map_sockmap.html) · [tools/bpf/bpftool/Documentation/bpftool-prog.rst](https://raw.githubusercontent.com/torvalds/linux/master/tools/bpf/bpftool/Documentation/bpftool-prog.rst) · [bpftool-map.rst](https://raw.githubusercontent.com/torvalds/linux/master/tools/bpf/bpftool/Documentation/bpftool-map.rst) · [bpftool-net.rst](https://raw.githubusercontent.com/torvalds/linux/master/tools/bpf/bpftool/Documentation/bpftool-net.rst)
- man pages: [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html) · [ip-tunnel(8)](https://man7.org/linux/man-pages/man8/ip-tunnel.8.html) · [tc-mirred(8)](https://man7.org/linux/man-pages/man8/tc-mirred.8.html) · [ip-fou(8)](https://man7.org/linux/man-pages/man8/ip-fou.8.html) · [ip-xfrm(8)](https://man7.org/linux/man-pages/man8/ip-xfrm.8.html) · [nft(8) Debian bookworm current](https://manpages.debian.org/bookworm/nftables/nft.8.en.html) · local UAPI `/usr/include/linux/if_tun.h`
- RFCs: [7348 (VXLAN)](https://www.rfc-editor.org/rfc/rfc7348.txt) · [8926 (Geneve)](https://www.rfc-editor.org/rfc/rfc8926.txt) · [8086 (GRE-in-UDP)](https://www.rfc-editor.org/rfc/rfc8086.txt) · [6936 (zero UDP checksum applicability)](https://www.rfc-editor.org/rfc/rfc6936.txt)
- proxy tools: [sing-box tun inbound docs](https://sing-box.sagernet.org/configuration/inbound/tun/) · [sing-box unit `-C` in release/config/sing-box.service](https://raw.githubusercontent.com/SagerNet/sing-box/testing/release/config/sing-box.service) · [cmd/sing-box/cmd.go](https://raw.githubusercontent.com/SagerNet/sing-box/testing/cmd/sing-box/cmd.go) · [tun2socks README](https://raw.githubusercontent.com/xjasonlyu/tun2socks/main/README.md) · [hev-socks5-tunnel README](https://raw.githubusercontent.com/heiher/hev-socks5-tunnel/main/README.md) · [redsocks README](https://raw.githubusercontent.com/darkk/redsocks/master/README.md) · [iproute2 misc/ss.c](https://raw.githubusercontent.com/iproute2/iproute2/main/misc/ss.c)
- literature: [Xue, Kallitsis, Houmansadr, Ensafi — USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/xue) · [PDF prepub + mirror](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf) · [Wu et al. — USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi)

## What I could not verify

- **bpftool execution.** Not installed in this sandbox; `prog show` / `map show` / `net
  show` are cited verbatim from the kernel Documentation source pages, not from a run. The
  unprivileged-BPF edge of the privilege boundary is untreated.
- **Privilege boundary of the rest.** `ip xfrm state` observed failing non-root with
  `RTNETLINK answers: Operation not permitted`; root-side behavior was not tested (no privilege).
  Same for `nft list ruleset` (non-root failure quoted verbatim) and `tc filter` (non-root read
  verified OK; root assumed per tc(8)).
- **`ss -0p` privilege semantics** — the flag was accepted; whether the Process column appears is
  untested with a privileged caller, and ss(8) does not state the rule (it documents only what -p
  does, not who is authorized).
- **`ss(8)`'s `-A` selector "raw" (the shape of output with real raw sockets present)** — no raw
  socket existed on the host (`/proc/net/raw` printed only headers); what `-A raw` prints for raw
  socket listings is documented but unvisualized here.
- **Live observation of a tun fd's `readlink` output.** Derived from `drivers/net/tun.c` (a real
  misc-device node, no anon-inode), not observed: no tun fd existed on this host to readlink.
- **`link/none` output for a TUN mode device** — source-derived (`dev->type = ARPHRD_NONE`, TUN
  branch), not observed on a device.
- **`/proc/net/protocols` behavior under a loaded transport module.** The observation is the
  current host's loaded-module state (nothing tunnel-ish loaded; 122 modules). What a loaded
  module does to this table was not tested — `modprobe` is root-gated here, and the source
  position (protos register per socket family, not per netdev driver) is inference, not an
  observation.
- **`conntrack -L` shape.** Not installed in this sandbox; relayed from
  `research/open-relays-amplification-reflectors.md` §7 rather than re-run.

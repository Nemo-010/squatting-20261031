# Overlay and mesh networks as squat infrastructure

**A borrowed host joins a mesh and serves a proxy or content to peers without ever opening an inbound
port on its public interface.** Reverse tunnels (cloudflared, ngrok, frp) dial out and expose a port on
a relay; an overlay does something structurally different — the host dials out, joins a private
network, and *nothing at all appears on the public interface*. The control-plane dials look like
ordinary HTTPS and UDP egress, the payload rides encrypted peer traffic, and every check in this
corpus that scans for listeners returns nothing, correctly.

This file covers Tailscale/Headscale, NetBird, ZeroTier, Nebula, tinc, n2n, Yggdrasil, cjdns and iroh.
The WireGuard data plane itself is covered in `proxy-tunnel-host-artifacts.md`; what is new here is the
coordination layer each mesh adds, the free tier that makes joining someone else's mesh free, and the
fact that the mesh's relays can carry the whole squat.

The structural point first, because it inverts several detections in this corpus: an overlay node's
public interface shows **no listener, no inbound flow, and no port** — the same property the corpus
records for egress-only proxies — but with an additional trick: the *payload* traffic does not
originate from the host's public IP either. A peer reaches the box over the tailnet. What remains on
the public interface is only the mesh's own keepalive and coordination traffic.

## 1. Tailscale and Headscale

**Artifacts.** `tailscaled` (daemon) and `tailscale` (CLI), unit `tailscaled.service`, state in
`/var/lib/tailscale`, socket `/var/run/tailscale/tailscaled.sock`, flags in `/etc/default/tailscaled`.
TUN interface `tailscale0` via `/dev/net/tun` — unless run with `--tun=userspace-networking`, which is
the default in the official container image and needs no `/dev/net/tun` at all
(tailscale.com/docs/concepts/userspace-networking). Userspace mode removes the TUN artifact entirely;
what remains is the process and the network flows.

**Ports.** UDP 41641 (WireGuard direct, with keepalives), UDP 3478 (STUN), TCP 443 (DERP relays and
coordination), TCP 80 (coordination fallback and captive-portal checks) —
tailscale.com/docs/reference/faq/firewall-ports.

**Control-plane endpoints — the cheap, pin-able detector.** Since July 2025 the coordination hosts
(`controlplane.tailscale.com`, `login.tailscale.com`, `console.tailscale.com`) resolve to static
ranges **192.200.0.0/24** and **2606:B740:49::/48**; `log.tailscale.com` moved in November 2025 to
**199.165.136.0/24** and **2606:B740:1::/48** (same FAQ page). The DERP relay map is public:
`https://controlplane.tailscale.com/derpmap/default` returns the full node list (`derp1-all` …
`derp28-all.tailscale.com` as of August 2025) with IPv4, IPv6 and `CanPort80` flags — a ready-made
endpoint feed for a conntrack or nftables check. A server with no tailnet business that holds a
long-lived TCP/443 flow to an address in the DERP map is a strong signal.

**No inbound port needed: yes.** Direct P2P via UDP hole punch, fallback to DERP over TCP 443. DERP is
an HTTPS-upgrade relay carrying the peers' WireGuard packets — it does not serve arbitrary TCP to
third parties, only tailnet members. That is exactly what a squatter's own clients need.

**Egress laundering — the honest answer.** DERP hides *ingress*, not egress. If the box proxies to the
internet, destinations see the box's public IP. Egress rotation through Tailscale requires a second
colluding host advertising an exit node — the destination then sees the exit node's IP. The pure squat
(ingress hiding) is free and undetectable from outside; egress rotation costs a second box.

**Free tier.** The Personal plan's device/user counts (historically 3 users / 100 devices) were not
re-verified this round — `unverified`. Headscale removes the vendor entirely (self-hosted coordination
server, same client binary), at which point the control-plane endpoints above no longer apply and the
only fixed signatures are the DERP-less flow shape, the binary name and `tailscale0`.

**Detection on one host.** `/proc/net/dev` for `tailscale0`; `auditd` on `/dev/net/tun` open by
non-allowlisted processes and on creation of `/var/lib/tailscale`; conntrack for UDP keepalives with
source port 41641 and long-lived TCP/443 to DERP-map addresses. The nixfred field guide
(tailscale.nixfred.com) documents the same signatures, including `tailscale ping` reporting `via
DERP(city)`.

**Bypass cost.** Rename the binary and register a custom unit (defeats name-based checks); userspace
networking (removes the TUN artifact); Headscale (removes the endpoint signatures). The flow shape —
one long-lived TCP/443 to a fixed IP, UDP 41641 keepalives — survives all three, but so does any
legitimate long-lived HTTPS client, which is the corpus's standing limitation.

## 2. NetBird

**Artifacts.** Binary `netbird`, unit `netbird.service`, TUN interface **`wt0`**. NetBird *manages the
host firewall itself* — it writes nftables/iptables and UFW/firewalld rules referencing `wt0`
(docs.netbird.io/about-netbird/ports-and-firewalls). That is an artifact the squatter must strip, and
stripping managed firewall rules is noisy: `nft list ruleset | grep -i netbird` finds it even after a
binary rename.

**Endpoints (same doc).** Management `api.netbird.io` TCP/443, signal `signal.netbird.io` TCP/443,
STUN `stun.netbird.io` UDP/80,443,3478,5555, relay `*.relay.netbird.io` TCP/443 (WebSocket) *and*
UDP/443 (QUIC) for clients ≥ v0.36.0, legacy TURN for older clients. A JSON dump of all cloud
endpoints is published at docs.netbird.io/docs-static/files/netbird-cloud-endpoints.json — a
detection feed the squatter cannot change without self-hosting the control plane.

**No inbound: explicit.** "The NetBird client doesn't require any inbound port to be open" (same page).

**Free tier.** 5 users, 100 machines (docs.netbird.io/manage/settings/plans-and-billing) — enough for
a relay fleet on one throwaway account.

**Bypass cost.** Rename the binary (cheap); remove or live with the managed firewall rules (loud);
self-host the management/signal/relay stack (removes every endpoint signature, costs a second server).

## 3. ZeroTier

**Artifacts.** `zerotier-one` daemon + `zerotier-cli`, unit `zerotier-one.service`, state
`/var/lib/zerotier-one/` (`identity.secret`, `planet`, `moons.d/`, `networks.d/`, `zerotier-one.port`),
TUN interface `zt<id>` per joined network. Default UDP **9993** (`ZT_DEFAULT_PORT` in
`include/ZeroTierOne.h`) plus a randomized secondary port and UPnP/NAT-PMP attempts — outbound NAT-PMP
from a server is itself unusual and is a detection artifact.

**Control-plane.** The root servers in the `planet` file (official roots under `*.zerotier.com`, e.g.
`root-lax-01`, `root-mia-01`, `root-tok-01`, `root-zrh-01`). ZeroTier documents that a private
`planet`/"moon" configuration is supported — a squatter can swap the planet file and remove every
vendor root IP from the flow signature (docs.zerotier.com/whitelist; community tooling automates it).

**No inbound: yes** (UDP hole punch, root-mediated relay fallback; a TCP relay exists for fully
blocked hosts — zerotier/pylon). **Free tier:** the current pricing page (checked this round,
zerotier.com/pricing) gives Personal/Free **10 devices, 1 network** — tighter than the legacy 25-node
tier that older write-ups cite, and still enough for a small relay cluster.

**Detection.** Process, state dir, `zt*` interfaces, UDP/9993 flows, `zerotier-one.port`.
**Bypass cost.** Binary rename, private planet, and libzt (userspace library form, no TUN — third
parties have demonstrated port-forwarding through libzt with no tun device). After that the signature
is flow-shape only.

## 4. Nebula

**Artifacts.** `nebula` + `nebula-cert`; upstream ships no unit (users create `nebula.service` or a
template); config `/etc/nebula/config.yaml`; TUN interface `nebula1` by default, renameable via
`tun.dev` (nebula.defined.net/docs/config/listen/).

**Ports.** Lighthouse conventionally UDP 4242, but roaming nodes are *recommended* to use `port: 0`
(random). Port-based detection is therefore weak by design; detection is flow-based: long-lived UDP to
a small fixed set of lighthouse/relay IPs.

**Control-plane.** None. Nebula has no vendor infrastructure — only the operator's lighthouses
(`static_host_map`). Nothing public to feed a detector; a squatter joining someone else's Nebula
network leaves only the config file and the flow shape.

**A detector's gift from the protocol:** by default Nebula replies to packets for unknown tunnels with
a `recv_error` packet — the docs explicitly note this "can be abused … as a way to discover if Nebula
is running on a host" and offer `send_recv_error: always|never|private`. An active probe against a
suspected node gets a confirmable reply; the squatter can set `never`, at a handshake-performance
cost. This is the only mesh in this file with a documented active-probe oracle.

**Bypass cost.** Rename binary, interface and port; disable `recv_error`; nothing else to strip
because there is no vendor layer.

## 5. tinc

**Artifacts.** `tincd` (+ `tinc` CLI in 1.1), templated unit `tinc@<netname>.service`, config root
`/etc/tinc/<NETNAME>/`. The TUN interface is **named after the network** by default (tinc.conf(5)) —
so the interface name carries no signal at all; the squatter picked it. Default TCP+UDP **655** for
the meta-connection and data. tinc 1.1 can attempt UPnP/NAT-PMP mappings.

**Control-plane.** None — `ConnectTo` peers are local config. **No inbound:** a leaf that only dials
`ConnectTo` targets works through NAT (meta over TCP, data falls back over the meta-connection when
UDP is blocked). **Bypass cost:** rename netname, binary and port — the durable signature is the
single long-lived TCP flow to one peer, which is indistinguishable from any long-lived client.

## 6. n2n

**Artifacts.** `edge` (client) and `supernode`; TAP interface `edge0` (`-d` renames); supernode
default UDP **7654**. The client binary name `edge` is a generic word — a name-based check must match
on the full path and the `supernode`/`edge` argument pair, not the basename.

**Structure.** The supernode is both coordination and relay, and needs a public UDP port — so the
squatter *joining* someone else's n2n network is squat-shaped (outbound UDP to one supernode, TAP
device, no inbound), while *running* a supernode is an ordinary public server. No vendor layer, no
public endpoint list, free software with no account at all.

## 7. Yggdrasil

**Artifacts.** `yggdrasil` daemon, unit `yggdrasil.service`, config `/etc/yggdrasil.conf`, TUN
interface `ygg0`. Peers are configured statically (`Peers:` with `tls://host:port` or `quic://`) or
discovered on the LAN via multicast. **No vendor layer at all** — Yggdrasil is a peer-to-peer routed
mesh where every node is a router and the "coordination" is the network itself. Public peers are
listed in the community-maintained `yggdrasil-network/public-peers` repository.

**What changes for the squatter.** No account, no free tier, no control-plane endpoint — a squatter
peers with any public node (outbound TLS to a community peer on an arbitrary port) and is instantly
reachable on the Yggdrasil network at its node address. Inbound payload traffic arrives through the
mesh, over the peering connection the host itself opened. The public interface shows outbound TLS to
the peer and nothing else.

**Detection.** `ygg0` interface, `yggdrasil` process, config file, TLS flows to public-peer addresses
(the peers list is public, so the flow check is feedable). **Bypass cost:** rename binary/interface,
pick uncommon peers, or run the mesh over a private peering set — the durable artifact is the config
file and the TUN device, both of which a root squatter renames in minutes.

## 8. cjdns

**Artifacts.** `cjdroute`, config `/etc/cjdroute.conf`, TUN interface (name from the config, often
`tun0` — not distinctive on a busy host). Peers are UDP endpoints configured with the peer's public
key; outbound peering means no inbound port. Like Yggdrasil there is no vendor, no account and no
control plane: the public-peers list is community-maintained in the `cjdns` GitHub organization.

**Detection.** Config file (keys, `interfaces`), process, UDP flows to configured peer IPs.
**Bypass cost.** Same as Yggdrasil: rename everything; the config and flow shape remain.

## 9. iroh (n0-computer)

Different class: iroh is an **embeddable** p2p library (Rust), not a daemon. A squatter can embed it
in an innocuous binary — no package, no unit, no conventional artifacts, ` DERP`-style relays operated
by n0 (relay endpoints under `*.iroh.network`, QUIC/HTTPS on 443) and direct QUIC hole-punched paths.
There is no TUN, no interface, no config directory: the signatures are (a) QUIC flows to n0 relay
addresses, (b) a `Mel0...`/node-id key embedded in the protocol handshake, and (c) whatever the host
application leaks. For a *library* squat the process-artifact checks in this corpus find nothing,
because the squat is inside a legitimate-looking binary — this is the memfd lesson of
`HARDENING.md` applied to overlays. Relay endpoint list: iroh's docs publish the current relay fleet;
`unverified` this round beyond the mechanism.

## 10. Cross-cutting detection

What survives every bypass in sections 1–9, cheapest first:

1. **`/dev/net/tun` opens by non-allowlisted processes** — auditd `openat` on the TUN char device.
   Defeated only by userspace modes (Tailscale userspace, libzt, iroh), which are themselves the
   exception rather than the default.
2. **Interface inventory** — `tailscale0`, `wt0`, `zt*`, `nebula1`, `ygg0`, `edge0` in
   `/proc/net/dev`. Every one is renameable or avoidable; but a *server* that grows any new TUN
   interface at all is a lead worth one command.
3. **The endpoint feeds** — Tailscale's DERP map (public URL), NetBird's published endpoint JSON,
   ZeroTier's root IPs, the Yggdrasil/cjdns public-peer lists. Long-lived flows to these addresses
   from a host with no declared mesh business are cheap to check with conntrack and nftables, and they
   survive every filesystem rename.
4. **Flow shape** — one long-lived UDP flow (or TCP/443) with keepalive cadence to a fixed small set
   of remotes, near-zero bytes for days, then bursts. This is the same shape the corpus records for
   `cloudflared`; the mesh adds the TUN/endpoint corroboration.
5. **The firewall-management artifact** — NetBird (and Tailscale's ACL mode) write nftables rules
   naming their interface. A squatter who renames binaries often forgets the ruleset.

What does not survive: name-based process checks (rename), port checks (Nebula `port: 0`, tinc
rebind), and vendor-endpoint checks against self-hosted control planes (Headscale, NetBird self-host,
ZeroTier moons, private planet files). The honest statement is the corpus's standing one: a mesh is
indistinguishable from legitimate remote access on flow shape alone, and the decision that it is a
squat comes from the host having no declared reason to run one — which is `baseline.sh`'s question,
not a signature's.

## 11. What this changes in the corpus

- `checks/triage.sh` already flags the TUN char device; the endpoint feeds above give
  `checks/network-gaps.sh`-style flow checks something feedable (DERP map URL, NetBird endpoint JSON).
- The "no listening socket" property, already recorded for egress-only tunnels in the refutation sweep
  (§8.14 there), is now *stronger* for overlays: there is also no inbound flow on the public interface
  at all, which removes the last assume-breach lead short of flow accounting.
- Free-tier economics: NetBird 5 users/100 machines and ZeroTier 10 devices mean one throwaway account
  arms a whole relay fleet. The account-churn business model the corpus describes for resale networks
  applies to mesh accounts unchanged.

## What I could not verify

- Tailscale's current Personal-plan device/user counts (checked in an earlier corpus round; not
  re-verified here).
- NetBird's exact client config path on Linux (`/etc/netbird.yml` — server-side paths are
  documented, client-side path not confirmed in docs this round).
- The current n0 iroh relay endpoint list and ports.
- ZeroTier root IPs (community-corroborated; not re-checked against a live planet file).
- Whether NetBird supports a documented TUN-less client mode.
- n2n's default management port across versions (5645 appears in man-page examples).

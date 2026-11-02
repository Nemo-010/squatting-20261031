# Scanner fleets: detecting a squatted host used as a rented scan node

## Summary

- **The corpus's DET0028 quote names `masscan` as a scanning tool but no file treats the tool shape.** `REPORT.md` quotes MITRE DET0028 ("sustained outbound traffic … includes curl, wget, masscan, or proxy clients") and names nmap only as an operator tool; this file fills that slice for the rented-fleet case (https://attack.mitre.org/detectionstrategies/DET0028/).
- **masscan does not open an AF_INET raw socket; it sends via libpcap (AF_PACKET).** First-hand read of `robertdavidgraham/masscan`: the packet data path goes through pcap; `socket(AF_INET, ...)` appears only in interface/route lookup helpers, not the send path. Detection of the masscan shape must read `/proc/net/packet`, not `/proc/net/raw` (https://github.com/robertdavidgraham/masscan).
- **Rate is the core knob and the defaults differ per tool.** masscan default 100 pps with `--rate` to raise (`robertdavidgraham/masscan` README); zmap `-r` default 10000 pps, 0 = line rate (`zmap/zmap` `src/zmap.1`); nuclei `-rl` default 150 req/s (`projectdiscovery/nuclei` `cmd/nuclei/main.go`) (https://github.com/zmap/zmap).
- **Payloadless SYN shapes are small but not uniform.** masscan's SYN is 44 B at L3 (40 B IPv4+TCP + a 4-byte MSS option, no TCP data, window 1024 — `src/templ-pkt.c`); zmap's SYN carries Windows-style TCP options, 52 B at L3 (`src/probe_modules/module_tcp_synscan.c`) (https://github.com/robertdavidgraham/masscan).
- **App-layer scanners run on ordinary sockets and look like clients.** zgrab2 posts a fixed UA `Mozilla/5.0 zgrab/0.x` with a `--senders` worker pool defaulting to 1000 (`zmap/zgrab2` `modules/http/scanner.go`, `config.go`); nuclei picks a **random User-Agent per request** (`pkg/protocols/http/build_request.go`), so a "Nuclei" UA string is not a reliable default fingerprint (https://github.com/zmap/zgrab2).
- **The fleet-rental market recycles these tools rather than replacing them.** Fleex orchestrates nuclei and masscan across rented VMs (https://fleexsecurity.github.io/fleex-docs/); GreyNoise classifies masscan/Nuclei fingerprints as Tool tags on its global sensor network (https://docs.greynoise.io/docs/greynoise-tags).
- **The AF_PACKET scanners are structurally invisible to kernel TCP-state counters.** `packet_xmit()` in `net/packet/af_packet.c` calls `dev_queue_xmit()` directly, bypassing the `NF_INET_LOCAL_OUT`/`POST_ROUTING` hooks where conntrack and `Tcp ActiveOpens` are fed — code-read inference, not live-measured here (https://raw.githubusercontent.com/torvalds/linux/master/net/packet/af_packet.c).
- **Per-unit bytes/packets accounting can catch the normal-socket scanners only.** `IPAccounting=` (systemd v235+) tracks `IPEgressBytes` and `IPEgressPackets` per unit; AF_PACKET sockets are explicitly not covered (https://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html); sibling `research/per-user-network-accounting.md` is the canonical treatment.
- **Detection reads three cheap tables first.** `/proc/net/raw` (AF_INET raw sockets, empty on an idle host), `/proc/net/packet` (masscan/zmap path), and `ss -tan state syn-sent` (normal-socket scanners) — all verified runnable on this worker (2026-11-01, see §3).

## 1. Tool shape

**masscan** (`https://github.com/robertdavidgraham/masscan`, cloned 2026-11-01, `master`):

- Default rate is **100 packets/second**; raise with `--rate` (README: "By default, the rate is set to 100 packets/second. To increase the rate to a million use something like `--rate 1000000`"). At high rates the README warns the scanner will melt the user's own network first, and recommends firewalling the port receiving SYN-ACK responses.
- Default SYN scan behaves "as if these were set: `-sS -Pn -n --randomize-hosts --send-eth`" (README), and the man page is explicit that "`-sS`: this does SYN scan only (currently, will change in the future)". `--send-eth` is the frame-level send: the packet path is **libpcap/AF_PACKET**, with masscan carrying its own userland TCP/IP stack for anything beyond the SYN. A `grep -rn -i rmem` across the whole clone finds **no** `rmem_max` requirement anywhere — see §8.
- Packet shape: TCP SYN, **no TCP payload**. `src/templ-pkt.c::default_tcp_template` sets IPv4 total length `\x00\x2c` (20 IPv4 + 20 TCP) and flags `\x02` (SYN), window 1024; a 4-byte MSS option `\x02\x04\x05\xb4` is appended, so the wire frame is **44 B at L3, 58 B at L2**.
- Source-port default: when `--src-port` is absent, `src/main.c` computes base = `40000 + now % 20000` **once per process** and uses a contiguous range of 17 ports (`src.port.range = 16`); each emitted packet takes the next port in a syn-cookie-hashed order, not a random pick per packet. With `--src-port`, the range must be a power of two (`src/main-conf.c`).
- Banner grabbing: masscan "can... complete the TCP connection and interaction with the application at that port in order to grab simple 'banner' information", and the README lists the protocols it checks: FTP, HTTP, IMAP4, memcached, POP3, SMTP, SSH, SSL, SMBv1, SMBv2, Telnet, RDP, VNC. Because masscan owns its own TCP stack, the **host's kernel answers each SYN-ACK with a RST** and kills the banner connection; the README's fixes are `--source-ip` on a spare local address, or `--source-port` plus a `iptables -A INPUT -p tcp --dport NNNNN -j DROP` rule so the kernel never sees the response.
- PF_RING ZC (README section): optional `pf_ring.ko` + `libpfring.so` from ntop, adapter name switches to `zc:<iface>`; the README positions the DNA/ZC driver for rates "above 2 million packets/second" that need Intel 10-GigE hardware. Not measured here (§8).

**zmap** (`https://github.com/zmap/zmap`, cloned 2026-11-01, `main`):

- Design: single-packet, stateless, Internet-wide; the README reports "full IPv4 on one port in under 45 minutes on gigE" and "under 5 minutes at 10 gigE with netmap or PF_RING". Default target `0.0.0.0/8`, cooldown 8 s, one probe per IP (`--probes 1`), default output CSV (`src/zmap.1`).
- Default rate **10000 pps** (`-r/--rate`, `src/zmap.1`: "Setting the rate to 0 will scan at full line rate"); `-B/--bandwidth` overrides it.
- Send socket (`src/socket-linux.c`): default `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`; with `--iplayer` (raw IP injection) it opens `socket(PF_INET, SOCK_RAW, IPPROTO_RAW)` — the only mail-path variant that lands in `/proc/net/raw`.
- Probe surface (first-hand filenames in `src/probe_modules/`): `tcp_synscan`, `tcp_synackscan`, `udp`, `dns`, `icmp_echo`, `icmp_echo_time`, `ntp`, `upnp`, `bacnet`, `ipip`. The default is `-M tcp_synscan`.
- SYN shape (`src/probe_modules/module_tcp_synscan.c`): default probe module `tcp_synscan`; the SYN carries **Windows-style TCP options** (MSS + NOP/WScale + NOP/SACK-permitted — `src/probe_modules/packet.c::set_tcp_options`), TCP header 32 B, so the frame is **52 B at L3, 66 B at L2**; the code comments that these options give the highest response hit-rate.
- Stateful follow-up is zgrab2: the docs' pipeline is `zmap | zgrab2` — zmap finds open ports, zgrab2 handshakes.

**zgrab2** (`https://github.com/zmap/zgrab2`, cloned 2026-11-01, `main`):

- App-layer banner/header grabber with transcript output: the README describes it as "fast, modular application-layer network scanner designed for completing large Internet-wide surveys... Unlike many other network scanners, ZGrab outputs detailed transcripts of network handshakes (e.g., all messages exchanged in a TLS handshake) for offline analysis." Module table (README, read 2026-11-01): AMQP, BACnet, Banner, DNP3, Fox, FTP, HTTP, IMAP, IPP, JARM, ManageSieve, Memcached, Modbus, MongoDB, MQTT, MSSQL, MySQL, NTP, Oracle, POP3, PostgreSQL, PPTP, Redis, Siemens, SMB, SMTP, SOCKS5, SSH, Telnet, TLS. Ordinary Go `net` sockets; no raw packet path.
- Default HTTP request shape (`modules/http/scanner.go`): `Method=GET`, `Endpoint=/`, **`UserAgent = "Mozilla/5.0 zgrab/0.x"`**, `MaxRedirects=0`, `MaxSize=262144` (256 KB); per-request headers `Host`, `User-Agent`, `Accept`, `Accept-Encoding` are rebuilt on every probe.
- Scheduler (`config.go`): `-s/--senders` is a worker-pool size, **default 1000** goroutines (`defaultSenders = 1_000`); connect timeout 10 s, per-target timeout 60 s.

**nuclei** (`https://github.com/projectdiscovery/nuclei`, cloned 2026-11-01, `main`):

- Template-driven HTTP probing (per-protocol templates in YAML); ordinary Go sockets.
- Default **User-Agent: randomized per request**. `pkg/protocols/http/build_request.go::setHeaders`? — the relevant line is `userAgent := useragent.PickRandom()` (line 583 in the clone); `pkg/protocols/utils/http/requtils.go` documents that headers are set "only if the header wasn't supplied by the user", so a template UA wins, otherwise the UA is drawn from the `projectdiscovery/useragent` library (its README: categorized user-agent pool). A fixed "Nuclei"-string UA appears only in the fuzz harness (`nuclei-fuzz`), not the default scanner.
- Rate/scheduler flags (`cmd/nuclei/main.go`): `-rl/--rate-limit` **150 requests/s**, `-rld` duration 1 s, `-bs/--bulk-size` 25 (hosts per template in parallel), `-c/--concurrency` 25 (templates in parallel), `-headc` 10; stats: `-stats` (progress bar; off by default), `-si/--stats-interval 5`, `-mp/--metrics-port 9092`.

**nmap** (`https://nmap.org/book/performance-timing-templates.html`, fetched 2026-11-01): timing template only here, keep brief. `-T5` ("insane", Table 6.3): `max-rtt-timeout 300 ms`, `initial-rtt-timeout 250 ms`, `max-retries 2`, `max-scan-delay 5 ms`, `host-timeout 15 min`. The author recommends `-T4`; `-T5` is tuned to be fast enough that some hosts fire their own rate-limit defenses, so fleet operators mostly stop at `-T4`.

## 2. How the fleet-rental market actually looks

- One hosted orchestration layer exists in the open: **Fleex** (https://fleexsecurity.github.io/fleex-docs/) — a CLI that spawns a fleet of VM images, distributes targets across them and runs nmap/masscan/nuclei-style scans in parallel, with a cost-estimate subcommand. It is a scheduling wrapper: the packets still come from the masscan/zmap/nuclei covered in §1.
- The only verified ecosystem mapping is GreyNoise's: their sensor fleet tags "Tool tags can be anything from open-source scanning tools to programming language libraries, such as NMap, Nuclei, Metasploit, Paramiko, and Go HTTP" (fetched 2026-11-01, https://docs.greynoise.io/docs/greynoise-tags). A `masscan` Visualizer tag page exists (https://viz.greynoise.io/tag/masscan-client, 403 to anonymous fetch — cannot confirm its contents from here).
- Beyond that, "scanning VPS" offers (`anonrdp` marketing pages, `incognion` offshore-hosting lists, LowEndTalk threads) are vendor marketing and forum anecdotes, not first-hand verifiable claims — they are not tabulated here (§8).

- A live ecosystem datapoint for the "scanners run everywhere" premise: SecurityScorecard's own scanner blog (2026-09-01, fetched 2026-11-01) separates "Mass scanners like ZMap and Masscan probe the entire internet at high speed, sweeping billions of addresses... Targeted scanners like Nmap go deep on a smaller set of hosts" — i.e. a commercial attack-surface firm runs the exact §1 tool set at fleet scale (https://securityscorecard.com/blog/what-is-internet-wide-scanning-and-how-attackers-use-it/).

That market is small in code but real in effect: a squatted cloud host participates today as one node in an orchestrated masscan/zmap/nuclei run whose scheduling came from a wrapper like Fleex, not as a standalone decision by whatever sits on the host. The tools are also not exotic: GreyNoise's Tool-tag list puts NMap, Nuclei and masscan-family fingerprints in the *benign-scanner* range, so the market's distinguishing feature is who rents the host, not what the packets look like.

## 3. What a scanning squat looks like from inside the host

**Three socket routes, each visible in a different table.**

| route | tools | table |
| --- | --- | --- |
| raw AF_INET (`IPPROTO_RAW`) | zmap `--iplayer`, most nmap SYN modes, banner-grabbing masscan runs needing a real TCP stack | `/proc/net/raw` |
| AF_PACKET (frame-level) | masscan default (`--send-eth` via libpcap), zmap default | `/proc/net/packet` |
| normal sockets (SOCK_STREAM) | zgrab2, nuclei, curl/wget, nmap `-sT`/`-sV` on normal connect | `/proc/net/tcp`, `ss`, conntrack |

`/proc/net/raw` field semantics (`https://www.man7.org/linux/man-pages/man5/proc_pid_net.html`, fetched 2026-11-01): it is "a dump of the RAW socket table"; of the columns, `sl`, `local_address` (address + protocol number), `tx_queue/rx_queue`, `uid` (effective UID of socket creator), `timeout`, `inode`, `ref`, `pointer`, `drops` are the informative ones; `tr`, `tm->when`, `rexmits`, `st` are not used by RAW. There is no "listener" concept for AF_INET raw sockets — the practical shape is: **nonempty `/proc/net/raw` on a host that has no packet-capture daemon and no nmap-style audit running is, by construction, a candidate**, and the `inode` column pairs the entry to a `/proc/<pid>/fd` on a world-readable host. Idle baseline observed on this worker (Artix, uid 966, 2026-11-01 19:02 UTC): header only, zero rows.

```text
# /proc/net/raw on an idle host (this worker, 2026-11-01 19:02 UTC):
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
(no data rows)
```

`/proc/net/packet` is the masscan/zmap-default route (`https://raw.githubusercontent.com/torvalds/linux/master/net/packet/af_packet.c`,`packet_seq_show` at line 4874, fetched 2026-11-01): each row is `sk RefCnt Type Proto Iface R Rmem User Inode`, where `sk` is a pointer unique to the socket, `Proto` is the bound L3 protocol (`0800` for IPv4 frames, `3` for all-frame capture), `R` is whether the socket is enabled to receive (`PACKET_SOCK_RUNNING`), `Rmem` is take-from-userspace bytes queued for the socket, `User` is uid, `Inode` pairs it to `/proc/<pid>/fd` like `/proc/net/raw`. The idle host is not always empty — observed on this worker (Artix, uid 966, 2026-11-01 19:02 UTC, kernel `7.2.11-artix1-1`):

```text
# /proc/net/packet, idle host:
sk               RefCnt Type Proto  Iface R Rmem   User   Inode
0000000036c68096 3      2    888e   0     1 0      65534  11689
0000000079895a04 3      2    890d   3     1 0      65534  11696
```

Two rows from clock-sync daemons (PTP over Ethernet), `Rmem 0` (nothing queued), `uid 65534` — so the detection primitive is a **matching Inode→fd to a recently-started, "no-listener" process** rather than "any row".

Normal-socket scanners leave kernel TCP fingerprints (`https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/snmp.h`, `TCP_MIB_ACTIVEOPENS` at line 136): `/proc/net/snmp`'s `Tcp` row has a fixed field order (verified on this worker, 2026-11-01); field 6 is `ActiveOpens`, incremented in `net/ipv4/tcp_output.c::tcp_connect()` when the kernel opens a SYN. Observed on this worker (2026-11-01 19:02 UTC):

```text
# /proc/net/snmp, Tcp row field order (header line, sandbox-verified):
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails
     EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
# extracted with dict(zip(header, values)): ActiveOpens=25776 PassiveOpens=63 OutSegs=10123911
```

The extraction one-liner is the same `dict(zip(header, values))` pattern `research/network-flow-heuristics-proxyjacking.md` uses for its ICMP counters.

**Conntrack shape.** `net.netfilter.nf_conntrack_tcp_timeout_syn_sent` defaults to **120** s (verified in `Documentation/networking/nf_conntrack-sysctl.rst`, torvalds/linux master, lines 150-151). For normal-socket scanners thousands of short-lived `SYN_SENT` entries churn through conntrack; the same is *not* true for AF_PACKET senders — code-read inference: `packet_xmit()` (`net/packet/af_packet.c:277`) calls `dev_queue_xmit()` directly and never passes the `LOCAL_OUT`/`POST_ROUTING` hooks (`net/ipv4/ip_output.c`) where conntrack runs, and systemd's IPAccounting likewise does not see it (quoted below). **This inference has not been live-measured here** — this worker lacks `CAP_NET_RAW`, so it cannot open an AF_PACKET sender to compare conntrack tables (§8). Also observed on this worker (2026-11-01 19:02 UTC): neither `/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent` nor `/proc/net/nf_conntrack` exists, because conntrack is not loaded; both tables and sysctls appear only with the module loaded — a conntrack-absent host silently fails this check instead of reporting zero.

### 3.1 Near-shapes: where the tables would NOT fire

- **Banner-mode masscan completes real TCP handshakes — but never through the kernel.** The README: masscan "contains its own TCP/IP stack separate from the system you run it on", and its two avoidance recipes are a spare `--source-ip` or `iptables -A INPUT -p tcp --dport N -j DROP` so "masscan still sees it [the SYN-ACK] since it bypasses the local stack". Result: no `ss -tan state syn-sent` row from masscan even in banner mode, no kernel `Tcp` delta, and the completed banner flows live only in masscan's own memory and traffic — the kernel tables never learned these connections existed.
- **The symmetric failure applies to zmap only in default mode.** `-X/iplayer` (AF_INET raw) *does* pass the kernel's `LOCAL_OUT` hooks (it sends through `raw_sendmsg`), so conntrack sees it; default AF_PACKET zmap does not. The two modes of one tool produce opposite host-side fingerprints, which is why §6 greps both tables.
- **The per-unit ratio check cannot be defeated by mixing modes.** Because it only ever sees normal-socket traffic, a unit that runs zgrab2 (normal sockets) *and* an AF_PACKET flood shows a clean-looking Bytes/Packets ratio for the latter and a scanning shape for the former — the two routes complement, never mask, but neither substitutes for the other.

**Per-unit accounting route (the one the corpus already has).** `systemd.exec(5)` / `systemd.resource-control` document `IPAccounting=` ("Takes a boolean…", added in v235 — property names `IPEgressBytes`/`IPEgressPackets` verified in `src/core/cgroup.c` of systemd main) (https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html). Lennart Poettering's own intro post states the boundary: "`AF_PACKET` (i.e., raw) **sockets are not covered**" (https://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html). So the bytes-per-packet arithmetic here **covers zgrab2/nuclei/curl-style normal-socket flows only**; masscan and zmap-by-default (libpcap) are invisible to the per-unit counters and must be caught via `/proc/net/packet` instead. Header arithmetic: RFC 791 IPv4 minimum header is 20 B (IHL×4, `https://www.rfc-editor.org/rfc/rfc791.html`), RFC 793 TCP minimum header 20 B (Data Offset field, `https://www.rfc-editor.org/rfc/rfc793.html`), RFC 8200 IPv6 fixed header 40 B (`https://www.rfc-editor.org/rfc/rfc8200.html`). So a **payloadless SYN flow emits ~40 B/packet (IPv4+TCP, no payload), ~52 B with zmap's options block, ~64 B for an IPv6 SYN without options, plus GSO undercount caveats** (systemd issue #34775, GSO byte-count undercount — `research/per-user-network-accounting.md` covers this and I am not restating those mechanics here). A threshold is only meaningful against those computing conditions, not absolutely.

**Persistence route.** The ordinary ways a fleet node schedules itself — cron entries, systemd timers, at-style jobs — fall into the persistence-directory set `checks/50-proxyjack.rules` already watches; the check exists, this file does not restate it.

## 4. Provider-side tie-in

The corpus already names the boundary: "Provider flow logs are named as the view the guest cannot edit" (`HARDENING.md` D59, "coverage gaps"). What arrives at the operator from that outside view is an **abuse notice**: a Tor-relay operator's 2025-10-15 forum post (https://forum.torproject.org/t/tor-relays-abuse-report-from-relays-in-family-7eaac49a7840d33b62fa276429f3b03c92aa9327/20693 — relay, not primary) quotes a Hetzner notice *"NetscanOutLevel: scansnarf-ng detected Netscan from xxx.xxx.xxx.xxx"* with the body "We have indications that there was an attack from your server. Please take all necessary measures to avoid this in the future and to solve the issue." — i.e. **the provider's own netflow detector fired, the notice text blames the host, and the operator is the one who has to answer.** GreyNoise frames the same trade from the defender's side: a scanning node is fine "provided you like handling abuse complaints and can afford the bandwidth costs on providers that allow such activity" (https://www.greynoise.io/blog/new-sensor-benign-activity). A squatted VPS loses at both ends: the host's owner answers the abuse notice for traffic the guest generated, and the corpus's DET0028 quote intends to catch the same phenomenon from the detector side.

## 5. The tools, side by side

| Tool | Scan mode | Payloadless? | Raw-socket path | Scheduling mechanism |
| --- | --- | --- | --- | --- |
| masscan | TCP SYN (its README/man page: "`-sS`: this does SYN scan only") | Yes — SYN, no TCP data; 44 B L3 | AF_PACKET via libpcap (`--send-eth`); no AF_INET raw data path | `--rate` (default 100 pps); base source-port block chosen once per process |
| zmap | TCP SYN (one packet per target) | Yes — SYN + options block; 52 B L3 | AF_PACKET default; `--iplayer` switches to `AF_INET`/`IPPROTO_RAW` | `--rate` (default 10000 pps, 0 = line rate); `--probes` (default 1) |
| zgrab2 | HTTP (+ TLS, SSH, FTP, SMTP, SMB modules) | No — full HTTP requests | none — ordinary Go sockets | `--senders` worker pool (default 1000); connect timeout 10 s |
| nuclei | HTTP templates (per-protocol YAML) | No — templated requests | none — ordinary Go sockets | `-rl` 150 req/s, `-bs` 25, `-c` 25, `-headc` 10 |
| nmap `-T5` | all nmap scan types (timing template only) | n/a — tuning, not a packet shape | raw packet sends per scan type | host-timeout 15 min, max-retries 2, max scan delay 5 ms |

No cell is invented: each is from the tool's own README, man page or source as cited in §1.

## 6. Detection recipe (cheapest first)

Run from inside the host. Everything below is one command or one file read; the "FP condition" line is the situation under which the row is not evidence of a squat.

1. **`ss -tan state syn-sent`** (world-readable; verified 2026-11-01 on this worker, exit 0, prints the `Recv-Q Send-Q Local Address:Port Peer Address:Port` header). A scanning frenzy fills it momentarily (`ss -h` on this sandbox lists `syn-sent` in the STATE-FILTER help line: `TCP-STATES := {established|syn-sent|syn-recv|...}`). *FP condition*: the host is a CI runner or a web crawler mid-run; zgrab2/nuclei bursts are ephemeral and look exactly like a multi-threaded client (zgrab2 spawns 1000 senders, so a burst of `SYN_SENT` is normal scale for it).
2. **`/proc/net/raw` nonempty baseline check** (world-readable; verified empty on the idle sandbox, 2026-11-01 19:02 UTC). Any row on an uninstrumented host is a candidate; pair its `inode` to `/proc/<pid>/fd` and to the other tables. *FP condition*: the page's readers are `nmap`, packet-capture tooling or the operator's own audit, and the `uid` column does not match an unknown service.
3. **`/proc/net/packet` nonempty baseline check** (world-readable; verified on the sandbox, idle host shows 2 rows from `uid 65534` clock-sync daemons). A row whose `Inode` resolves to a recently-started process with **no `/proc/net/tcp` listener** is the masscan/zmap shape. *FP condition*: clock-sync, `tcpdump`, provider agent or supervisor tooling all legitimately hold AF_PACKET sockets — the shape is not "row>0", it is "row → an unexplained uid and unexplained process".
4. **Extract `Tcp ActiveOpens` twice, ~60 s apart** (world-readable; field order fixed, §3, verified 2026-11-01 on this worker):

```sh
python3 -c 'l=open("/proc/net/snmp").read().splitlines();
 h=[x.split()[1:] for x in l if x.startswith("Tcp:")][0];
 v=[x.split()[1:] for x in l if x.startswith("Tcp:")][1];
 d=dict(zip(h,v)); print("ActiveOpens", d["ActiveOpens"], "PassiveOpens", d["PassiveOpens"])'
```

A delta in the thousands over a minute on a host with no declared crawling/churn role is the scanning shape. *FP condition*: short-lived bursts on a run-ephemeral box (batch browser test, deploys) — the tell is *relative to the host's own prior baseline*, not absolute (see sibling `research/network-flow-heuristics-proxyjacking.md` for the rate-vs-shape framing).
5. **Per-unit ratios** (root needed): for each unit with `IPAccounting=yes`, compare `IPEgressBytes` to `IPEgressPackets` (`busctl`/`systemctl show -p IPEgressBytes,IPEgressPackets <unit>`); a unit whose ratio sits near the SYN-shape sizes above (~40–80 B) is a scanning unit. *FP condition*: AF_PACKET senders are invisible to this counter (quoted above), GSO undercount (systemd #34775) can distort individual flows, and a unit that also serves real HTTPS can carry a large payload inside the same counter — the check is per-unit, not per-flow.
6. **conntrack** (root needed): `cat /proc/net/nf_conntrack | grep SYN_SENT` plus `sysctl net.netfilter.nf_conntrack_tcp_timeout_syn_sent` (default **120**). *FP condition*: two caveats, not one — (i) empty conntrack is the *normal* AF_PACKET-scanner case (masscan/zmap SYN floods never enter conntrack; code-read inference, §3) so an empty table is never evidence, and (ii) the tables may be absent entirely because the conntrack module is not loaded (observed on this worker, 2026-11-01); crawlers and health probes create the same entries when it is loaded.
7. **Persistence relations** (root): the persistence watches named in `checks/50-proxyjack.rules` (cron dirs, systemd timers) shortlist the candidate identities most likely to *be* the scheduler. *FP condition*: every backup job and every package-update timer lives in the same directories; the watch fires on shape, not intent.

Items 1–4 run unprivileged; 5–7 need root and cost one command each. The recipe is **inside-the-host only** — the external provider-vantage equivalents live in the corpus as "outside the guest" (`HARDENING.md` D59).

## 7. Sources

- scanner source (cloned 2026-11-01, read first-hand) · https://github.com/robertdavidgraham/masscan · https://github.com/zmap/zmap · https://github.com/zmap/zgrab2 · https://github.com/projectdiscovery/nuclei
- kernel and man-page ground truth · https://www.man7.org/linux/man-pages/man5/proc_pid_net.html · https://raw.githubusercontent.com/torvalds/linux/master/net/packet/af_packet.c · https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/snmp.h · https://raw.githubusercontent.com/torvalds/linux/master/Documentation/networking/nf_conntrack-sysctl.rst
- header-size arithmetic · https://www.rfc-editor.org/rfc/rfc791.html · https://www.rfc-editor.org/rfc/rfc793.html · https://www.rfc-editor.org/rfc/rfc8200.html
- per-unit accounting boundary · https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html · https://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html (AF_PACKET caveat) · systemd issue #34775 (GSO undercount, see sibling `research/per-user-network-accounting.md`)
- ecosystem datapoints · https://docs.greynoise.io/docs/greynoise-tags · https://viz.greynoise.io/tag/masscan-client (403 to anonymous fetch) · https://www.greynoise.io/blog/new-sensor-benign-activity · https://fleexsecurity.github.io/fleex-docs/ · https://forum.torproject.org/t/tor-relays-abuse-report-from-relays-in-family-7eaac49a7840d33b62fa276429f3b03c92aa9327/20693
- timing template · https://nmap.org/book/performance-timing-templates.html
- corpus siblings · `checks/50-proxyjack.rules` · `checks/network-gaps.sh` · `research/network-flow-heuristics-proxyjacking.md` · `research/per-user-network-accounting.md` · `HARDENING.md` (D59 wording) · `REPORT.md` (DET0028 quote)

## 8. What I could not verify

- **masscan's "rmem_max requirement" — searched the whole first-hand clone (`grep -rn -i rmem` over `src/`, `doc/`, `extra/`); the only hit is `LUA_ERRMEM` in `stub-lua.h`, an unrelated macro.** The requirement named in the task brief does not exist in the project; rate-limit errors in practice are ENOBUFS/packet-send failures, not a tunable documented by the tool. Treating it as hint-not-holding, not as fact.
- **A Go reimplementation of masscan: none exists that I could verify.** The GitHub projects named as "Go masscan" (`zan8in/masscan`, `raylax/masscan`, `moond4rk/go-masscan`) all document themselves as libraries that **shell out to a locally installed `/usr/bin/masscan`**, i.e. wrappers around the C binary, not reimplementations. This meansDetection targeting "renamed/wrapped *binaries*" still lands on a real `masscan` process — which is the FP-relevant note, not a distinct tool.
- **Scan-fleet SaaS market beyond Fleex: unverified.** `PortScannerPro` "nmap as a service" marketing, `AnonRDP`/`Incognion` "scanning VPS" pages and LowEndTalk anecdotes are vendor pages and forum posts; no first-hand proof of an actual fleet rental ceiling, SLA or abuse-tolerance policy was found. Kept out of the table deliberately.
- **Netmap / PF_RING throughput claims (zmap <5 min at 10 gigE, masscan ~2 Mpps and above with Intel 10-GigE): README quotes, not measured here.** This worker has no PF_RING, kernel-module build toolchain or 10-GigE NIC, so the numbers are the projects' own claims, not experiments.
- **The "AF_PACKET sends bypass conntrack hooks and `Tcp ActiveOpens`" detection asymmetry is code-read only.** Verified in source (`net/packet/af_packet.c::packet_xmit`, `net/ipv4/ip_output.c` hook placement) but this worker lacks `CAP_NET_RAW`, so no live comparison of conntrack counts between a masscan run and a zgrab2 run was possible. To close this gap: a disposable VM with two scanners and a `conntrack`/`ss` diff would do it in one command pair.
- **The Hetzner `NetscanOutLevel: scansnarf-ng` notice text is quoted at third hand** (a Tor-relay forum post by an operator, 2025-10-15); no Hetzner documentation confirms the detector's name or wording.
- **A live bytes-per-packet measurement for a unit with `IPAccounting=yes` running zgrab2/nuclei/masscan was not performed**, so the §3 ratios remain arithmetic from header sizes plus README packet shapes; the GSO undercount (systemd #34775) means individual flows will over- or under-shoot the 40–80 B framing. Sibling `research/per-user-network-accounting.md` already covers the undercount mechanics; this file's numbers are a *computing-condition* threshold, not an observed one.

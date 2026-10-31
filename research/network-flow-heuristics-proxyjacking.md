# Network-Flow Heuristics for Detecting Proxyjacking, Tunnel Squatting and Torrent Abuse on One Linux Server

Free/open-source only. BPF filters were syntax-checked by compiling them with `pcap_compile()` against libpcap; version numbers come from upstream docs or the projects' field references.

## Summary

- **JA3 needs a package on Zeek, is in Suricata's EVE TLS output since at least 4.1 and built into Wireshark ≥3.6.0. JA4 is built into Suricata ≥8.0 and Wireshark ≥4.2.0, and on Zeek needs `zkg install zeek/foxio/ja4` with Zeek 7.0+.**
- **JA4 is the right fingerprint for this threat** because its `_b` and `_c` sections hash *sorted* cipher/extension lists, so a proxy that randomises extension order stops generating a new hash per connection — and the same fingerprint appears whether the client spoke TCP or QUIC.
- **BitTorrent is two one-line BPF filters**: `tcp[((tcp[12] & 0xf0) >> 2):4] = 0x13426974` finds the `0x13 "Bit"` peer handshake at any payload offset; `udp[8:4] = 0x64313a61`/`0x64313a72` finds DHT KRPC queries/responses, because bencoded dict keys are sorted so every message starts `d1:`.
- **QUIC is the modern hiding place**: Zeek ≥6.1 writes `quic.log` (SNI, ALPN, version); Suricata ≥8.0 writes a `quic` EVE record with SNI *and* JA4. `cloudflared` tunnels deliberately use UDP/TCP 7844; WireGuard handshake-initiations are fixed 148-byte UDP packets starting `01 00 00 00`.
- **SOCKS is the actual proxyjacking protocol** and Zeek ships a SOCKS analyzer (`@load base/protocols/socks`, on by default) writing `socks.log`; on the wire a SOCKS5 CONNECT is the 4-byte constant `05 01 00 01`.
- **DNS is where tracker/bootstrap/DGA names surface**; a Shannon-entropy test on the leftmost label is ~10 lines of `awk`, no package.
- **Beaconing and long-lived sessions are solved free by RITA** (beaconing, long connection, DNS tunnelling), thresholds `base: 50 / low: 70 / medium: 90 / high: 100`.
- **Line rate is architecture, not tuning**: Zeek is explicitly single-threaded and needs AF_PACKET fanout past one core; Suricata is multi-threaded and its `workers` runmode "performs the best".
- **Verify you are not lying to yourself**: Zeek's `capture_loss.log` `percent_lost` is the only honest answer to "am I seeing this traffic".

## 1. TLS client fingerprinting

**JA3** is MD5 over the decimal ClientHello fields `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`, e.g. `769,47-53-5-10-…,0-10-11,23-24-25,0` (<https://github.com/salesforce/ja3>). It is no longer maintained by Salesforce, and it hashes ordered lists, so ordering randomisation per connection defeats it.

**JA4** is `a_b_c`, e.g. `t13d1516h2_8daaf6152771_b186095e22b6` (<https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>):

- `a` = protocol char (`q` QUIC / `d` DTLS / `t` TLS-over-TCP) + 2-char TLS version + `d`/`i` (SNI present/absent) + 2-char cipher count + 2-char extension count (each capped `99`) + first and last alphanumeric char of the first ALPN value (`h2`, `h1`, else `00`).
- `b` = first 12 hex chars of SHA-256 over the cipher hex codes **sorted** in hex order, comma-delimited, GREASE removed (`000000000000` if none).
- `c` = first 12 hex chars of SHA-256 over the extension hex codes **sorted**, with `0000` (SNI) and `0010` (ALPN) removed, then `_`, then the signature algorithms in appearance order.

**JA4S** has no prose spec — FoxIO ships only `technical_details/JA4S.png` — so this is read from the reference implementation `zeek/src/ja4s.cc`:

```
JA4S = {proto}{version}{2-char ext count}{ALPN first+last} _ {4-hex chosen cipher} _ {sha256(ext codes)[:12]}
```

Two differences from JA4 matter: the middle section is the **raw** 4-hex-digit cipher (not a hash), and the extension list is emitted in ServerHello order, unsorted (<https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/zeek/src/ja4s.cc>). FoxIO's own framing: "if the client sends JA4=a_b_c and the server responds with JA4S=d_b_e, that server will always respond to a_b_c with d_b_e" (<https://blog.foxio.io/ja4+-network-fingerprinting>) — so JA4+JA4S together identify a relay far better than either alone.

| Tool | JA3 | JA4 |
|---|---|---|
| Zeek | needs package: `zkg` install of `salesforce/ja3` (`zkg.meta` → `script_dir = zeek`), lands in `ssl.log` (<https://raw.githubusercontent.com/salesforce/ja3/master/zkg.meta>, <https://docs.zeek.org/en/current/logs/ssl.html>) | needs package: `zkg install zeek/foxio/ja4`; **Zeek 7.0+**, C++20 (Clang 19+/GCC 12+), CMake 3.15+ (<https://github.com/FoxIO-LLC/ja4/blob/main/zeek/README.md>) |
| Suricata | built in; in EVE TLS docs from **4.1.0** (<https://docs.suricata.io/en/suricata-4.1.0/output/eve/eve-json-format.html>) | built in from **8.0**; absent in 7.0.0 docs, present in 8.0.0 (<https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html>) |
| tshark | `tls.handshake.ja3`, **3.6.0+** | `tls.handshake.ja4`, **4.2.0+** (<https://www.wireshark.org/docs/dfref/t/tls.html>) |

Suricata leaves fingerprints off unless a rule needs them (<https://raw.githubusercontent.com/OISF/suricata/master/suricata.yaml.in>):

```yaml
app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
      #ja3-fingerprints: auto      # disabled by default, enabled if rules require it
      #ja4-fingerprints: auto
```

Set both to `yes`. Rules then match on sticky buffers, and the `quic` protocol keyword works too, so one JA4 covers TCP and UDP proxies (<https://docs.suricata.io/en/suricata-8.0.0/rules/ja-keywords.html>; `startswith` is a real `content` modifier per the same guide's §8.7.4, <https://docs.suricata.io/en/suricata-8.0.0/rules/payload-keywords.html>):

```
alert tls  any any -> any any (msg:"JA4 known proxy client"; ja4.hash; \
    content:"t13d1516h2_8daaf6152771_b186095e22b6"; sid:1000101;)
alert quic any any -> any any (msg:"JA4 QUIC, no SNI"; ja4.hash; \
    content:"q13i0310h3_"; startswith; sid:1000102;)
```

## 2. SNI extraction without a tap

`tls.handshake.extensions_server_name` has been stable since Wireshark 3.0.0 (<https://www.wireshark.org/docs/dfref/t/tls.html>):

```sh
tshark -r capture.pcapng -Y 'tls.handshake.type == 1' -T fields -E separator=/t \
  -e ip.src -e tcp.dstport -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str -e tls.handshake.ja3 -e tls.handshake.ja4

# a proxy client's shape: SNI absent, or ALPN not h2/h1
tshark -r capture.pcapng -Y 'tls.handshake.type == 1 && !tls.handshake.extensions_server_name' \
  -T fields -e ip.src -e ip.dst -e tcp.dstport -e tls.handshake.ja4
```

With no Wireshark installed, filter handshake records and grep cleartext. `proto [ expr : size ]` takes any arithmetic expression, size ∈ {1,2,4} (<https://www.tcpdump.org/manpages/pcap-filter.7.html>):

```sh
tcpdump -i eth0 -n -s0 -A -l \
  'tcp and tcp[((tcp[12] & 0xf0) >> 2):1] = 0x16 and not tcp port 443' \
| grep -aoE '[a-z0-9][a-z0-9._-]{3,60}\.(com|net|org|io|xyz|top|biz)'
```

Caveat from the same man page: transport-header arithmetic "does not work against IPv6 packets. It only looks at IPv4 packets."

## 3. QUIC and UDP anomaly

RFC 9000 §17.2: byte 0 of a long header carries `Header Form = 0x80` and `Fixed Bit = 0x40`; Initial is long packet type `0x00`, so an Initial's first byte is `0xC0`–`0xCF`. Version 1 is `0x00000001` (<https://www.rfc-editor.org/rfc/rfc9000.txt>). A UDP/443 stream of `0xC0` first bytes with no matching Zeek `quic.log` entry is either a broken QUIC stack or something else wearing 443.

`quic.log` (added **6.1**) exposes `version`, `client_initial_dcid`, `server_scid`, `server_name`, `client_protocol`, `history` (<https://docs.zeek.org/en/current/logs/quic.html>):

```sh
zeek-cut id.orig_h id.resp_h server_name client_protocol < quic.log \
| awk -F'\t' '$3=="" || $4!~/^(h3|hq-)/ {print}'
```

Suricata's `quic` EVE record carries `version`, `sni`, `ua`, `client_alpns`, `cyu`, `ja3`, `ja3s`, `ja4` — the same shape as TLS (<https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html>). Three more UDP signatures, all verified to compile:

```sh
# WireGuard handshake initiation: type=1 + 3 reserved zero bytes, 148-byte payload
tcpdump -n 'udp and udp[8:4] = 0x01000000 and udp[4:2] = 156'
# STUN / WebRTC hole punching: top 2 bits zero, magic cookie 0x2112A442 (RFC 5389 §6)
tcpdump -n 'udp and udp[8:2] & 0xc000 = 0 and udp[12:4] = 0x2112a442'
# any QUIC long header
tcpdump -n 'udp and udp[8] & 0xf0 = 0xc0'
```

WireGuard's field layout (`u8 message_type`, `u8 reserved_zero[3]`, `u32 sender_index`, …) and message types 1/2/4/3 are on <https://www.wireguard.com/protocol/>; 148 bytes is the arithmetic sum of its documented fields. STUN's zero top bits and `0x2112A442` cookie are RFC 5389 §6 (<https://www.rfc-editor.org/rfc/rfc5389.txt>).

**Tunnel squatting** is unusually easy: `cloudflared` "connects outbound to Cloudflare on port `7844`" over both TCP and UDP to `region1.v2.argotunnel.com`/`region2.v2.argotunnel.com` (<https://developers.cloudflare.com/tunnel/configuration/>, <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/>). A long-lived QUIC session to 7844 whose ALPN is not `h3` is not a browser.

## 4. BitTorrent: 0x13 handshake and DHT KRPC

BEP 3: the peer handshake "starts with character ninteen (decimal) followed by the string 'BitTorrent protocol'" — the `0x13` is a length prefix "put there in the hope that other new protocols may do the same and thus be trivially distinguishable" (<https://www.bittorrent.org/beps/bep_0003.html>). Total is 68 bytes: `1 + 19 + 8 + 20 + 20`. Zeek's analyzer enforces it (`pstrlen != 19` or bad `pstr` → exception; PDU `&length = 68`, <https://raw.githubusercontent.com/zeek/zeek/master/src/analyzer/protocol/bittorrent/bittorrent-analyzer.pac>, `.../bittorrent-protocol.pac`).

```sh
# 0x13 'B' 'i' 't' at payload offset 0 — finds peers on any port
tcpdump -i eth0 -n -A 'tcp and tcp[((tcp[12] & 0xf0) >> 2):4] = 0x13426974'
```

DHT is easier: BEP 5's KRPC messages are single bencoded dictionaries, and BEP 3 requires dict keys "in sorted order (sorted as raw strings, not alphanumerics)" — so every message begins `d1:` and the next character gives the direction (<https://www.bittorrent.org/beps/bep_0005.html>):

| Message | Prefix | BPF |
|---|---|---|
| query (`ping`/`find_node`/`get_peers`/`announce_peer`) | `d1:ad2:id20:` | `udp[8:4] = 0x64313a61` |
| response | `d1:rd2:id20:` | `udp[8:4] = 0x64313a72` |
| error | `d1:eli201e` | starts `d1:e` |

```sh
tcpdump -i eth0 -n -c 200 'udp and (udp[8:4] = 0x64313a61 or udp[8:4] = 0x64313a72)'
```

`announce_peer` carries `info_hash` and the port the peer will download on, in cleartext — the single most incriminating field on the wire.

Suricata ≥7 parses DHT natively: `SCRegisterBittorrentDhtUdpParser()` is registered unconditionally in `src/app-layer-parser.c`, the parser is `enabled: yes` with no port restriction, and EVE emits `bittorrent-dht` events with `request_type`, `request.info_hash`, `request.port`, `response.nodes` — the event type is in the 7.0 docs and absent from 6.0 (<https://raw.githubusercontent.com/OISF/suricata/master/src/app-layer-parser.c>, <https://docs.suricata.io/en/suricata-7.0.12/output/eve/eve-json-format.html>). Zeek's BitTorrent analyzer is a compiled component (`Zeek::BitTorrent`, `bittorrent_peer_handshake`, `bittorrent_peer_port`, `bittorrent_peer_request`) but has **no script and no log** — `@load base/protocols/bittorrent` does not exist and `base/protocols/socks` is in `init-default.zeek` while `bittorrent` is not — so you must bind and log it yourself:

```zeek
@load base/protocols/conn
event zeek_init() { Analyzer::register_for_ports(Analyzer::ANALYZER_BITTORRENT, {6881/tcp}); }
event bittorrent_peer_handshake(c: connection, is_orig: bool, reserved: string,
                                info_hash: string, peer_id: string) {
    print fmt("%s -> %s:%s info_hash=%s", c$id$orig_h, c$id$resp_h, c$id$resp_p,
              bytestring_to_hexstr(info_hash));
}
```

ntopng classifies the whole flow instead, showing "Bit Torrent" as the Application via nDPI (<https://www.ntop.org/guides/ntopng/user_interface/network_interface/flows/flows.html>).

## 5. SOCKS: the actual proxyjacking protocol

A proxyjacking implant is a relay, and relays speak SOCKS. Zeek ships a SOCKS analyzer and `socks.log` (`SOCKS::Info`, `SOCKS::LOG`, `SOCKS::ports`) and `@load base/protocols/socks` is in `init-default.zeek`, so it is on by default and DPD-driven, i.e. not tied to port 1080 (<https://docs.zeek.org/en/current/scripts/base/protocols/socks/main.zeek.html>, <https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/init-default.zeek>).

```sh
# SOCKS5 CONNECT: VER=5, CMD=1, RSV=0, ATYP=1  (RFC 1928)
tcpdump -n 'tcp and tcp[((tcp[12] & 0xf0) >> 2):4] = 0x05010001'
# SOCKS4 CONNECT: VN=4, CD=1
tcpdump -n 'tcp and tcp[((tcp[12] & 0xf0) >> 2):2] = 0x0401'
ss -lntup    # -p shows other users' processes only as root (man8 ss)
```

## 6. Notebook abuse

An exposed Jupyter server is a compute+network relay that needs no malware. Jupyter binds `127.0.0.1:8888` by default with token auth on (<https://jupyter-notebook.readthedocs.io/en/5.5.0/public_server.html>, <https://jupyter-server.readthedocs.io/en/latest/operators/security.html>), so a flow to 8888 from anywhere but localhost is already an anomaly. The kernel channel is a WebSocket, and Zeek's WebSocket analyzer is loaded by default (`@load base/protocols/websocket` in `init-default.zeek`) writing `websocket.log` (`$path="websocket"`, <https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/websocket/main.zeek>). The tell is shape, not content: HTTP `101 Switching Protocols` on a non-443 port followed by a very long-lived, low-rate, bidirectional flow — exactly the pattern in §8.

## 7. DNS anomaly: trackers, bootstrap nodes, DGA

Zeek's `dns.log` gives `query`, `qclass_name`, `qtype_name`, `rcode_name`, `answers`, `TTLs`, `rtt` (<https://docs.zeek.org/en/current/logs/dns.html>). Tracker/bootstrap names are ordinary FQDNs, so they are a blocklist problem — but a client that resolves a DHT bootstrap host and then starts emitting `0x64313a61` is a torrent node; correlate `dns.log` with §4.

DGA entropy needs no package (this snippet was tested locally):

```sh
zeek-cut query < dns.log | awk -F. '{
  l=$1; n=length(l); if (n<8) next; delete c;
  for(i=1;i<=n;i++) c[substr(l,i,1)]++;
  e=0; for(ch in c){ p=c[ch]/n; e -= p*log(p)/log(2) }
  if (e > 3.6) printf "%.2f %s\n", e, l
}' | sort -rn | head -40
```

Measured reference points: `google` → 1.92, `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6` → 4.62, `xqztvkfjrnwpl` → 3.70. The 3.6 cut-off is a starting point, not a published constant — set it from your own baseline. Long `TXT` answers and `NULL` queries are the classic tunnel shape; Suricata's `dns.rcode:!0` and `dns.opcode:!0` catch oddball traffic (<https://docs.suricata.io/en/suricata-8.0.0/rules/dns-keywords.html>). RITA adds a purpose-built DNS-tunnelling detector and "queries threat intel feeds to search for suspicious domains and hosts".

## 8. Beaconing and long-lived sessions

RITA does all three out of the box on Zeek logs — Beaconing Detection, Long Connection Detection, DNS Tunneling Detection, Threat Intel Feed Checking — and needs Docker Engine + Compose on CentOS 9 Stream, Rocky 9, RHEL 9 or Ubuntu 22.04/24.04 amd64. Severity buckets are documented: `beacon.score_thresholds` defaults to `base: 50, low: 70, medium: 90, high: 100` (<https://github.com/activecm/rita>, <https://github.com/activecm/rita/blob/main/docs/Configuration.md>).

```sh
rita import --database=proxy --logs=/opt/zeek/logs/current
rita view proxy                 # TUI search: beacon:>=90 sort:duration-desc
rita view --stdout proxy > out.csv
```

Without RITA, `conn.log` carries `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history` (<https://docs.zeek.org/en/current/logs/conn.html>). A relayed session is long, low-rate and bidirectional — not a download:

```sh
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log \
| awk -F'\t' '$4>3600 && $5>1e5 && $6>1e5 {printf "%s -> %s:%s %.0fs %d/%d\n",$1,$2,$3,$4,$5,$6}'
```

For an actual periodic-beacon script, Zeek's built-in `SumStats` framework (`SumStats::create`, `observe`, reducers `HLL_UNIQUE`/`LAST`) is the right primitive (<https://docs.zeek.org/en/current/scripts/base/frameworks/sumstats/main.zeek.html>). Read `weird.log` and `notice.log` daily — Zeek calls notices "the closest Zeek is coming to IDS alerts" (<https://docs.zeek.org/en/current/logs/weird-and-notice.html>).

## 9. What free tools do at line rate

**Zeek is single-threaded by design**: "once the limitations of a single processor core are reached the only option currently is to spread the workload across many cores" (<https://docs.zeek.org/en/current/cluster-setup.html>). AF_PACKET fanout is compiled in by default (check with `zeek -N Zeek::AF_Packet`):

```sh
sudo setcap cap_net_raw,cap_net_admin=+eip /opt/zeek/bin/zeek
zeek -i af_packet::eth0 &        # both workers join fanout group 23 (AF_Packet::fanout_id default)
zeek -i af_packet::eth0 &
IFACE=eth0; for o in rx tx sg tso ufo gso gro lro; do ethtool -K $IFACE $o off; done
```

(a worker restart transiently disturbs fanout balancing — visible as log gaps/duplicates).

**Suricata is multi-threaded**: "Generally, the `workers` runmode performs the best… the NIC/driver makes sure packets are properly balanced over Suricata's processing threads" (<https://docs.suricata.io/en/suricata-8.0.0/performance/runmodes.html>). Published knobs: `max-pending-packets` "Suggested setting: 10000 or higher. Max is ~65000"; `af-packet` with `tpacket-v3: yes` for IDS/NSM (v2 for IPS); `ring-size: 100000` per thread (<https://docs.suricata.io/en/suricata-8.0.0/performance/tuning-considerations.html>).

**ntopng Community** "is free to use and open source" and needs no license; nProbe Pro (flow collection) and reporting identity features are the paid tiers (<https://www.ntop.org/guides/ntopng/versions_and_licensing.html>). For free you get a live flow table with per-flow Application (nDPI), L4 proto, client/server, Duration, throughput, Total Bytes — an interactive version of the `conn.log` queries above. It also raises a **REMOTE TO REMOTE** alert, which "triggers when a device on the monitored network is detected to be communicating directly with another device outside of its normal subnet" (<https://www.ntop.org/guides/ntopng/user_interface/shared/alerts/remediations/ntopng_flow_risks.html>) — exactly a relay forwarding someone else's traffic.

**tcpdump + pipes** is cheapest and reassembles nothing, so it cannot see a handshake split across segments. Use it for §3–§5 byte signatures; move to Zeek or Suricata when you need per-flow state.

Finally, read `capture_loss.log`: `percent_lost` is derived from TCP sequence gaps and the docs' worked example shows `0.412308930008045` meaning 0.41%, "not 41.23%" (<https://docs.zeek.org/en/current/logs/capture-loss-and-reporter.html>). If it is not near zero, every negative below it is worthless.

## 10. Minimum runbook

`ss -lntup` (unexpected listeners) → SOCKS5 filter → DHT filter → WireGuard/7844 check → DGA awk → `rita view` with `beacon:>=90` and `duration:>2h` → group Suricata's TLS events by `.tls.ja4`. One JA4 shared by many internal hosts talking to one external IP is a proxy, not a browser fleet.

## Sources

JA4 algorithm <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md> · JA4S reference impl <https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/zeek/src/ja4s.cc> · JA4+ index <https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/technical_details/README.md> · JA4+ blog <https://blog.foxio.io/ja4+-network-fingerprinting> · JA4 Zeek plugin <https://github.com/FoxIO-LLC/ja4/blob/main/zeek/README.md> · JA4 tshark recipe <https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/README.md> · JA3 <https://github.com/salesforce/ja3> and <https://raw.githubusercontent.com/salesforce/ja3/master/zkg.meta> · Zeek ssl.log <https://docs.zeek.org/en/current/logs/ssl.html> · quic.log <https://docs.zeek.org/en/current/logs/quic.html> · dns.log <https://docs.zeek.org/en/current/logs/dns.html> · conn.log <https://docs.zeek.org/en/current/logs/conn.html> · tunnel.log <https://docs.zeek.org/en/current/logs/tunnel.html> · weird/notice <https://docs.zeek.org/en/current/logs/weird-and-notice.html> · zeek-cut <https://docs.zeek.org/en/current/tutorial/logs.html> · capture_loss <https://docs.zeek.org/en/current/logs/capture-loss-and-reporter.html> · cluster/AF_PACKET <https://docs.zeek.org/en/current/cluster-setup.html> · SumStats <https://docs.zeek.org/en/current/scripts/base/frameworks/sumstats/main.zeek.html> · SOCKS <https://docs.zeek.org/en/current/scripts/base/protocols/socks/main.zeek.html> · init-default.zeek <https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/init-default.zeek> · BitTorrent events <https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_BitTorrent.events.bif.zeek.html> · BitTorrent analyzer <https://raw.githubusercontent.com/zeek/zeek/master/src/analyzer/protocol/bittorrent/bittorrent-analyzer.pac> · Suricata JA3/JA4 keywords <https://docs.suricata.io/en/suricata-8.0.0/rules/ja-keywords.html> · Suricata EVE JSON <https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html> · Suricata DNS keywords <https://docs.suricata.io/en/suricata-8.0.0/rules/dns-keywords.html> · Suricata runmodes <https://docs.suricata.io/en/suricata-8.0.0/performance/runmodes.html> · Suricata tuning <https://docs.suricata.io/en/suricata-8.0.0/performance/tuning-considerations.html> · suricata.yaml.in <https://raw.githubusercontent.com/OISF/suricata/master/suricata.yaml.in> · app-layer registration <https://raw.githubusercontent.com/OISF/suricata/master/src/app-layer-parser.c> · Wireshark TLS fields <https://www.wireshark.org/docs/dfref/t/tls.html> · pcap-filter(7) <https://www.tcpdump.org/manpages/pcap-filter.7.html> · BEP 3 <https://www.bittorrent.org/beps/bep_0003.html> · BEP 5 <https://www.bittorrent.org/beps/bep_0005.html> · RFC 5389 <https://www.rfc-editor.org/rfc/rfc5389.txt> · RFC 9000 <https://www.rfc-editor.org/rfc/rfc9000.txt> · WireGuard <https://www.wireguard.com/protocol/> · Cloudflare Tunnel <https://developers.cloudflare.com/tunnel/configuration/> and <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/> · RITA <https://github.com/activecm/rita> and <https://github.com/activecm/rita/blob/main/docs/Configuration.md> · ntopng editions <https://www.ntop.org/guides/ntopng/versions_and_licensing.html> · ntopng flows <https://www.ntop.org/guides/ntopng/user_interface/network_interface/flows/flows.html> · ntopng REMOTE TO REMOTE <https://www.ntop.org/guides/ntopng/user_interface/shared/alerts/remediations/ntopng_flow_risks.html> · nDPI flow risks <https://www.ntop.org/guides/nDPI/flow_risks.html> · ATT&CK T1496.002 <https://attack.mitre.org/techniques/T1496/002/> · ATT&CK DET0028 <https://attack.mitre.org/detectionstrategies/DET0028> · ATT&CK T1090.003 <https://attack.mitre.org/techniques/T1090/003/> · Akamai proxyjacking <https://www.akamai.com/blog/security-research/proxyjacking-new-campaign-cybercriminal-side-hustle> · ss(8) <https://man7.org/linux/man-pages/man8/ss.8.html> · Jupyter bind <https://jupyter-notebook.readthedocs.io/en/5.5.0/public_server.html> · Jupyter security <https://jupyter-server.readthedocs.io/en/latest/operators/security.html> · Zeek websocket <https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/websocket/main.zeek>

## What I could not verify

- **A prose JA4S specification.** Only `technical_details/JA4S.png` exists; the `a_b_c` layout in §1 is my reading of `zeek/src/ja4s.cc`. Whether `JA4S_c` is meant to hash extensions in ServerHello order or sorted is **not stated in any prose doc I could reach** — the reference implementation does not sort. Treat `c` as implementation-defined.
- **JA4T/JA4L/JA4SSH algorithms.** Listed in the JA4+ index and produced by the Zeek plugin; I did not verify them. JA4L's distance maths is in the FoxIO blog (`D = jc/p`, TTL-based hop estimation) but I did not confirm it against an implementation.
- **First Suricata release with JA3.** I confirmed JA3 is in the EVE JSON TLS docs for 4.1.0 and did not check 4.0.0; the accurate claim is "present in the 4.1.0 docs", not "added in 4.1".
- **Native QUIC JA4 in Wireshark.** The Wireshark field reference lists `tls.handshake.ja4` but I found no `quic.*ja4*` field. FoxIO's tshark example does print `q…` fingerprints, suggesting the QUIC dissector reuses the TLS fields, but I could not confirm the field path and did not test on a QUIC capture.
- **Zeek BitTorrent activation.** I verified the analyzer exists as a compiled component with `bittorrent_*` events and that `base/protocols/bittorrent` has no script directory, so no log is produced today. My `Analyzer::register_for_ports(Analyzer::ANALYZER_BITTORRENT, {6881/tcp})` snippet is **not executed or documented** — it follows the generic `Analyzer::register_for_ports` API but I did not confirm it works for a binpac analyzer without a DPD signature.
- **Throughput figures.** I deliberately give none. Neither Zeek's nor Suricata's docs publish a supported pps/Gbps number for commodity hardware; any number would be invented. Read `capture_loss.log` and Suricata's `stats` drop counters instead.
- **ntopng Community capture limits.** The docs describe edition tiers by feature (graphical reports, LDAP/SSO, SNMP, ClickHouse export, nProbe) but I found no documented host-count or interface-count cap for Community.
- **Honeygain/Peer2Profit wire IOCs.** The Akamai write-up describes the campaign and its Docker/script artefacts but publishes no port or domain indicators I could turn into a filter; the §5 SOCKS filters are a protocol-level substitute, not vendor IOCs.
- **The 3.6 entropy cut-off** in §7 is my own empirical starting point (I verified the `awk` and the sample values locally), not a published threshold.
- **WireGuard's 148-byte handshake length** is arithmetic over the documented struct, not a number stated on wireguard.com.

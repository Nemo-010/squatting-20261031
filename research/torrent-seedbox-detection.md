# Torrent Seedbox Detection on a Cloud Host

Scope: a box turned into a BitTorrent seeder — `qbittorrent-nox`, `transmission-daemon`, `deluged`,
`rtorrent`, `aria2c` in BT mode — either because the account holder is farming upload credit for a private
tracker, or because something else put a client there. Covers: handshake bytes, DHT KRPC, uTP, tracker
announces, PEX, the Message-Stream-Encryption blind spot that defeats all of them, how ratio farming
differs observably from public-swarm seeding, what egress costs per free tier, and the cheapest ordered
checks an operator can run on their own host. Every number carries its source; unconfirmed items are
marked **unverified**.

## Summary

- **The peer handshake is 68 bytes**: `0x13` + `"BitTorrent protocol"` + 8 reserved + 20-byte info_hash +
  20-byte peer_id (BEP 3), and three reserved bits identify a modern client — extension `reserved[5] & 0x10`
  (BEP 10), DHT `reserved[7] & 0x01` (BEP 5), Fast Extension `reserved[7] & 0x04` (BEP 6), i.e.
  `00 00 00 00 00 10 00 05`.
- **DHT is the cheapest reliable packet signature** because bencoding sorts dict keys: every KRPC query
  starts `d1:ad2:id20:` = `64 31 3a 61 64 32`, every response `d1:rd2:id20:` = `64 31 3a 72 64 32`.
- **Default bootstrap hostnames are a DNS-side tell needing no packets**: libtorrent ships
  `dht.libtorrent.org:25401`; qBittorrent hard-codes that plus `dht.transmissionbt.com:6881` and
  `router.bt.ouinet.work:6881`.
- **All three clients are one `apt` command away on Debian trixie**: `qbittorrent-nox 5.1.0-2`,
  `transmission-daemon 4.1.0~beta2+dfsg-3+deb13u2`, `deluged 2.2.0-1`, so "not installed" is never durable.
- **qBittorrent no longer defaults to 6881**: `BitTorrent/Session/Port` defaults to `-1`, replaced by
  `rand(1024, 65535)` at startup, with a *second* random SSL port. Port-based detection fails on it.
- **MSE/PE erases every byte signature above**: each side's first flight is a 96-byte DH key plus 0–512
  bytes of padding, capped at 608 bytes. Only the *shape* survives.
- **Private vs public is visible as absence**: BEP 27 forbids DHT/PEX/LSD for `private=1` torrents, so BT
  peer traffic with zero DHT and no `ut_pex` is a private-tracker client.
- **The bill is the detector**: Oracle 10 TB/month outbound free then US$0.0085/GB; AWS 100 GB/month free;
  GCP's free `e2-micro` includes **1 GB/month** egress — ~17 minutes of upload at 1 MB/s.
- **Disk-read + one-way egress + low CPU** is the seedbox signature, distinguishing it from the miner
  (CPU-bound) and the proxy (balanced bytes, no disk).

## 1. The three daemons on the box

| | qBittorrent-nox | transmission-daemon | deluged |
|---|---|---|---|
| Debian trixie version | `5.1.0-2` | `4.1.0~beta2+dfsg-3+deb13u2` | `2.2.0-1` |
| Control port | WebUI **8080** (`WebUI/Port`) | RPC **9091** (`rpc_port`) | daemon **58846**; `deluge-web` **8112** |
| Peer port | `-1` → random 1024–65535, plus a random *SSL* port | **51413** | **6881–6891**, TLS **6892–6896** |
| Config | `~/.config/qBittorrent/qBittorrent.conf` | `~/.config/transmission-daemon/settings.json` | `~/.config/deluge/core.conf` |
| peer_id prefix | `-qB` + 4 version chars + `-` | `-TR` + 4 chars + `-` | `-DE` + 3 version chars + release char + `-` |
| User-Agent | `qBittorrent/<ver>` | `Transmission/<ver>` | `Deluge/<ver> libtorrent/<LT>` |

Sources: <https://packages.debian.org/trixie/qbittorrent-nox>, <https://packages.debian.org/trixie/transmission-daemon>,
<https://packages.debian.org/trixie/deluged>, <https://manpages.debian.org/testing/transmission-daemon/transmission-daemon.1.en.html>,
<https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md> and the
`preferences.cpp` / `sessionimpl.cpp` / `preferencesmanager.py` / `web.py` files linked in Sources.

peer_ids are generated, not folklore. libtorrent's `generate_fingerprint()` emits 8 bytes — `-`, two name
chars, four version chars (`0`–`9`, then `A`–`Z` for values ≥ 10), `-` — so qBittorrent 4.6.0 is `-qB4600-`
and 4.6.10 is `-qB46A0-` (<https://raw.githubusercontent.com/arvidn/libtorrent/master/src/fingerprint.cpp>).
Deluge calls it with `'DE'` then overwrites index 6 with a release letter, yielding `-DE200s-`; its own
docstring shows `--DE200s--`, which the code does not produce.

Structurally important: **qBittorrent moved off 6881**. `m_port` initialises to `-1` and, if still
negative at construction, becomes `Utils::Random::rand(1024, 65535)`; the SSL port is a second independent
draw (same code in `release-4.6.7`); a port list is a weak check on anything modern.

## 2. Wire fingerprints

### 2.1 The peer handshake (BEP 3)

> "The handshake starts with character ninteen (decimal) followed by the string 'BitTorrent protocol' …
> After the fixed headers come eight reserved bytes … Next comes the 20 byte sha1 hash …"
> — <https://www.bittorrent.org/beps/bep_0003.html>

byte 0 = `0x13`; 1–19 = pstr; 20–27 = reserved; 28–47 = info_hash; 48–67 = peer_id. The 20-byte prefix in
hex is `13426974546f7272656e742070726f746f636f6c`. Because TCP options shift the payload, use the
data-offset nibble:

```sh
tcpdump -ni any -c 5 'tcp[((tcp[12] & 0xf0) >> 2):4] = 0x13426974'
tcpdump -ni any -c 5 'tcp[((tcp[12] & 0xf0) >> 2):20] = 0x13426974546f7272656e742070726f746f636f6c'
```

Reserved bits, derived from the BEPs: extension `reserved[5] & 0x10`, DHT the last bit
`reserved[7] & 0x01`, Fast Extension `reserved[7] & 0x04`. All three on gives
`00 00 00 00 00 10 00 05` at offset 20 — the normal libtorrent 2.x shape, so qBittorrent and Deluge.

Two spec facts for shape analysis: `bitfield` (or Fast's Have All/None) is "only ever sent as the first
message", and requests are `2^14` = 16 KiB. A pure seeder is therefore: handshake, full bitfield, unchoke,
then ~16 KiB piece messages outward.

### 2.2 DHT KRPC (BEP 5)

DHT is UDP on the peer port (advertised by the `PORT` message, id `0x09`). Sorted dict keys make the first
bytes deterministic; using BEP 5's own example packets:

```sh
tcpdump -ni any -c 5 'udp[8:6] = 0x64313a616432'   # "d1:ad2:"  query with args dict
tcpdump -ni any -c 5 'udp[8:6] = 0x64313a726432'   # "d1:rd2:"  response
```

A response may carry an `ip` key that sorts before `r`, so not every response matches; the query signature
is the reliable half. Wireshark dissects this as `bt-dht` since 1.8.0.

### 2.3 uTP (BEP 29)

A 20-byte v1 header; libtorrent encodes `type_ver = (type << 4) | 1` with `ST_DATA=0, ST_FIN=1,
ST_STATE=2, ST_RESET=3, ST_SYN=4`, so byte 0 ∈ `01 11 21 31 41` and byte 1 = `0` with no extension
(<https://raw.githubusercontent.com/arvidn/libtorrent/master/src/utp_stream.cpp>).

```sh
tcpdump -ni any -c 5 'udp[8] = 0x41 and udp[9] = 0'    # ST_SYN v1, initiation only
```

Do **not** filter `udp[8]=0x01 and udp[9]=0`: that is byte-identical to the opening of a WireGuard
handshake initiation (`01 00 00 00`, 148 bytes).

### 2.4 Tracker announces

An HTTP announce is a `GET` whose query string is the fingerprint: `info_hash`, `peer_id`, `port`,
`uploaded`, `downloaded`, `left`, `compact`, `event` (BEP 3); qBittorrent's User-Agent is literally
`qBittorrent/<version>`. UDP trackers (BEP 15) open with magic `0x41727101980`:

```sh
tcpdump -ni any -c 5 'udp[8:8] = 0x0000041727101980'
```

Wireshark has `bt-tracker` only **from 4.2.0** (<https://www.wireshark.org/docs/dfref/b/bt-tracker.html>).

### 2.5 PEX (BEP 11) and LSD (BEP 14)

PEX is message opcode `20`, one byte of extended-message id, then a bencoded payload with `added`,
`added.f`, `dropped`. It lives inside the reassembled peer stream, so `tcpdump` byte filters miss it; its
detection value is negative evidence, since BEP 27 forbids it on private torrents. LSD is
`239.192.152.143:6771` carrying `BT-SEARCH * HTTP/1.1` — on by default in libtorrent, off in Transmission
(`lpd_enabled` false), so absence proves nothing.

### 2.6 MSE/PE — where packet filters die

Transmission defaults to `encryption: "preferred"`; qBittorrent ships a separate SSL listen port; Deluge
exposes `ssl_listen_ports`. The layer is Message Stream Encryption
(<https://github.com/transmission/transmission/blob/main/extras/encryption.txt>): the initiator sends a
768-bit DH public value `Ya` (96 bytes) plus 0–512 bytes of `PadA`, the responder replies `Yb` + `PadB`, and
its fail-fast bounds are *"if A sent less than 96 Bytes within 30 seconds"* and *"if A sent more than 608
bytes"*.

The detectable shape is therefore: **each side's first data flight is 96–608 bytes of uniform random
bytes, no recognisable prefix, on a port that is neither 80 nor 443**, followed by sustained bidirectional
transfer — a flow-statistics problem (entropy, first-flight size, port class), not a `content:` match.
Everything in §2.1–§2.5 is worth zero against a client set to "required".

## 3. Private-tracker ratio farming vs public swarms

BEP 27 is behavioural, not a wire format: *"When a BitTorrent client obtains a metainfo file containing
the 'private=1' key-value pair, it MUST ONLY announce itself to the private tracker, and MUST ONLY initiate
connections to peers returned from the private tracker."* Its rationale names the incentive: "private
trackers often maintain statistics about registered users and restrict access … for users that do not
adequately upload" (<https://www.bittorrent.org/beps/bep_0027.html>). A seedbox is a rented upload faucet
for exactly that statistic.

| | private-tracker client | public-swarm client |
|---|---|---|
| Tracker hosts | exactly one, usually HTTPS | many, often plain HTTP/UDP |
| DHT | **none** (mandatory) | constant `get_peers`/`announce_peer` |
| PEX / LSD | **none** (mandatory) | present unless disabled |
| Rights-holder notices to the provider | rare — swarm is access-controlled | common |
| Egress shape | flat, high, months-long, same peers | bursty, churns with swarm interest |

The first column is why a private seedbox is invisible to reputation: nobody external complains, so the
only signal is the metre — and why the DNS check in §5 is load-bearing.

## 4. Traffic shape and the bill

### 4.1 What normal looks like

BEP 3's choking algorithm unchokes **four** reciprocating peers plus **one** optimistic peer, rotated
every 30 s, with choke state changing once per 10 s — so a seeder serves ~5 peers even with hundreds
connected. libtorrent defaults: `connections_limit 200`, `active_limit 500`, `active_seeds 5`,
`active_dht_limit 88`, `upload_rate_limit 0` (unlimited) (<https://www.libtorrent.org/reference-Settings.html>).
Transmission defaults: `--peerlimit-global 240`, `--peerlimit-torrent 60`. Hundreds of flows is therefore
expected, not evidence.

### 4.2 Egress allowances

| Provider | Free egress | Marginal rate | Exhausted at 1 MB/s (own arithmetic) |
|---|---|---|---|
| Oracle Cloud Always Free | **10 TB/month** | "Outbound data over 10TB/month starting at US$0.0085" | ~116 days |
| AWS | **100 GB/month** | ~US$0.09/GB first 10 TB (**unverified**, see below) | ~28 hours |
| GCP free `e2-micro` | **1 GB/month** from North America | — | **~17 minutes** |

Sources: <https://www.oracle.com/cloud/networking/>, <https://aws.amazon.com/ec2/pricing/on-demand/>,
<https://cloud.google.com/free/docs/free-cloud-features>.

The GCP number explains the "free-tier seedbox" pattern: on an Oracle tenancy, 10 TB/month at 3 Mbit/s
sustained is a free seedbox indefinitely. The other document worth reading is DigitalOcean's AUP, which
forbids *"Operating open proxies, open mail relays, open recursive domain name servers, Tor exit nodes, or
other similar network services"* and *"Excessive Use of Shared System Resources"*, while **never
mentioning BitTorrent** (no occurrence of "torrent", "peer-to-peer" or "p2p" in
<https://www.digitalocean.com/legal/acceptable-use-policy>).

### 4.3 The three-way discriminator

| Pattern | CPU | Egress | Ingress | Disk read | Live disk |
|---|---|---|---|---|---|
| Cryptominer | high | low | low | none | no |
| Proxy / relay | low | high | high (balanced) | none | no |
| **Seedbox** | **low** | **high, one-way** | low | **high** | **growing** |

`/proc/<pid>/io` gives `rchar`, `wchar`, `read_bytes`, `write_bytes` per process
(<https://man7.org/linux/man-pages/man5/proc_pid_io.5.html>); cgroup v2 `io.stat` gives `rbytes`/`wbytes`
per device (<https://docs.kernel.org/admin-guide/cgroup-v2.html>).

## 5. Detection recipe — cheapest first

**1. Process table (seconds, no package).**

```sh
ps -eo pid,user,etime,args --sort=-etimes \
  | grep -E 'qbittorrent-nox|transmission-daemon|deluged|deluge-web|rtorrent|aria2c' | grep -v grep
```

*FP:* `aria2c` is a legitimate CI fetcher and only speaks BT with a `.torrent`/magnet argument — read
`args`, not the binary name.

**2. Socket table with per-socket byte counters (iproute2, already installed).** `ss -i` prints
`bytes_acked`/`bytes_received` per socket — per-connection egress with no accounting daemon
(<https://man7.org/linux/man-pages/man8/ss.8.html>).

```sh
ss -tnp state established | wc -l                       # peer fan-out
ss -tunap | grep -E ':(8080|9091|51413|58846|8112|6881|6882|6889)\b'
ss -tinp | sort -t: -k2 -n | tail -20                   # biggest flows, with byte counters
ss -s                                                   # one-line summary, no /proc parsing
```

*FP:* those ports are also Jenkins/Tomcat (8080), Prometheus pushgateway (9091), etc. Attribute by PID.

**3. Bootstrap hostnames, if a logging resolver exists.** Any client with DHT on resolves
`dht.libtorrent.org`, `dht.transmissionbt.com` or `router.bittorrent.com`:

```sh
journalctl -u unbound --since -24h | grep -cE 'dht\.libtorrent\.org|dht\.transmissionbt\.com'
```

*FP:* a box merely *running* a DHT node resolves these while transferring nothing. Absence is the
meaningful half: a private client never does.

**4. Filesystem artefacts.** Transmission writes cumulative counters straight out of
`libtransmission/stats.cc` (`uploaded_bytes`, `downloaded_bytes`, `seconds_active`, `session_count`,
`files_added`).

```sh
for f in ~/.config/qBittorrent/qBittorrent.conf ~/.config/transmission-daemon/settings.json \
         ~/.config/deluge/core.conf; do [ -e "$f" ] && echo "FOUND $f"; done
find /home /root /srv /var/lib -xdev \( -name '*.torrent' -o -name '*.fastresume' \) 2>/dev/null | head
python3 -c "import json;d=json.load(open('/root/.config/transmission-daemon/stats.json'));print(d['uploaded_bytes'],d['seconds_active'])"
grep -n 'Session' ~/.config/qBittorrent/qBittorrent.conf
```

*FP:* a `.torrent` on disk is not seeding; the client must be running, and `~/.config` may belong to a
different user. qBittorrent's key is `Session\Port` under `[BitTorrent]` in the INI.

**5. Ask the client** — the only way to separate ratio farming from a one-off download.

```sh
# qBittorrent: login needs the Referer header, returns an SID cookie
curl -s -c /tmp/qb -o /dev/null -H 'Referer: http://127.0.0.1:8080' \
     --data 'username=admin&password=adminadmin' http://127.0.0.1:8080/api/v2/auth/login
curl -s -b /tmp/qb http://127.0.0.1:8080/api/v2/transfer/info    # up_info_data, dht_nodes, connection_status
curl -s -b /tmp/qb 'http://127.0.0.1:8080/api/v2/torrents/info?filter=seeding'

# Transmission: a 409 hands you the CSRF token
SID=$(curl -s -o /dev/null -D - http://127.0.0.1:9091/transmission/rpc \
      | awk -F': ' '/X-Transmission-Session-Id/{print $2}' | tr -d '\r')
curl -s -H "X-Transmission-Session-Id: $SID" \
  -d '{"method":"torrent_get","arguments":{"fields":["name","upload_ratio","uploaded_ever","percent_done","tracker_stats"]}}' \
  http://127.0.0.1:9091/transmission/rpc
```

Sources: <https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)> (`/transfer/info`
returns `up_info_data`, `dht_nodes`, `connection_status`; its login example uses `admin`/`adminadmin`, while
≥4.6 prints a random temporary password if none is set — <https://man.archlinux.org/man/qbittorrent-nox.1.en>)
and <https://github.com/transmission/transmission/blob/main/docs/rpc-spec.md> (§2.2.1 CSRF, §3.3
`upload_ratio`).

*FP:* `dht_nodes > 0` proves DHT is running, not seeding; a high `upload_ratio` on a distro ISO looks
identical to farming here.

**6. Packet confirmation (needs `tcpdump`).**

```sh
timeout 10 tcpdump -ni any -c 5 'tcp[((tcp[12] & 0xf0) >> 2):4] = 0x13426974'
timeout 10 tcpdump -ni any -c 5 'udp[8:6] = 0x64313a616432'
timeout 10 tcpdump -ni any -c 5 'udp[8:8] = 0x0000041727101980'
timeout 10 tcpdump -ni any -c 5 'udp[8] = 0x41 and udp[9] = 0'
```

*FP:* WireGuard (§2.3) and MSE (§2.6); silence here is not exculpatory.

**7. Reassembly, only if 1–6 were inconclusive.** Wireshark's are the free parser of record —
`bittorrent` (33 fields), `bt-dht` (1.8.0+), `bt-utp` (1.6.0+), `bt-tracker` (4.2.0+)
(<https://www.wireshark.org/docs/dfref/>):

```sh
tshark -i any -Y bittorrent -T fields -e ip.dst -e bittorrent.peer_id -e bittorrent.info_hash
tshark -i any -Y bt-tracker -T fields -e bt-tracker.tracker -e bt-tracker.info_hash -e bt-tracker.event
```

**Zeek ships no BitTorrent analyser** — the log index at
<https://docs.zeek.org/en/current/script-reference/log-files.html> has no `bittorrent`/`torrent` log — so
the free path is a signature plus the existing `conn.log`:

```zeek
signature bt-peer-handshake {
  ip-proto == tcp
  payload /^\x13BitTorrent protocol/
  event "BitTorrent peer handshake"
}
```

**Suricata** likewise has no BT parser — its protocol list runs HTTP, HTTP/2, TLS, DNS, SMB… with no
BitTorrent entry (<https://docs.suricata.io/en/latest/protocols/protocols.html>) — so rules are pure
`content:` matches:

```
alert tcp any any -> any any (msg:"BitTorrent peer handshake"; \
    content:"|13|BitTorrent protocol"; depth:20; sid:1000201; rev:1;)
alert udp any any -> any any (msg:"BitTorrent DHT KRPC query"; \
    content:"|64 31 3a 61 64 32|"; depth:6; sid:1000202; rev:1;)
alert udp any any -> any any (msg:"BitTorrent UDP tracker connect"; \
    content:"|00 00 04 17 27 10 19 80|"; depth:8; sid:1000203; rev:1;)
```

**8. The provider's metre.** On a free tier this never misses — it is the bill: the console egress graph,
or `awk '/eth0:/{print $10}' /proc/net/dev` sampled into `vnstat`.

## 6. False-positive modes, named

| Mode | Why it trips | Distinguisher |
|---|---|---|
| **Official distro ISO seeding** | Ubuntu publishes `.iso.torrent` itself — <https://ubuntu.com/download/alternative-downloads> | info_hash is a published distro torrent; payload dir is the mirror's own ISO tree |
| **Package mirror** | `apt-mirror`/`debmirror`/`rsync` are HTTP/rsync, **not** BT (unless it also seeds ISOs) | `ss -tnp` shows rsync/nginx, no BT handshake |
| **CI fetching an artifact by torrent** | `aria2c` with a magnet, or a Node `webtorrent` job | short-lived, one info_hash, parent is a CI runner |
| **WireGuard vs uTP** | `udp[8]=0x01,udp[9]=0x00` matches both | uTP ST_SYN is `0x41`; WG initiation is exactly 148 bytes |
| **DHT-only participation** | `enable_dht` resolves bootstrap names and answers `ping` idle | no handshakes, no disk growth, no egress |

## Sources

- BEP 3, 5, 6, 10, 11, 14, 15, 27, 29 — <https://www.bittorrent.org/beps/bep_0003.html>,
  <https://www.bittorrent.org/beps/bep_0005.html>, <https://www.bittorrent.org/beps/bep_0006.html>,
  <https://www.bittorrent.org/beps/bep_0010.html>, <https://www.bittorrent.org/beps/bep_0011.html>,
  <https://www.bittorrent.org/beps/bep_0014.html>, <https://www.bittorrent.org/beps/bep_0015.html>,
  <https://www.bittorrent.org/beps/bep_0027.html>, <https://www.bittorrent.org/beps/bep_0029.html>
- libtorrent — <https://www.libtorrent.org/reference-Settings.html>,
  <https://raw.githubusercontent.com/arvidn/libtorrent/master/src/fingerprint.cpp>,
  <https://raw.githubusercontent.com/arvidn/libtorrent/master/src/utp_stream.cpp>
- qBittorrent — <https://raw.githubusercontent.com/qbittorrent/qBittorrent/master/src/base/bittorrent/sessionimpl.cpp>,
  <https://raw.githubusercontent.com/qbittorrent/qBittorrent/master/src/base/preferences.cpp>,
  <https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)>,
  <https://man.archlinux.org/man/qbittorrent-nox.1.en>
- Transmission — <https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md>,
  <https://github.com/transmission/transmission/blob/main/docs/Peer-ID-and-User-Agent.md>,
  <https://github.com/transmission/transmission/blob/main/extras/encryption.txt>,
  <https://github.com/transmission/transmission/blob/main/docs/rpc-spec.md>,
  <https://manpages.debian.org/testing/transmission-daemon/transmission-daemon.1.en.html>
- Deluge — <https://raw.githubusercontent.com/deluge-torrent/deluge/develop/deluge/core/preferencesmanager.py>,
  <https://raw.githubusercontent.com/deluge-torrent/deluge/develop/deluge/core/core.py>,
  <https://raw.githubusercontent.com/deluge-torrent/deluge/develop/deluge/ui/web/web.py>
- Debian — <https://packages.debian.org/trixie/qbittorrent-nox>,
  <https://packages.debian.org/trixie/transmission-daemon>, <https://packages.debian.org/trixie/deluged>
- Tooling — <https://man7.org/linux/man-pages/man8/ss.8.html>,
  <https://man7.org/linux/man-pages/man5/proc_pid_io.5.html>,
  <https://docs.kernel.org/admin-guide/cgroup-v2.html>,
  <https://www.wireshark.org/docs/dfref/>,
  <https://docs.zeek.org/en/current/frameworks/signatures.html>,
  <https://docs.suricata.io/en/latest/protocols/protocols.html>,
  <https://attack.mitre.org/techniques/T1496/002/>
- Billing / policy — <https://www.oracle.com/cloud/networking/>, <https://aws.amazon.com/ec2/pricing/on-demand/>,
  <https://cloud.google.com/free/docs/free-cloud-features>,
  <https://www.digitalocean.com/legal/acceptable-use-policy>,
  <https://ubuntu.com/download/alternative-downloads>

## What I could not verify

- **Which release stopped qBittorrent defaulting to 6881** — `m_port(..., -1)` + `rand(1024,65535)` is in
  master and `release-4.6.7`, but no changelog entry pins the change.
- **The AWS per-GB rate from a primary page** — the EC2 table is client-side rendered; "100 GB free" is in
  the served text, but `$0.09/GB` comes from secondary summaries. **Unverified** likewise: any current
  Resilio/P2P-sync protocol description for that false-positive row.
- **Whether Transmission 4.1.x still writes `stats.json`** — `stats.cc` reads it, but the loader is
  named `load_old_stats`.
- **Deluge's `--DE200s--` docstring vs the 8-byte code output** — I trust the code, not the wire.
- **Any published campaign dropping a torrent client on compromised cloud hosts** — no campaign-level
  reporting names qBittorrent/Transmission/deluged as a dropped payload; ATT&CK T1496.002 covers the class
  generically, and the documented pattern is repurposed *legitimate* accounts.

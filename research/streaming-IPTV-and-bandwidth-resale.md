# Streaming, IPTV and sold bandwidth: ffmpeg restream fan-out, 机场 subscription resale, seedbox slots, and the traffic that gives them away

> **Hardened 2026-11-01 — adversarial review: D56.** The origin counters are the only strong item and exist only when the operator's media server is the origin. A push to a CDN moves the fan-out off the host, `ffmpeg -i -` removes the URL from the command line, and variable-bitrate encoding removes the metronome.
> The corrected checks and the residual bypasses are in
> [HARDENING.md](../HARDENING.md). Read that before relying on the commands below.

This file covers the slice of server repurposing where the *product* is video or raw bytes rather than compute: a box that pulls a live feed and re-publishes it (RTMP/RTMPS, HTTP-FLV, HLS, SRT), a box that terminates hundreds of short-lived client pulls of one origin playlist (the IPTV-panel shape), a box sold as a "机场" (airport) subscription node or a seedbox slot, and a box that simply sells its uplink to a bandwidth marketplace. The common thread is that the abuse is *bandwidth-shaped*: CPU stays near idle because audio and video are remuxed with `-c copy` rather than re-encoded, disk barely moves, and the only thing that changes is a flat, unvarying egress curve plus an odd concurrency profile on a handful of ports. Everything below is written from the operator's side of the wire.

## Summary — the load-bearing findings

- The best-documented notebook-to-streaming chain is Aqua Nautilus' November 2024 report: unauthenticated JupyterLab/Notebook on 8888 → `ffmpeg` downloaded from MediaFire (MD5 `ecf054bf36972571efa68df489a9e969`) → `-i` a beIN Sports piracy source at `x9pro.xyz` → republish to `ustream.tv`; operator IP `41.200.191.23` (<https://www.aquasec.com/blog/threat-actors-hijack-misconfigured-servers-for-live-sports-streaming/>). Aqua maps the last hop to ATT&CK **T1496 Resource Hijacking** and **T1048 Exfiltration Over Alternative Protocol**.
- Aqua counted ~15,000 Jupyter servers on Shodan and ~150 (~1%) allowing RCE — the exposed population that makes this shape recurrent rather than a one-off.
- The toolkit leaves a free, greppable fingerprint: libavformat's default HTTP header is literally `User-Agent: Lavf/<libavformat version>` (`DEFAULT_USER_AGENT "Lavf/" AV_STRINGIFY(LIBAVFORMAT_VERSION)`, <https://raw.githubusercontent.com/FFmpeg/FFmpeg/master/libavformat/http.c> lines 192, 1804–1805). A local FFmpeg n9.0.2 / libavformat 63.1.102 build emits `Lavf/63.1.102`.
- RTMP defaults are compile-time constants: `RTMP_DEFAULT_PORT 1935`, `RTMPS_DEFAULT_PORT 443` (<https://raw.githubusercontent.com/FFmpeg/FFmpeg/master/libavformat/rtmp.h> lines 27–28). Publishers announce `FMLE/3.0 (compatible; Lavf/…)`; players a platform string (`libavformat/rtmpproto.c`, ~line 2897).
- The fan-out ratio (egress ÷ ingress on one path) is the single most diagnostic number for IPTV resale, and mainstream servers expose it: MediaMTX publishes `paths_inbound_bytes`, `paths_outbound_bytes` and `paths_readers{readerType=…}` (<https://mediamtx.org/docs/features/metrics>).
- MediaMTX's default listeners are a ready-made port checklist (full table in §2): RTMP 1935, RTMPS 1936, RTSP 8554, HLS 8888, WebRTC 8889/UDP 8189, SRT 8890, API 9997, metrics 9998, pprof 9999 (<https://mediamtx.org/docs/references/configuration-file>). Any of these listening on a box that is not a media server is the finding.
- HLS is *poll-shaped*, not stream-shaped: with FFmpeg's default `hls_time 2` / `hls_list_size 5` (verified locally via `ffmpeg -h muxer=hls`), one viewer issues ~60 HTTP requests/minute and never holds a socket open — `ss` is blind to it and log cadence is mandatory.
- Retail prices explain the arbitrage: a documented 机场 tier is ¥15/month for 100 GB = ¥0.15/GB, ¥0.12/GB at the 1000 GB tier (<https://mofajc.com/longmaoyun-review/>). Honeygain pays 10,000 credits = $10 with a $20 floor (<https://www.honeygain.com/honeygain-payout>); third-party reviews put accrual at 3 credits per 10 MB, ≈$0.30/GB — an order of magnitude above datacenter bandwidth, because the *residential ASN* is the product.
- Oracle's Always Free AMD micro is capped at "up to 50 Mbps network bandwidth via the internet" (<https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm>) = 16.2 TB/month flat, enough for ~8 concurrent 6 Mbit/s 1080p viewers. Free tiers are economically worth stealing.
- A Europol-coordinated Bulgarian action against five cable operators (17 June 2019) documented the classic single-origin IPTV topology: 60+ premium channels to **more than 700,000 subscribers**, hardware seized (<https://www.europol.europa.eu/media-press/newsroom/news/end-of-broadcast-for-iptv-criminal-network>). At that scale the origin is not a hidden process — it is a saturated NIC.

## 1. The documented notebook → restream chain, and what it leaves behind

Aqua Nautilus' honeypots caught a benign binary doing hostile work. The sequence, as published (<https://www.aquasec.com/blog/threat-actors-hijack-misconfigured-servers-for-live-sports-streaming/>; corroborated by <https://thehackernews.com/2024/11/hackers-hijack-unsecured-jupyter.html>):

1. Initial access to a token-less JupyterLab/Notebook reachable at `http://<ip>:8888/tree?`, which gives interactive code execution with no auth.
2. The attacker updates the box and downloads `ffmpeg` (MD5 `ecf054bf36972571efa68df489a9e969`) from MediaFire rather than a distro repo. VirusTotal returns it as clean — the payload is a *legitimate media tool used as a proxy component*, which is why it was never classified as an attack.
3. `ffmpeg` runs with `-i` pointed at an external piracy source (`x9pro.xyz`) and the output at `ustream.tv`, with flags "to control the streaming speed and minimize detection" — in FFmpeg terms `-re` (read input at native frame rate, <https://ffmpeg.org/ffmpeg.html>) plus a copy-mode codec so the box does almost no work.
4. The feed was UEFA Champions League (Shakhtar Donetsk vs BSC Young Boys, 6 Nov 2024) and beIN Sports content; the actor address was `41.200.191.23`.

Two properties matter for detection. First, `-c copy` means **CPU is not the signal** — a hijacked restreamer is a near-idle process with a saturated uplink, so any stack keyed on CPU, load average or miner-style thermal behaviour will miss it. Second, the box is simultaneously a *client* of a piracy origin and a *server* to an ingest point, so the flow pair is asymmetric in reputation: inbound from a no-name domain, outbound to a platform ingest.

### The fingerprints, precisely

```bash
# Cheapest possible: full command lines of any process carrying an RTMP/SRT/HLS sink
grep -aH . /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' ' ' | \
  grep -aE 'rtmp://|rtmps://|srt://|udp://.*\?pkt_size|-f[[:space:]]+flv|-f[[:space:]]+hls'
```

The default HTTP user agent is set in source, not config (`libavformat/http.c`):
```c
/* http.c:192 */
#define DEFAULT_USER_AGENT "Lavf/" AV_STRINGIFY(LIBAVFORMAT_VERSION)
/* http.c:200 — overridable */
{ "user_agent", "override User-Agent header", ... { .str = DEFAULT_USER_AGENT }, ... }
/* http.c:1804-1805 — emitted only if the caller did not set one */
if (!has_header(s->headers, "\r\nUser-Agent: "))
    av_bprintf(&request, "User-Agent: %s\r\n", s->user_agent);
```

So in any plain-HTTP access log, `Lavf/` in the UA field is an FFmpeg-family client; the same holds for `ffmpeg -user_agent "…"`, which exists precisely because that header is otherwise a tell. `-user_agent` does not exist for RTMP (RTMP is not HTTP), which is why RTMP pushes must be found at the connection layer instead.

## 2. The toolchain's port and protocol surface

| Protocol | Default port | Source |
|---|---|---|
| RTMP | 1935/tcp | `RTMP_DEFAULT_PORT` <https://raw.githubusercontent.com/FFmpeg/FFmpeg/master/libavformat/rtmp.h> |
| RTMPS | 443/tcp | `RTMPS_DEFAULT_PORT`, same file |
| RTMPS (MediaMTX listener) | 1936/tcp | <https://mediamtx.org/docs/references/configuration-file> |
| RTSP | 8554/tcp | same |
| RTP / RTCP | 8000, 8001/udp | same |
| HLS | 8888/tcp | same |
| WebRTC (HTTP signalling) | 8889/tcp, UDP 8189 | same |
| SRT | 8890/udp | same |
| Control API / metrics / pprof | 9997, 9998, 9999 | same |
| RTMP stats endpoint (nginx-rtmp example) | 8080/tcp | <https://raw.githubusercontent.com/arut/nginx-rtmp-module/master/README.md> |

nginx-rtmp's own configuration shows the restream idiom that hijacked hosts reproduce by hand — an `exec` hook that re-publishes a stream through FFmpeg:

```nginx
application live {
    live on;
    exec ffmpeg -re -i rtmp://localhost:1935/$app/$name -vcodec flv -acodec copy -s 32x32
                -f flv rtmp://localhost:1935/small/${name};
}
```

and a stats endpoint that makes simultaneity countable without touching the kernel:

```nginx
server {
    listen 8080;
    location /stat { rtmp_stat all; rtmp_stat_stylesheet stat.xsl; }
    location /stat.xsl { root /path/to/stat.xsl/; }
}
```

The XML behind `/stat` exposes, per application and per stream, `nclients`, `bytes_in`, `bytes_out`, `bw_in`, `bw_out` (element names confirmed in `stat.xsl`, <https://raw.githubusercontent.com/arut/nginx-rtmp-module/master/stat.xsl>). The units of `bw_in`/`bw_out` are unverified here.

## 3. Three business models, three traffic shapes

### 3.1 IPTV / restream fan-out — one origin, N pulls

Shape: **1:N**. Ingress is one steady flow at source bitrate; egress is that same bytes/sec multiplied by concurrent viewers, and the two diverge monotonically as the audience grows. The Europol case (700,000 subscribers, 60+ channels, 17 June 2019, <https://www.europol.europa.eu/media-press/newsroom/news/end-of-broadcast-for-iptv-criminal-network>) is the top of the range; the same shape exists at 20 viewers on a stolen VPS.

Arithmetic an operator can apply to their own box (assumption labelled):

- A 6 Mbit/s 1080p H.264 stream (typical figure, **not sourced here**) is 0.75 MB/s = 2.7 GB/hour = 64.8 GB/day ≈ 1.9 TB/30 days, **per viewer**.
- Oracle's 50 Mbps Always Free cap is 6.25 MB/s = 16.2 TB/30 days, so roughly **8 concurrent such viewers** saturate a free tier.
- Any host whose 30-day egress is measured in TB while CPU sits under a few percent is a CDN edge (not yours), a backup target (nightly window), or a restreamer.

The distinguishing statistic is the **fan-out ratio** `egress_bytes / ingress_bytes` measured on the streaming path only. For a legal relay it is ≈1 (a rebroadcast to one ingest). For a reseller it equals the audience. MediaMTX hands this over directly:

```bash
curl -s http://127.0.0.1:9998/metrics | grep -E 'paths_(readers|inbound_bytes|outbound_bytes)'
# paths_readers{name="cam1",state="ready",readerType="hls"} 37
# paths_inbound_bytes{name="cam1",state="ready"} 4.1e+09
# paths_outbound_bytes{name="cam1",state="ready"} 1.1e+11   -> fan-out ~27
```

### 3.2 机场 / airport subscription nodes — many tiny flows, sold by the GB

The Chinese "airport" market sells access to a fleet of proxy nodes by monthly traffic quota: a documented example is ¥15/month for 100 GB (¥0.15/GB), ¥0.12/GB at the 1000 GB tier (<https://mofajc.com/longmaoyun-review/>). The shape is the *inverse* of IPTV: hundreds of short-lived TLS flows per node, low per-flow bitrate, no sustained 1:N fan-out, egress ≈ ingress. What it shares is quota consumption — a node that pushed 1 TB in a month on a plan costing less than that bandwidth is shared beyond its terms or resold. The streaming-specific variant is "unlock" traffic: a node advertised as unblocking a catalogue necessarily egresses to that catalogue's ASNs from a datacenter IP the catalogue would normally refuse — a per-destination question answerable from flow logs alone.

### 3.3 Seedbox slots and bandwidth-as-a-product

A seedbox reseller buys one dedicated box and sells N slices, each with its own rTorrent/Transmission/qBittorrent instance and port. Shape: **upload-dominant**, many peers per instance, per-peer rates of tens to hundreds of kbit/s, long-lived connections idling for hours between bursts. Unlike a restream there is no fixed bitrate and no single peer holding 90% of the bytes; unlike a proxy the peers are thousands of distinct IPs on ephemeral ports.

Bandwidth marketplaces (Honeygain and peers) are the purest form: the host installs an agent whose only job is to make the box a residential exit. Shape: **many short TLS connections to a small set of coordinating endpoints**, low duty cycle, high connection *count*, small per-connection byte totals, and a process tree with no reason to exist on a server. The economics explain it: 10,000 credits = $10 with a $20 payout floor (<https://www.honeygain.com/honeygain-payout>), and third-party reviews put accrual at 3 credits per 10 MB (<https://www.frugalforless.com/honeygain-review/>) — ≈$0.30/GB, about 15× the ¥0.15/GB (≈$0.021/GB) retail for datacenter proxy bandwidth in the 机场 market. Residential ASN space, not throughput, is what is being bought.

## 4. Counting simultaneity

"Simultaneous viewers" is not one measurement; it differs per protocol, and getting it wrong yields the two classic errors — counting sockets where there are none, or counting requests where one client opens many.

- **RTMP / RTMPS / SRT**: a viewer holds one long-lived TCP (or UDP) association. Count distinct `(peer_ip, local_port)` pairs. Server-side, the local port is the service port, so `sport = :1935` is the right filter.
- **HTTP-FLV**: one long-lived HTTP GET, `Content-Type: video/x-flv` (FFmpeg's flv muxer reports mime type `video/x-flv`; `ffmpeg -h muxer=flv`). Byte counters accumulate on a single socket, so a viewer looks like a stalled download that never ends — count sockets whose age exceeds several minutes with continuously growing `bytes_sent`.
- **HLS**: no persistent socket at all. Approximate concurrency as the number of **distinct peer IPs fetching any segment or playlist of the same path within a sliding window of 2× `#EXT-X-TARGETDURATION`** (RFC 8216 §4.3.3.1, <https://www.rfc-editor.org/rfc/rfc8216>). FFmpeg's default segment length is 2 s (`hls_time`, verified locally), MediaMTX's low-latency default is 1 s segments with 200 ms parts (`hlsSegmentDuration: 1s`, `hlsPartDuration: 200ms`, <https://mediamtx.org/docs/references/configuration-file>) — the smaller the part, the more requests per viewer per minute, which is itself a detectable cadence.
- **LL-HLS**: parts multiply request counts by roughly `segment/part`, so the same audience generates ~5× the request rate of classic HLS; thresholds tuned on classic HLS fire falsely here.

## 5. Detection recipe — cheapest first

Run these on the box itself, cheapest and least-assuming first.

**Step 0 — interface byte counters, no packages, 1 minute.**
```bash
a=$(awk '/eth0/{print $10}' /proc/net/dev); sleep 60; b=$(awk '/eth0/{print $10}' /proc/net/dev)
echo "egress Mbit/s: $(( (b-a)*8/60/1000000 ))"
```
`/proc/net/dev` column 10 is transmit bytes and exists on any kernel with procfs; sysfs (`/sys/class/net/*/statistics`) carries the same data when mounted. **False positives:** apt-cacher duties, off-site backups, container image pulls, NFS servers. The discriminator is *flatness*: streaming egress has very low per-second variance (a `-re`-paced feed is a metronome), while backups and mirrors are bursty.

**Step 1 — per-socket bytes and rate, iproute2 only.**
```bash
ss -Htn state established '( sport = :1935 or sport = :1936 or sport = :8888 or sport = :8889 or sport = :8554 or sport = :8890 )'
ss -tin state established '( sport = :1935 )' | grep -oE 'bytes_(sent|received):[0-9]+|delivery_rate [0-9a-z]+'
```
`-i` documents `bytes_acked` and `bytes_received` per socket (<https://man7.org/linux/man-pages/man8/ss.8.html>, lines ~199–202); the filter expression and `or` chaining were verified by running them (iproute2-7.3.0). **False positives:** a self-hosted media server, OBS pushing to your own nginx-rtmp, camera/NVR bridges on 8554. Check the *peer*, not the port.

**Step 2 — process command lines (finds the pusher, not what it pulls from).**
```bash
grep -aH . /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' ' ' | grep -aE 'rtmp://|srt://|-re -i|f flv'
```
**False positives:** Jupyter users doing legitimate video work (exactly the ambiguity Aqua describes), CI transcode jobs, `ffmpeg` thumbnailers. Corroborate with parentage: `ffmpeg` under a notebook kernel or an interactive shell with an external peer is the pattern; `ffmpeg` under `systemd` with a local input file is not.

**Step 3 — listener inventory.**
```bash
ss -tulpn 2>/dev/null | grep -E ':(1935|1936|8554|8888|8889|8890|9997|9998|9999|8000|8001)\b'
```
**False positives:** dev servers parked on 8080/8888 (Jupyter *and* HLS both like 8888), Prometheus exporters on 9998. Port alone is weak; port plus a non-owner process is strong.

**Step 4 — application counters (best signal-to-effort ratio if a media server exists).**

```bash
curl -s http://127.0.0.1:8080/stat | python3 -c "
import sys,xml.etree.ElementTree as ET
for s in ET.fromstring(sys.stdin.read()).iter('stream'):
    print(s.findtext('name'), 'clients=', s.findtext('nclients'), 'in=', s.findtext('bytes_in'), 'out=', s.findtext('bytes_out'))"
```
Same idea for MediaMTX via `:9998/metrics` as shown in §3.1. **False positives:** the counters are per-path and per-application; a path named `small` from an `exec` transcode loop will show as an extra stream — that is a configuration artefact, not evidence.

**Step 5 — request-pattern analysis from the web server log (the only way to see HLS).**
```bash
awk '{print $1, $7}' /var/log/nginx/access.log \
 | grep -E '\.m3u8|\.ts(\?|$)|\.m4s(\?|$)' \
 | awk '{print $1}' | sort | uniq -c | sort -rn | head
```
A single IP issuing ≥50 `.ts` requests in the last minute against one path is a viewer; forty IPs doing it against one path is an audience. **False positives:** crawlers (few requests, no cadence), your own health checks, and mobile clients that refetch the playlist once after a network switch.

**Step 6 — kernel path, for history or per-destination attribution.** `conntrack -L -p tcp --dport 1935` needs the `conntrack` package *and* a loaded `nf_conntrack`; neither was present in the sandbox used for this file, so treat it as "needs a package plus a module". `nft` counters work but writing them changes firewall state — read-only alternative: `nft list ruleset` to see whether a byte counter is already installed.

## 6. What separates "expensive" from "abusive" without guessing

Three ratios do most of the work, and none needs an agent, a module, or a privileged operation: **fan-out** (`out/in` on one path; ≈1 for a relay, ≈N for a reseller), **flatness** (variance of per-second egress; near zero for a `-re`-paced feed, high for anything legitimate), and **cost coverage** (a 机场 node pushing 1 TB/month on a ¥15 plan is shared beyond its terms or resold — <https://mofajc.com/longmaoyun-review/>).

## Sources

- Aqua Nautilus, "Threat Actors Hijack Misconfigured Servers for Live Sports Streaming" (19 Nov 2024): <https://www.aquasec.com/blog/threat-actors-hijack-misconfigured-servers-for-live-sports-streaming/>
- The Hacker News, "Hackers Hijack Unsecured Jupyter Notebooks to Stream Illegal Sports Broadcasts": <https://thehackernews.com/2024/11/hackers-hijack-unsecured-jupyter.html>
- FFmpeg `libavformat/http.c`: <https://raw.githubusercontent.com/FFmpeg/FFmpeg/master/libavformat/http.c>
- FFmpeg `libavformat/rtmp.h`: <https://raw.githubusercontent.com/FFmpeg/FFmpeg/master/libavformat/rtmp.h>
- FFmpeg `libavformat/rtmpproto.c`: <https://raw.githubusercontent.com/FFmpeg/FFmpeg/master/libavformat/rtmpproto.c>
- FFmpeg CLI options (`-re`): <https://ffmpeg.org/ffmpeg.html>
- MediaMTX configuration reference: <https://mediamtx.org/docs/references/configuration-file>
- MediaMTX metrics: <https://mediamtx.org/docs/features/metrics>
- nginx-rtmp-module README: <https://raw.githubusercontent.com/arut/nginx-rtmp-module/master/README.md>
- nginx-rtmp-module `stat.xsl`: <https://raw.githubusercontent.com/arut/nginx-rtmp-module/master/stat.xsl>
- Europol, "End of Broadcast for IPTV criminal network" (17 Jun 2019): <https://www.europol.europa.eu/media-press/newsroom/news/end-of-broadcast-for-iptv-criminal-network>
- 机场 pricing review (龙猫云, ¥15/100GB): <https://mofajc.com/longmaoyun-review/>
- Honeygain payout mechanics: <https://www.honeygain.com/honeygain-payout>
- Third-party Honeygain rate (3 credits / 10 MB): <https://www.frugalforless.com/honeygain-review/>
- Oracle Cloud Always Free resources (50 Mbps cap): <https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm>
- RFC 8216 (HTTP Live Streaming), §4.3.3.1 `EXT-X-TARGETDURATION`: <https://www.rfc-editor.org/rfc/rfc8216>
- `ss(8)` man page: <https://man7.org/linux/man-pages/man8/ss.8.html>
- ATT&CK T1496 Resource Hijacking: <https://attack.mitre.org/techniques/T1496/>; T1048 Exfiltration Over Alternative Protocol: <https://attack.mitre.org/techniques/T1048/>

## What I could not verify

- **The exact FFmpeg command line** used in the Aqua case. The report quotes the source (`x9pro.xyz`) and destination (`ustream.tv`) and says flags controlled stream speed, but does not publish the argv. `-re` is the only FFmpeg flag that matches "control the streaming speed"; it is an inference.
- **nginx-rtmp `bw_in` / `bw_out` units** (bits/s vs kbit/s). `stat.xsl` shows the fields exist; no primary doc states the unit.
- **Oracle's 10 TB/month outbound allowance.** Widely repeated, but I could not find it on the two Oracle pages I fetched; the verified number is the 50 Mbps per-micro-instance cap.
- **The credit-per-megabyte rate on Honeygain's own site.** The 3 credits/10 MB figure comes from a third-party review; only 10,000 credits = $10 and the $20 payout floor are vendor-confirmed. The derived ≈$0.30/GB inherits that caveat.
- **Seedbox slot pricing and per-slot bandwidth allocations.** No primary vendor page fetched; section 3.3 is therefore qualitative.
- **Whether any specific 机场 vendor resells an Always Free tenancy.** The pricing and quota facts are documented; the linkage to a free tier is stated only as an economic possibility.
- **Executable verification of live listeners.** Binding sockets and mounting `/sys` were unavailable in this sandbox, so the `ss` filters were verified against existing connections (exit 0, empty match) rather than a live RTMP listener.

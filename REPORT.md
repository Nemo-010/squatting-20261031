# Squatting a server

**What gets run on other people's cloud hosts, why it survives, and how to catch it on one box with no budget.**

This is the consolidated technical report. The `research/` directory holds sixteen deep dives with full
command sets, source URLs and "what I could not verify" sections; `checks/` holds runnable scripts that
implement the cheapest tiers. Everything here is derived from vendor documentation, kernel source,
RFCs, man pages and published threat intelligence. Provider terms are quoted as facts where they
constrain what is technically possible, without commentary.

Read this as an operator's document. The interesting question is not "what malware is on the box" —
a squatted host usually has no malware in any signature sense — but "why is this machine emitting
traffic, and who is being served".

---

## 1. The three businesses that share one footprint

A squatted server looks the same regardless of motive: an outbound connection, a small process, and an
egress graph that slopes upward. What differs is who profits.

### 1.1 Proxyjacking — the host is sold as an exit IP

A broker binary or container dials **out**, registers the host, and relays third-party TCP through its
address. Nothing listens publicly. MITRE formalised the technique as **T1496.002, Resource Hijacking:
Bandwidth Hijacking**, with detection strategy DET0028 whose analytics call out "sustained outbound
traffic … potentially linked to scanning or proxyjacking. Includes curl, wget, masscan, or proxy
clients" and, for virtual instances, "sustained outbound data rates, often to TOR, VPN, or proxy
endpoints".

The unit economics explain the persistence. Sysdig measured Pawns.app paying **$9.60/month for one IP
running 24 h**, so "a modest compromise of 100 IPs will net a passive income of nearly $1,000 per
month", against ~23,000 internet-reachable Log4j hosts implying **>$220,000/month** at the time.
Silent Push's 2026 crawl enumerated **117,224 unique IPs** across the resale pools it mapped —
60,247 residential, 38,762 datacenter, 18,215 mobile — at **$0.28/GB residential paid out against
$7.60/GB resold**, with hosting IPs worth **$0.10/GB**.

Datacenter IPs are the cheapest tier and the one major networks increasingly refuse, which is why the
same actors prefer compromised edge devices. A 2026 GreyNoise campaign put **143+ devices in 34
countries** on Pawns.app via CVE-2024-3272/3273, CVE-2021-44228 and CVE-2025-31324. But much cloud
squatting is not for resale at all: it is one person in a filtered region buying an unmetered egress
pipe.

**Families:** IPRoyal Pawns (`hezb.x86_64`), Peer2Profit, ProxyLite.ru, Honeygain, EarnFM, Repocket,
Traffmonetizer, Weave. **Carriers:** Mimo/Mimo'lette, P2PInfect, TeamTNT's Docker Gatling Gun,
Kinsing, LABRAT, TrafficStealer, EMERALDWHALE. TeamPCP (2025–26) moved the same business into
Kubernetes with a **privileged DaemonSet mounting the host filesystem**.

### 1.2 The self-service relay — one binary, one outbound flow

This is the population that matters for a server operator. A proxy server bound to loopback plus a
tool that publishes it through a third party, so **no inbound port is ever opened**.

| layer | tools | observable signature |
|---|---|---|
| proxy core | Xray-core, v2ray, sing-box, hysteria2, tuic, naiveproxy, shadowsocks-rust | outbound TLS/QUIC, usually 443 to a CDN |
| publish | cloudflared (Argo), ngrok, frp, rathole, chisel, gost, tmate | one long-lived flow to a fixed relay |
| transport | VLESS/REALITY, VMess+WS, Trojan, XHTTP, Hysteria2, TUIC | indistinguishable from HTTPS at packet level |
| clients | v2rayN, Clash/mihomo, NekoBox, Shadowrocket | — |
| orchestration | one-click shell installers, subscription aggregators | `curl … \| bash`, systemd unit, cron |

The Chinese-language ecosystem is the largest open instance. `zizifn/edgetunnel` has **9,300 stars
and 52,109 forks**; `cmliu/edgetunnel` shows **48,702 stars / 38,584 forks** and was pushed
2026-10-08. That fork-to-star ratio is not contribution, it is "fork, deploy, forget".
`fscarmen/ArgoX` advertises 12 protocols and "one command on any Linux VPS" with no domain or
certificate; `mack-a/v2ray-agent` (22,257 stars) is the VPS form.

The Cloudflare Workers branch is bounded by documented limits: Workers Free is **100,000 requests/day
resetting at midnight UTC, 10 ms CPU per request, 128 MB memory, 50 subrequests, 6 simultaneous open
connections, 100 Workers per account**, and hitting the cap returns Error 1027. A Worker also cannot
dial Cloudflare's own ranges over TCP, which is why these projects need an external `PROXYIP`.
Cloudflare now answers some deployments with "Cloudflare received a Network abuse regarding:
&lt;name&gt;.workers.dev" (issue #1853, opened 2026-10-30).

**What an installed instance actually leaves on disk.** Two of the most-used installers are consistent
enough to be worth memorising:

- `233boy/Xray` installs to `/etc/xray/` with the binary at `/etc/xray/bin/xray` and a *shell wrapper*
  at `/usr/local/bin/xray` — so a `strings` hit on the wrapper is not a hit on the binary.
- `mack-a/v2ray-agent` installs to `/etc/v2ray-agent/` with per-inbound numbered config fragments:
  `02_VLESS_TCP_inbounds.json`, `02_trojan_TCP_inbounds.json`, `03_VLESS_WS_inbounds.json`,
  `06_hysteria2_inbounds.json`, `07_VLESS_vision_reality_inbounds.json`, `09_tuic_inbounds.json`, plus
  `00_socks5_base.json` and `09_routing.json`. It writes both `xray.service` and `sing-box.service`.

A `find / -name '*_inbounds.json'` is therefore a faster tell than any process scan.

### 1.3 Bandwidth as inventory — torrents, restreams, subscriptions

Three variants of "sell the pipe":

- **Ratio farming.** qBittorrent-nox / transmission-daemon / deluged on a 1–10 Gbit host; sustained
  near-line-rate egress, hundreds of short peer flows, trivial CPU, monotonically growing storage.
  Defaults are as much the attack surface as the bandwidth: Transmission's
  `rpc_authentication_required` is **false** with `rpc_bind_address` `0.0.0.0`, Deluge's web UI
  password is literally `deluge`, qBittorrent's WebUI reference config is user `admin` (the API
  examples use `adminadmin`) on `:8080`, and **CVE-2023-30801** (default creds → RCE via the
  external-program feature, CVSS 9.8) was reported exploited in the wild in March 2023.
- **Restreaming.** Documented in notebook intrusions: an unauthenticated JupyterLab on `:8888` used to
  run `ffmpeg` against a source and publish to `ustream.tv` (Aqua, Nov 2024, actor IP
  `41.200.191.23`). Not mining, not a proxy — bandwidth theft with a fan-out of paying viewers.
  `ffmpeg` identifies itself as `User-Agent: Lavf/<version>` unless told otherwise, and RTMP
  publishers announce as `FMLE/3.0 (compatible; Lavf/…)`.
- **Subscription resale.** The "airport" (机场) market prices data around **¥0.15/GB** at the 100 GB
  tier, against Honeygain's third-party payout near **$0.30/GB** and datacenter egress at fractions of
  a cent — a spread that pays for a lot of stolen IP addresses.

### 1.4 Adjacent roles a borrowed box gets drafted into

Not every squat is a proxy. The same access is reused for:

- **Reflectors.** Open DNS resolvers and NTP/memcached/CLDAP/SSDP/CharGen responders used for
  amplification. Published factors (CISA TA14-017A, from Rossow's measurement work): DNS **28–54×**,
  SSDP **30.8×**, CLDAP **56–70×**, CharGen **358.8×**, NTP **556.9×**, memcached **10,000–51,000×**.
  memcached UDP has been off by default since **1.5.6**.
- **Open relays.** SMTP, HTTP and SOCKS proxies that someone else's spam or scraping runs through.
  Shadowserver counted **68,000 open HTTP proxies** in 2023.
- **Tor exit.** A relay that makes every abuse complaint about the host land on the host's owner,
  regardless of who sent the traffic.
- **Build farms.** CI runners as free compute: GitHub's hosted runners are unmetered for bandwidth,
  and the only policing is AUP §9 "Excessive Bandwidth Use" plus the Actions terms' "disproportionate
  burden" clause.
- **Remote desktops.** RDP/VNC/xrdp/Guacamole sessions on a "free VPS" obtained for the purpose.
- **Overlay/mesh nodes.** Tailscale, NetBird, ZeroTier, Nebula, tinc, Yggdrasil, cjdns and iroh
  running on a borrowed host as a relay or exit for someone else's mesh — see
  [research/overlay-mesh-networks.md](research/overlay-mesh-networks.md) and `checks/overlay-nets.sh`.
  The useful asymmetry: a server that grows any new TUN interface, or opens long-lived flows to a
  vendor's coordination endpoints, is a lead even when every binary is renamed.

### 1.5 The free-tier inventory, and why each one is chosen

Free tiers are attacked for three different properties: raw compute, a high-reputation egress IP, and
an interactive runtime a relay can live in. The published numbers are the whole argument.

| platform | free allowance | why it gets used | enforcement |
|---|---|---|---|
| Oracle Cloud Always Free | 2× `VM.Standard.E2.1.Micro` (1/8 OCPU, 1 GB, up to 50 Mbps) + 1,500 OCPU-h / 9,000 GB-h A1 (≡2 OCPU / 12 GB); **10 TB/month** egress | the largest free egress pipe published | idle reclamation: 95th-pct CPU <20 %, network <20 %, memory <20 % (A1) over 7 days |
| Google Colab | ~12 h runtime | notebook relay, torrent, miner | account-level runtime block |
| Google Cloud Shell | ephemeral Compute Engine VM, 5 GB persistent `$HOME`, **50 h/week** default quota, `$HOME` deleted after 120 days unused | a real VM with a real IP, no card | quota, not policy |
| GitHub Codespaces | Free: **120 core-hours/month**, 15 GB-month storage | build or relay inside a repo context | entitlement only |
| Hugging Face Spaces | CPU Basic 2 vCPU / 16 GB | high-reputation egress; a Gradio app as a proxy front | ports **80/443/8080 only**; moderation string `trojan proxy on :7860` |
| Kaggle | notebook VMs with GPU quota | compute-heavy jobs | AUP bans "server farming" and "circumvention/obfuscation" |
| Serv00 | shared hosting with `binexec` | VLESS/WS on a shell account | ToS bans proxy/VPN/tunnel; sweep 2–6 April 2025 |
| Koyeb | 1 free service, 512 MB / 0.1 vCPU | small relay | payment method required since Dec 2022 after an abuse surge |
| Render | 750 free instance-hours per workspace per month | small relay | spin-down after 15 min idle; suspension on exhaustion |
| Cloudflare Workers | 100,000 requests/day | VLESS server at the edge | Error 1027; abuse reports |
| Fly.io | — | removed | free tier ended 7 Oct 2024 |
| Glitch | — | removed | app hosting shut 8 Jul 2025 |

Two conclusions follow. First, most "detection" offered by these platforms is an entitlement check or
a per-account block, not traffic analysis. Second, the platforms that *removed* the free tier (Fly.io,
Glitch) did so rather than police it — the same trade an operator faces.

### 1.6 The panel economy behind the subscriptions

Individual relay scripts are the visible layer; behind them is a business software stack. Repository
scale, checked 2026-10-31: `v2board/v2board` 5,066 stars (last push 2024-03-19), `cedar2025/Xboard`
4,833 stars and pushed 2026-10-29 as a "high-performance panel based on V2board secondary
development", `subconverter` 17,110 stars, `Sub-Store` 10,802 stars. The node agents that talk to these
panels have a short life: `XrayR-project/XrayR` carries the description **"项目已废弃"** (deprecated) at
2,820 stars, and `V2bX` is archived.

The panels are an attack surface in their own right, and one that has been exercised: **CVE-2026-37504**
in V2Board ≤1.7.4 leaked the node authentication token because `UniProxyController` read it from a
query parameter, exposing it to access logs, `Referer` headers and CDN caches — enough to impersonate
a node and sit in the traffic path.

---

## 2. Jupyter is the instrument of choice

A Jupyter server *is* a remote-execution service with an HTTP front end, and it says so. The project's
own operator docs describe `/api/kernels` as "Connect to kernel websockets, send/recv kernel messages.
**This generally means arbitrary code execution, and should usually be considered equivalent to having
all other permissions**." A kernel is `python -m ipykernel_launcher -f {connection_file}`; `!cmd` runs
in a subshell. If the token leaks, or auth is off, there is nothing to exploit.

Exposure, measured repeatedly: ~10,000 internet-visible notebooks in April 2022 with 70 reachable
unauthenticated (Aqua); **~15,000 Jupyter servers online with ~150 (~1 %) enabling remote code
execution** by November 2024.

Documented chains, all entering through the notebook:

| campaign | entry | payload | persistence |
|---|---|---|---|
| Qubitstrike (Cado 2023) | bash terminal over the UI | base64 → `curl \| bash`, XMRig as `python-dev` in `/usr/share/.LQvKibDTq4` | 4 cron files, SSH key, `sshd_config` rewrite |
| Wiz summer '23 | open notebook | `tmate` renamed `python`, PRoot, udocker, ngrok with a hard-coded token | GitHub-hosted `run.sh` |
| Sobolan (Aqua 2025) | unauth JupyterLab | 13 files in `/var/tmp/.lol11/.ICE-Temp`, `chattr +i` on the directory | cron `* * * * *`, `@reboot` |
| Koske (Aqua 2025) | unauth JupyterLab, `123456` | polyglot JPEG, `LD_PRELOAD` rootkit hiding via `readdir()` | systemd unit, `.bashrc`, 30-min cron |
| ffmpeg restream (Aqua 2024) | unauth JupyterLab `:8888` | `ffmpeg` from MediaFire, `x9pro.xyz` → `ustream.tv` | none needed |
| Cado MSI/ELF (2025) | exposed notebook | ChaCha20-encrypted blob from GitHub/Gitee, 9 coins | cron at 10/20/30/40 min |

What they leave behind is the useful part: `~/.local/share/jupyter/runtime/kernel-<id>.json` (five ZMQ
ports and the HMAC key), `jpserver-<pid>.json` (the token), `~/.ipython/profile_default/history.sqlite`
(`sessions`/`history`/`output_history` — every executed cell), and `.ipynb` files whose `outputs`
retain recon stdout and base64 blobs.

Free notebook services are chosen deliberately, and every provider has written it down. Colab's FAQ
bans "connecting to remote proxies", "downloading torrents or engaging in peer-to-peer file-sharing",
"mining cryptocurrency" and — free tier only — "remote control such as SSH shells, remote desktops";
free notebooks cap at **12 hours**. Kaggle's AUP (22 June 2025) bans "server farming", "tools for
circumvention/obfuscation" and "activity unrelated to ML data science". Hugging Face's content policy
(10 April 2025) names "Using tools like Cloudflare Tunnel, TOR, proxies, VNC, Chrome Remote Server,
etc., to bypass restrictions", allows only ports 80/443/8080, and its moderation string is literally
`Flagged as abusive, reason trojan proxy on :7860`. Serv00 bans "Proxy software", "VPN", "Tunneling
software", "Random binaries names" in ToS §7 and ran a sweep on **2–6 April 2025** with the ban text
`ToS violation: VPN/ proxy/tunnel`.

---

## 3. Why it is not detected

The honest answer: it *is* detected, late, by accounting and complaints rather than by security
tooling. Understanding why the security tooling fails is what tells you where to spend effort.

### 3.1 The network is clean for the tunnel family specifically

Not for every family — an open SOCKS server on 1080, an RDP server on 3389, a torrent peer port and an
SMTP relay all listen, and all are trivially found by a scan. The point is that the *fastest-growing*
family, the CDN-published relay, is invisible to scanning, for six reasons:

1. **No listening socket.** Cloudflare's own docs say the connector "creates outbound-only
   connections" and note that "most firewalls allow outbound traffic by default". Exposure scanners,
   port scans and attack-surface dashboards see nothing. `cloudflared` never *listens* on 7844 — it
   dials it (TCP for http2, UDP for quic).
2. **The destination is a first-party CDN.** `region1/region2.v2.argotunnel.com`, SNI `cftunnel.com`
   and friends, valid certificates, Cloudflare's own address space. There is no bad IP to block.
3. **One flow, many streams.** A single multiplexed TLS session carries every logical stream, so
   flow-level anomaly detection sees one boring persistent connection.
4. **Padding and randomisation are design goals.** XHTTP adds `?x_padding=` of **100–1000** random
   bytes per request and `X-Padding` of **100–1000** on responses, randomises post intervals (default
   30 ms, recommended as a range), varies `hMaxRequestTimes` 600–900 and `hMaxReusableSecs` 1800–3000
   per side, and can split upload and download across different transports, IP families or SNIs.
   REALITY borrows a third-party site's handshake and **forwards unauthenticated probes to that
   site**, so active probing gets a valid answer. NaiveProxy pads to match HTTP/2 CONNECT.
5. **The bytes are small.** Sysdig: "1 GB of network traffic spread out over a month is tens of
   megabytes per day — very likely to go unnoticed", against cryptomining's conspicuous CPU spike.
6. **The binary is legitimate.** `docker pull fazalfarhan01/peer2profit` (>10M pulls) or an official
   `cloudflared` release. Akamai's observation is exact: "the files that are actually used … are
   legitimate and will not be detected by anti-malware solutions."

### 3.2 The layers that would catch it are blind by construction

- **Socket-owner matching** — `iptables -m owner` and `nft meta skuid` — "is only valid in the OUTPUT
  and POSTROUTING chains. Forwarded packets do not have any socket associated with them."
- **`meta cgroup`** reads the cgroup **v1** net_cls classid (`NFT_META_CGROUP` is `#ifdef
  CONFIG_CGROUP_NET_CLASSID` around `sock_cgroup_classid()`), and cgroup v2 has no net_cls
  controller, so it matches zero on a modern host.
- **Container namespaces** are invisible to host `ss`, and a container with its own netns is the
  default deployment.
- **Provider-side NAT** hides the internal source; what the provider sees is interface bytes.

### 3.3 And the box itself can be made to lie

The most dangerous case for a *single-server* operator is not an undetected squat, it is a squat that
has compromised the tool you would use to find it.

`/etc/ld.so.preload` is honoured even in secure-execution mode (which strips env `LD_PRELOAD`), and
loading a library that hooks `fopen`/`readdir`/`open` is enough to filter `/proc/net/tcp`. This is not
hypothetical:

- **P2PInfect** sets `LD_PRELOAD=/home/<user>/.lib/libs.so.1` and filters its own ports **60100–60150**
  out of `/proc/net/tcp` and `tcp6`.
- **Kinsing**'s `libsystem.so` hooks **18** symbols, hides the literals `kinsing`, `kdevtmpfsi`,
  `libsystem.so`, and returns **`EPERM`** for those literals while returning `ENOENT` for everything
  else — a `stat` that fails `EPERM` on a random path is the fingerprint.
- **Diamorphine** (LKM) hooks `getdents`, `getdents64` and `kill`, with `SIGINVIS=31`,
  `SIGMODINVIS=63`, `SIGSUPER=64`.
- **beurk** hooks **libpcap**, which means `tcpdump` output is not trustworthy on a compromised host.

`netstat` reads `/proc/net/tcp` directly (net-tools removed its netlink support), so it is trivially
hooked. `ss` is better: it uses `NETLINK_SOCK_DIAG` with `SOCK_DIAG_BY_FAMILY` and falls back to procfs
only when netlink fails or when `PROC_NET_TCP` / `PROC_ROOT` is set. That gives a same-binary,
two-datasource diff — but note the variable takes a **path**, not a flag:

```sh
ss -Htan | wc -l                                # netlink view
PROC_NET_TCP=/proc/net/tcp ss -Htan | wc -l     # procfs view
```

`PROC_NET_TCP=1` opens a file literally named `1`, prints a header and zero rows, and produces a
guaranteed false "disagreement" — the easiest way to get this wrong.

`ss -p` still resolves owners through `opendir("/proc")` and `readlink("/proc/PID/fd/N")`, so process
attribution is hookable even when the socket list is not.

The counter-technique is **cross-view validation**: any two independent sources that disagree is the
finding. `/proc/net/*` versus netlink versus a raw `AF_PACKET` capture versus an eBPF probe fed from
kernel tracepoints. A raw `AF_PACKET` socket sits below the libc and libpcap layers that beurk hooks,
which makes it a good tiebreaker — but the strongest evidence is a **kernel-side counter** (the
cgroup-eBPF byte/packet map behind `IPAccounting=`, or conntrack's per-flow counters), because no
userland library can edit those. If `IPEgressBytes` says the unit moved a gigabyte and `ss` shows
nothing, believe the counter.

### 3.4 What actually catches them: money, and a complaint

Provider-side, detection is dominated by volume and abuse reports. The published allowances make the
arbitrage legible: AWS includes 100 GB/month egress, DigitalOcean bills **$0.01/GiB** past plan
allowance, Hetzner includes 20 TB (EU) with **€1.00/TB** overage, Oracle Always Free includes
**10 TB/month** then **US$0.0085/GB**, and GCP's free `e2-micro` includes only **1 GB/month** of North
America egress — about seventeen minutes at 1 MB/s.

Oracle is the one provider with an explicit anti-idle clause, and it reads as a detection rule: it
deems an instance idle if, over 7 days, 95th-percentile CPU is **<20 %**, network utilisation
**<20 %**, and (A1 only) memory **<20 %**.

The consequence: a squatter's business model is churn, and an operator's advantage is making the
account expensive to replace. **Detection you cannot act on is theatre.**

### 3.5 And the censor is a detector the squatter actually fears

The sections above answer "why the cloud provider does not notice". There is a second detector in the
path, and it explains much of the protocol design: the Chinese filtering system.

The state of the art is measured in *How the Great Firewall of China Detects and Blocks Fully Encrypted
Traffic* (USENIX Security 2023). Per that work the classifier was deployed in early November 2021 and
decides on the **first TCP payload** from a small feature set: a protocol fingerprint (Shadowsocks,
VMess, Obfs4), the fraction of set bits, and the number, fraction, position and longest run of printable
ASCII characters; its probes are about 50 random bytes. The same work reports roughly **0.6 %** of
ordinary connections blocked as collateral, and probabilistic blocking of a large share (about 26 %) of
connections to popular datacenter ranges. Those figures are the paper's measurements, not mine.

Two operational consequences:

- **Why the protocols look the way they do.** REALITY exists to make the handshake byte-identical to a
  real site; XHTTP exists to make the HTTP layer look like a browser's; uTLS exists to stop the Go
  ClientHello from sticking out. Those defences are aimed at *this* classifier, and they double as
  anti-detection against an operator's flow heuristics — which is why a naive JA3 rule loses.
- **What you will see if you are the relay.** Active probing from addresses you cannot resolve, and
  requests to paths you never published. A REALITY server forwards unauthenticated probes to its
  target, so your logs show it proxying to a third-party site — that traffic is neither yours nor
  theirs.

---

## 4. Detection, cheapest first

Full detail and sources in `research/`. Runnable forms in `checks/`.

### Tier 0 — ten minutes, nothing installed

Base `procps` + `iproute2` + `coreutils`. This is a triage aid, not a detector. The binary path is
harder to fake than the process name, but it is not identity either: `pip install --user` puts a
payload in a directory this snippet does not list, and `python3 -c` has no payload image at all.
`checks/triage.sh` is the hardened version of this tier and reports the processes it could not read.

```sh
# images under staging paths, plus interpreters running inline code
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case $exe in
    */tmp/*|*/var/tmp/*|*/dev/shm/*|*/run/*|*/home/*/.cache/*|*"(deleted)"*|/memfd:*)
      printf '%-7s %-50s %s\n' "$pid" "$exe" "$(tr '\0' ' ' < "$p/cmdline")" ;;
  esac
  case ${exe##*/} in
    python*|node|perl|ruby|php*|java)
      tr '\0' '\n' < "$p/cmdline" | grep -qxE -- '-c|-e|-m|--eval|-jar' &&
        printf '%-7s inline code through %s: %s\n' "$pid" "${exe##*/}" "$(tr '\0' ' ' < "$p/cmdline")" ;;
  esac
done

ss -Htnp state established '( dport = :7844 or sport = :7844 )'   # one vendor's edge, not the family
ss -Hunp                                                           # QUIC, uTP, WireGuard, DHT
cat /etc/ld.so.preload 2>/dev/null                                 # any content is a finding

find / -name '*_inbounds.json' 2>/dev/null                         # one-click installer layout
for n in /proc/[0-9]*/ns/net; do readlink "$n"; done | sort -u     # distinct netns
```

Three signals to act on:

- an established session to `*.argotunnel.com` / `:7844` from a host with no declared tunnel;
- `comm` of `[kworker/0:1]` **while** `/proc/<pid>/exe` resolves — kernel threads have no user address
  space, so that combination is always a lie;
- a `readdir("/proc")` that returns fewer numeric entries than `/proc/<pid>` directories that `stat`
  can reach. (Measured false-positive mode: this also happens benignly, so treat it as a prompt to
  switch to netlink, not as proof.)

The third one is a name check, and a name is not identity: the same process can be called `sshd` and
nothing on the host will disagree. Read the first two as leads and the process image plus its package
owner as the finding.

`/proc/<pid>/exe` is not *unforgeable* — `prctl(PR_SET_MM_EXE_FILE)` repoints it, and a `memfd`
payload shows as `/memfd:name (deleted)`. But repointing needs `CAP_SYS_RESOURCE`, so where tenants are
unprivileged it is still the best single identifier. When it looks wrong, compare `/proc/<pid>/maps`,
`ldd` output and the on-disk inode.

### Tier 1 — accounting (the tier that pays)

**Per service, systemd** (235+, Linux 4.11 cgroup-eBPF):

```sh
systemctl show nginx.service -p IPIngressBytes -p IPIngressPackets -p IPEgressBytes -p IPEgressPackets
```

Three limits to design around, all verified: it is **not recursive** across slices — a slice does not
aggregate its children, so summing both double-counts; it is **unavailable for per-user managers**
("currently only available for system services, not for per-user services"), so a rootless JupyterHub
gets nothing; and it **structurally undercounts TCP** because it sums `skb->len` before GSO — open
issue #34775, where a 10 KB upload reports `IPEgressBytes=11001`, and nftables counters undercount the
same way because no netfilter hook runs late enough to see the split.

**Per UID, nftables** — works for per-user managers and survives a renamed binary:

```
table inet acct {
    set suids { type uid; flags dynamic; }
    chain out { type filter hook output priority 0; policy accept;
        update @suids { meta skuid counter } }
    chain forwarded { type filter hook forward priority 0; policy accept;
        update @oifaces { meta oifname counter } }
}
```

`meta skuid` needs a socket in *this* netns, so a container's traffic never matches; forwarded traffic
has no UID at all, which is why the forward chain counts per interface instead. UID 0 is one bucket and
is not evidence of anything.

**Per flow, conntrack** — enable first, it is off by default (`net.netfilter.nf_conntrack_acct=1`),
then `conntrack -L -o extended`. Use it to see *which peer* and *how much*. Do **not** read asymmetry as
a tunnel signal: a reply-heavy flow is a download, and a relay is often roughly balanced.

**Per interface, vnstat** — the canary that keeps months of history without capturing. Point it at
*every* interface, not one chosen by hand: `vnstat --alert output exit type d condition above limit
25 GiB` on `eth0` says nothing about a tunnel over `tun0`. macvlan/ipvlan/SR-IOV traffic does not cross
the host counters at all.

**Per unit and whole host, `checks/egress-watch.sh`** — samples services, scopes and slices, warns when
a counter resets, and compares the sum of unit deltas against the host interface counter so bytes no
unit accounts for are a finding on their own.

**Per connection, `ss -tin`** — the zero-package way to see `bytes_sent`, `bytes_acked`,
`bytes_received` and `delivery_rate` for a live socket.

### Tier 2 — auditd, when you want the record

One file, `/etc/audit/rules.d/50-proxyjack.rules`, then `augenrules --load`. The load-bearing rules:

```
-a always,exit -F ar -S socket -F a0=2  -k net_socket
-a always,exit -F ar -S connect,bind -F saddr_fam=2  -k net_conn
-a always,exit -F ar -S sendto,sendmsg -F saddr_fam=2  -k udp_conn
-a always,exit -F ar -S ioctl -F a1=0x400454ca -k tun_ioctl
-a always,exit -F ar -S clone -F a0&0x40000000 -k ns_net
-a always,exit -F ar -S setns -F a1&0x40000000 -k ns_net
-a always,exit -F ar -S execveat -k execveat
-a always,exit -F ar -S memfd_create -k memfd
-a always,exit -F ar -F dir=/etc/systemd/system -F perm=wa -k persist
-a always,io_uring -S connect,sendmsg,openat,openat2 -k uring_net
```

`checks/50-proxyjack.rules` is the full set. Four traps, each of which silently costs you the whole
ruleset:

- **The field is `arch`, not `ar`.** `-F ar` is not a field at all — libaudit returns "`-F missing
  operation for ar`", `augenrules` aborts, and because the abort happens after the leading `-D` you are
  left with no rules; if `-e 2` has already been applied, you cannot change it until reboot. Check with
  `auditctl -l` after every load.
- **`-F path=` on a directory is not recursive** and needs the inode to exist at load time, which is
  why `-w /etc/ld.so.preload` silently fails on a clean host. Use `-F dir=/etc/cron.d -F perm=wa`.
- **`saddr_fam` is populated only for bind/connect/sendto**, and for `sendmsg` only when the message
  carries an address. That is why `sendto,sendmsg` is in the ruleset and a connected `sendmsg` still is
  not: the data plane needs a probe or the egress counter.
- **The io_uring filter resolves `-S` against a fixed opcode table in audit userspace.** An opcode that
  is not in that table aborts the whole load, and `SOCKET`/`SEND`/`RECV` are `audit_skip` in the kernel
  and can never be audited. Name only `connect,sendmsg,openat,openat2`.
### Tier 3 — eBPF, when accounting is not enough

`kprobe:tcp_connect` is the single best probe, and it is upstream's own `tools/tcpconnect.bt`:

```sh
sudo bpftrace -e 'kprobe:tcp_connect { $sk=(struct sock*)arg0;
  if ($sk->__sk_common.skc_family==2)
    printf("%-16s %-6d %s:%d -> %s:%d\n", comm, pid,
      ntop($sk->__sk_common.skc_rcv_saddr), $sk->__sk_common.skc_num,
      ntop($sk->__sk_common.skc_daddr), bswap($sk->__sk_common.skc_dport)); }'
```

Use the kprobe (populated `struct sock`), not the syscall tracepoint. `checks/probes.bt` is the hardened
set: it adds `execveat` (how a memfd payload actually runs), `clone3` with the namespace flags read out
of `struct clone_args`, `io_uring_setup`, and `udp_sendmsg` so QUIC/hysteria2 are not invisible.

A per-`comm` connect-vs-accept ratio is a shape heuristic, not a proof: a SOCKS relay is a server, a
loopback health endpoint supplies an accept, and the name is free. Do not build a control on it. `bcc
tcplife` traces socket state changes, not packets, so a connection that was already established when the
tool started has no event until it closes; `ss -tin` is the zero-package per-socket byte view. Tetragon
(kernel ≥4.19) adds in-kernel filtering and `Sigkill` at a measured **1.68 %** for exec tracing, **2.46 %**
with JSON output, **5.88 %** worst-case connection-rate loss — write both a TCP and a UDP policy, and
monitor that the daemon is still alive, because `systemctl stop tetragon` is the bypass.

### Tier 4 — flow signatures

Constants are cheap and precise:

```
# BitTorrent peer handshake at payload offset 0, any port
tcp[((tcp[12] & 0xf0) >> 2):4] = 0x13426974
# DHT KRPC query / response  ('d1:ad2:id20:' / 'd1:rd2:id20:')
udp[8:6] = 0x64313a616432
udp[8:6] = 0x64313a726432
# UDP tracker protocol magic
udp[8:8] = 0x0000041727101980
# uTP SYN (type_ver = (type<<4)|1). NOT 0x01 - that matches WireGuard
udp[8] = 0x41
# SOCKS5 CONNECT
tcp[((tcp[12] & 0xf0) >> 2):4] = 0x05010001
# XMRig stratum login ({"id":1,"jsonrpc":"2.0","method":"login")
tcp[((tcp[12] & 0xf0) >> 2):4] = 0x7b226964
```

Four caveats that decide whether these fire at all:

- modern qBittorrent picks a **random** listen port in 1024–65535 per instance, so port-based detection
  is dead;
- MSE/PE `required` replaces the 68-byte handshake with a 96–608-byte random first flight, which
  defeats the handshake signature — but `preferred` still accepts plaintext, and private trackers
  commonly leave it that way, so the signature still catches a large share;
- **Suricata does ship a BitTorrent DHT parser** (`bittorrent-dht` app-layer, with
  `app-layer-event:bittorrent-dht.malformed_packet`); **Zeek ships none**; Wireshark covers `bt-dht`
  (1.8.0+), `bt-utp` (1.6.0+) and `bt-tracker` (4.2.0+);
- for DNS tunnelling (`dnstt`, `iodine`) there is no fixed constant: the signal is label entropy,
  TXT/NULL record volume and per-domain query rate. The corpus is thinner here and says so.

For TLS, JA4 is a better hash than JA3, but it is a *library* fingerprint, not an intent one. uTLS
reproduces Chrome closely enough that a client either looks exactly like Chrome or looks random each
time; REALITY forwards unauthenticated probes to a real site, so the fingerprint and its server
counterpart both match the borrowed site. Do not build a policy on a JA3/JA4 deny-list. The only
residue is an allow-list of fingerprints expected on a given host, which is an inventory problem.

### Tier 5 — external vantage

You can see your own box the way the Electrosphere does, for free:

```sh
curl -s "https://check.torproject.org/api/ip"                 # {"IsTor":false,"IP":"..."}
curl -s "https://onionoo.torproject.org/details?search=<ip>"  # authoritative relay lookup
curl -s "https://internetdb.shodan.io/<ip>"                   # ports, hostnames, tags, vulns
curl -s "https://crt.sh/?q=<domain>&output=json"              # CT: hostnames pointing at you
curl -s "https://api.mnemonic.no/pdns/v3/<ip>?limit=5"        # passive DNS: who points here
```

Reference numbers measured on 2026-10-31: Tor has **2,893 Exit-flagged relays** collapsing to **1,225
unique exit addresses** across 62 countries and 235 ASNs; `torbulkexitlist` is **1,225** IPv4 lines.
`exitlist.torproject.org` now returns NXDOMAIN at zone level, so the old DNS interface is gone; the
remaining paths are Onionoo and `check.torproject.org`. Onionoo's `exit_addresses` covers only the last
24 hours, so a decommissioned exit lingers a day.

Blocklist mechanics matter because misreading them produces false alarms: Spamhaus DQS replies with a
positive A record in 127.0.0.0/16 (`127.0.0.2` SBL, `.3` CSS, `.4` XBL, `.9` DROP) and **all of
127.255.255.0/24 is an error code, not a listing** — querying through a public resolver gives you
`127.255.255.254` almost always. XBL is the list a proxyjacked box lands on: it explicitly covers
"'Free VPN' type applications using the customer device as a proxy". AbuseIPDB's free tier is 1,000
checks/day and its score is a logarithm of distinct reporters with daily decay.

### Tier 6 — catching the entry, not the workload

Cheap and underused: make the box a worse target than the next one.

- **`endlessh`** (Debian trixie, `endlessh 1.1-5.1`): port 2222, 10-second delays, `MaxLineLength 32`,
  `MaxClients 4096`. Holds scanners open indefinitely for almost no cost, and logs every attempt.
- **Cowrie** (pip, Python 3.11+, not in Debian): full SSH/Telnet emulation with `cowrie.json` events —
  `cowrie.session.connect`, `cowrie.login.failed`, `cowrie.command.input`,
  `cowrie.session.file_download`. Built-in output plugins for Telegram, Slack, Discord, AbuseIPDB,
  MISP, Prometheus.
- **Canarytokens** (free): web bug and DNS tokens fire on *any* access or resolution, no agent needed.
  They are defeated by blocking the token domain at the resolver or in `/etc/hosts`, so they catch an
explorer, not a payload that never resolves an unknown name.
- **Fake credentials and files**: an `~/.aws/credentials` that is never used, a `~/.ssh/id_rsa` that is
  watched. `chattr +i` is a **write** tripwire only — "it cannot be deleted or renamed … and the file
  can not be opened in write mode". For reads, `atime` is unreliable but not useless: under the default
  `relatime`, "the file's last access time is always updated if it is more than 1 day old", so a single
  access to a cold canary moves the timestamp while a stream of accesses does not. Use auditd or
  inotify when you need every access.
- **`systemd.path`** with `PathExists=`/`DirectoryNotEmpty=` needs no packages, but the defaults are a
trap: `TriggerLimitIntervalSec`/`TriggerLimitBurst` (defaults **2 s / 200**, systemd 250) put the unit
into a failed state after the burst and it stops watching. Set both to 0 and monitor
`systemctl --failed`, or the tripwire is a liability. Dotfiles are ignored by path monitoring, and
`PathExists=` fires on a transition, not on a read — a canary that is read needs inotify or auditd.

### Tier 7 — notebooks and containers specifically

- Meter at spawn: each single-user server as a systemd scope/unit with `IPAccounting=yes`, or
  `c.SystemdSpawner.unit_extra_properties`.
- Enforce at spawn: `socket cgroupv2 level 2 "system.slice/jupyter-<user>-singleuser.service"` in nft.
  Sockets do **not** migrate between cgroups, so retrofitting is useless for the tunnel already open.
- Attribute after: `history.sqlite`, `runtime/jpserver-*.json` permissions, and
  `grep -rlE 'socks|peer2profit|xmrig|stratum' --include='*.ipynb'`.
- Do not use `SocketBindDeny=any` — kernels must bind five loopback ZMQ ports.
- Kubernetes: `nodes/proxy` permission is equivalent to exec on every container on the node and does
  **not** appear in API audit logs; kubelet has no audit log at all, only `-v=3` httplog. Watch
  `kubelet_http_requests_total{path,server_type}` and `kubelet_websocket_streaming_requests_total`.
  And check whether your kubelet took the legacy flag path — `applyLegacyDefaults()` forces
  `anonymous=true`, `AlwaysAllow` and `--read-only-port=10255`, while the config-file path defaults to
  `anonymous: false`, `Webhook`, `readOnlyPort: 0`.

---

## 5. The controls that beat the detection

No layer above can distinguish a padded TLS tunnel from a legitimate HTTPS client on the wire. The
controls that work remove the capability rather than describing it.

**Default-deny egress per unit.** This turns a squat into a broken service:

```ini
# /etc/systemd/system/-.slice.d/egress.conf   <- note: this applies to the whole host
[Slice]
IPAddressDeny=any

# per unit, allow only what it needs
[Service]
IPAddressAllow=192.0.2.10
```

Placing `IPAddressDeny=any` on `-.slice` is a **host-wide kill switch**: the lists are "implicitly
combined with any lists configured for any of the parent slice units", so every service inherits the
deny and only allow-listed ones can talk. Stage it — one slice first, confirm, then move up the tree.
On a notebook host this breaks pip and DNS unless a resolver is allow-listed, and allowing the
resolver gives the tunnel back: a resolver recurses to any authoritative server, so `dnstt`/`iodine`
satisfy the policy without ever contacting a denied address. If the notebook needs DNS, run a local
resolver that only forwards the names the tenant is allowed to resolve; do not allow the recursive
resolver itself.

**A rate ceiling rather than a hard block**, for a tenant that legitimately needs some bandwidth:

```
socket cgroupv2 level 2 "system.slice/jupyter-alice-singleuser.service" \
    limit rate over 2 mbytes/second drop
```

**Keep the capability away.** `CAP_NET_ADMIN` (bit 12 of `CapEff`) is required for TUN creation; do not
grant it to tenants, do not expose `/dev/net/tun` into containers, and record `CapEff` at spawn so you
can tell later whether a process ever had the ability.

**Close the SSH side door**, the cheapest control against `ssh -R`, `tmate` and Chisel:

```
AllowTcpForwarding no
PermitOpen none
GatewayPorts no
PermitTunnel no
X11Forwarding no
```

If a user genuinely needs one forwarded port, replace the blanket `no` with `PermitOpen host:port` and
keep `GatewayPorts no`, which is what stops a remote forward from binding publicly.

---

## 6. What is not worth buying

- **Attack-surface scanners** — the CDN-tunnel family listens on nothing.
- **Geo-IP blocking and CDN IP blocklists** — the exit path is a legitimate CDN in the same country as
  your legitimate traffic.
- **JA3 deny-lists** — trivially parroted; and `tcpdump` is not ground truth on a compromised host
  (beurk hooks libpcap).
- **An on-host IDS appliance** — you pay for packets you cannot decrypt on a padded, multiplexed TLS
  tunnel.
- **Perfect attribution of a forwarded packet** — the kernel does not have it to give you. Account at
  the UID/cgroup/namespace boundary and accept the boundary.

---

## 7. If you find one: order of operations

The instinct to `kill -9` first destroys most of the evidence — the socket disappears, `/proc/<pid>/exe`
resolves to nothing, and the memory is gone. Capture, then contain, then clean:

1. **Record the sockets first**: `ss -tanp`, `ss -uanp`, and `conntrack -L -o extended` if accounting is
   on. These are the only view of peers that vanishes on teardown.
2. **Freeze, do not kill**: `kill -STOP <pid>` stops the traffic while keeping `/proc` readable, and
   gives you time to copy `/proc/<pid>/{cmdline,environ,maps,status,fd/}`.
3. **Copy the binary**: `cp /proc/<pid>/exe /root/evidence-<pid>` — that works on a deleted file.
4. **Snapshot the persistence surfaces** before editing them: `/etc/cron.d`, `/var/spool/cron`,
   `/etc/systemd/system`, `~/.config/systemd/user`, `/etc/rc.local`, `authorized_keys`,
   `/etc/ld.so.preload` and everything it names.
5. **Then contain**: stop and disable the unit, or drop egress for that uid/cgroup. Killing the network
   path first is what stops the egress while you work.
6. **Then clean** — and prefer rebuild over cleaning a host that had a kernel-level or preload rootkit.
   If `/etc/ld.so.preload` was non-empty or a module was loaded, treat userland tooling as untrusted
   from that point on.
7. **Notify the provider's abuse desk** with timestamps and the peers you recorded, since the traffic
   was attributed to their address, and check whether the IP landed on a blocklist while you worked.

That last step matters practically: an exit IP on XBL keeps costing the operator long after the process
is gone, and delisting requires showing the remediation.

---

## 8. Limits of this document

Every layer here measures bytes and processes. None measures intent: a single encrypted flow to a
reputable CDN on 443 is simultaneously an ordinary HTTPS client and a working proxy. What holds up is
**correlation** — an egress trend that does not match the unit's declared purpose, plus a binary that
lives somewhere writable, plus a listener inventory that disagrees with itself. Even that combination
is legitimate for a private seedbox, a self-hosted CI runner or a real remote desktop; those are the
known limitations in `HARDENING.md`, not detections.

The censor-side figures in §3.5 are the published measurements of the cited paper, not my own
reproduction. Blocklist, exit-node and pricing figures were measured on 2026-10-31 and will drift. DNS
tunnelling and Windows-side detection are the thinnest parts of the corpus.

`HARDENING.md` records the adversarial review of every detection family above, including the eight that
cannot be separated from legitimate use (TLS fingerprint, connect/accept shape, process name, private
seedbox, self-hosted runner, valid RDP logon, provider billing, and the censor-side classifier). Those
are not gaps to be closed with more host tooling.

On a host you control, the cheapest reliable outcome is default-deny egress plus per-unit accounting.
The cheapest reliable *signal* is the one an operator notices without any tooling: traffic that keeps
flowing while nothing is being served.

---

## Appendix — the sixteen deep dives

| file | slice |
|---|---|
| [ebpf-runtime-detection-single-host.md](research/ebpf-runtime-detection-single-host.md) | bpftrace / bcc / Tetragon / Tracee probes and their overhead |
| [auditd-proc-detection.md](research/auditd-proc-detection.md) | auditd rule file, `/proc` forensics, alerting without a SIEM |
| [per-user-network-accounting.md](research/per-user-network-accounting.md) | nft counters, systemd `IPAccounting=`, conntrack, vnstat and what each cannot see |
| [network-flow-heuristics-proxyjacking.md](research/network-flow-heuristics-proxyjacking.md) | JA3/JA4, BitTorrent/SOCKS/DHT/QUIC filters, Zeek and Suricata at line rate |
| [proxy-tunnel-host-artifacts.md](research/proxy-tunnel-host-artifacts.md) | process, port and IoC tables for every proxy/tunnel family |
| [rootkits-that-hide-the-squat.md](research/rootkits-that-hide-the-squat.md) | preload rootkits, netlink-vs-proc cross-checks, `unhide`/`rkhunter` |
| [jupyter-multitenant-detection.md](research/jupyter-multitenant-detection.md) | notebook runtime artifacts, per-tenant metering and enforcement |
| [torrent-seedbox-detection.md](research/torrent-seedbox-detection.md) | handshake hex, DHT/uTP/tracker fingerprints, ratio farming vs public swarms |
| [tor-exit-relays-and-IP-reputation.md](research/tor-exit-relays-and-IP-reputation.md) | Tor exit lists, Onionoo, Spamhaus, AbuseIPDB, RDAP, persistence of listings |
| [open-relays-amplification-reflectors.md](research/open-relays-amplification-reflectors.md) | SMTP/HTTP/SOCKS relays, DNS/NTP/memcached/CLDAP amplification, detection |
| [ci-runners-and-build-farms.md](research/ci-runners-and-build-farms.md) | GitHub/GitLab runners as free compute and bandwidth, runner detection |
| [kubernetes-and-container-squatting.md](research/kubernetes-and-container-squatting.md) | kubelet/Docker exposure, malicious images, per-pod cgroup accounting |
| [windows-rdp-vnc-and-remote-desktop-abuse.md](research/windows-rdp-vnc-and-remote-desktop-abuse.md) | RDP/xrdp/VNC/Guacamole exposure and logon telemetry |
| [streaming-IPTV-and-bandwidth-resale.md](research/streaming-IPTV-and-bandwidth-resale.md) | ffmpeg/RTMP/HLS restreaming, fan-out ratios, subscription economics |
| [external-vantage-and-honeypots.md](research/external-vantage-and-honeypots.md) | Shodan/Censys/CT/passive DNS, endlessh, Cowrie, canarytokens, systemd.path |
| [overlay-mesh-networks.md](research/overlay-mesh-networks.md) | Tailscale/Headscale, NetBird, ZeroTier, Nebula, tinc, n2n, Yggdrasil, cjdns, iroh; TUN device, coordination endpoints, mesh-written firewall rules |
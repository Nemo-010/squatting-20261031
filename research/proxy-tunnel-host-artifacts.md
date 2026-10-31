# Host-artifact detection for proxy / tunnel / torrent software on a single Linux server

*Slice: what a root shell and `/proc` can tell you about proxyjacking, tunnel squatting and notebook abuse — process identity, socket tables, container namespaces, config-file sweeps and vendor-published IoCs. Zero-cost tooling only.*

---

## Summary

- **The binary path is the only unspoofable identity.** `comm` (16 bytes, writable via `prctl(PR_SET_NAME)`), `argv[0]` (`exec -a`) and `cmdline` are all attacker-controlled; `/proc/<pid>/exe` is not — except when the payload is a `memfd` (kernel ≥ 3.17), where it reads `/memfd:name (deleted)`.
- **Renamed Go binaries still rat themselves out.** `cloudflared`, `xray`, `sing-box`, `hysteria`, `frp`, `chisel`, `gost`, `ngrok`, `rathole` are Go/Rust builds; `go version -m` and `strings` recover module paths and version strings from a stripped, renamed copy.
- **cloudflared never listens on 7844 — it dials out to it** (TCP for `http2`, UDP for `quic`). Grepping listening sockets for "argo" finds nothing; you must query *established* sockets and DNS (`*.argotunnel.com`).
- **A small port signature table separates the families**: 7000/7500 (frps), 2333 (rathole), 8080 (chisel/gost/qBittorrent WebUI), 3128/1080 (3proxy), 1080 (microsocks/dante/v2ray sample), 9091/51413 (transmission), 8112/58846 (deluge), 4040 (ngrok agent API), 20241-20245 (cloudflared metrics).
- **`ss` is blind across network namespaces.** A container with its own netns is invisible to host `ss`; only `--network host` containers and host processes appear. Enumerate netns inodes under `/proc/*/ns/net` and `nsenter` in.
- **`ss -p` attribution needs root (or matching UID)**: readlink of `/proc/<pid>/fd` is gated by a ptrace access-mode check, and a non-root `ss -tulpn` in this sandbox printed no process column at all.
- **Docker is the delivery vehicle of choice**: Sysdig documents Peer2Profit/Honeygain images with >10M pulls; Akamai's campaign deployed them via SSH, killed rival containers, and named the working dir `_postfixd_`.
- **Vendor IoCs are thin but greppable**: Sysdig MD5s `6927833415c4879728707574c0849bfc` (`/tmp/p32`), `f10861ea968770effbd61cda573b6ff8` (`/tmp/b`, `/tmp/c`); Akamai SHA256 `6f1ac1e711e662edad32713c135ce29562d636794cf5a21a44bbb34955610f0a` (`vksp`).
- **Everything below runs with base packages** (`procps`, `iproute2`, `coreutils`); `lsof`, `auditd`, `bpftrace` are optional and never required.

---

## 1. Process-layer artifacts: comm, argv[0], exe

### 1.1 What each field actually is

| Field | Source | Truncation | Attacker-writable |
|---|---|---|---|
| `/proc/pid/comm` | `prctl(PR_SET_NAME)`, `pthread_setname_np` | 16 bytes incl. NUL (`TASK_COMM_LEN`) — [proc_pid_comm(5)](https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html) | yes, any time |
| `/proc/pid/cmdline` | argv memory | none | yes — man page: *"Think of this file as the command line that the process wants you to see"* — [proc_pid_cmdline(5)](https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html) |
| `/proc/pid/exe` | executed inode | n/a | no (kernel-maintained) |

Two `comm` values worth a hard-coded alert because they are *kernel-thread impersonation*: a real kernel thread has no user address space, so `readlink /proc/<pid>/exe` fails; `ps` still prints the name in **square brackets** ([ps(1)](https://man7.org/linux/man-pages/man1/ps.1.html)). Any process whose `comm` is `[kworker/0:1]` but whose `/proc/<pid>/exe` resolves has a live userspace binary behind it.

### 1.2 One-liner: find processes running from writable or anonymous memory

```sh
# run as root; safe, read-only
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  exe=$(readlink "$p/exe" 2>/dev/null) || continue      # ENOENT for kernel threads
  case "$exe" in
    */tmp/*|*/var/tmp/*|*/dev/shm/*|*/run/*|*/home/*/.cache/*|*"(deleted)"|/memfd:*)
      printf '%-7s %-55s %s\n' "$pid" "$exe" "$(tr '\0' ' ' < "$p/cmdline")" ;;
  esac
done
```

- `*"(deleted)"` is appended by the kernel when the inode was unlinked ([proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)) — the classic "download, chmod, run, rm" pattern.
- `/memfd:name (deleted)` is what an `memfd_create(2)` payload looks like (Linux 3.17+; the `/proc/pid/maps` example string `/memfd:my_memfd_file (deleted)` is in [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html)).
- Hash the **running** image, not the disk path — this survives on-disk replacement and unlink:
  ```sh
  sha256sum "/proc/$pid/exe"
  ```

### 1.3 The renamed-binary trick and how to break it

`cp cloudflared /usr/bin/systemd-helper; chmod +x; ./systemd-helper tunnel run --token <tok>` defeats name matching, but Go and Rust leave build metadata:

```sh
go version -m /proc/$pid/exe        # prints module path + deps (needs the go toolchain)
strings -a /proc/$pid/exe | grep -m3 -E 'go1\.[0-9]+|github\.com/(fatedier/frp|XTLS/Xray-core|SagerNet/sing-box|apernet/hysteria|jpillora/chisel|go-gost/gost|cloudflare/cloudflared|ngrok/ngrok|rathole-org/rathole)'
```

`go version [-m] [file ...]` prints embedded build info for Go binaries — [cmd/go docs](https://pkg.go.dev/cmd/go). `strings` (binutils, installed by default) is enough when Go is absent: module paths, `tokio`/`hyper` crate names for Rust builds (`rathole`, `hysteria` variants), and the version string usually survive `-ldflags "-s -w"`.

Then ask the package manager whether that path is legitimate — remembering to strip the ` (deleted)` suffix first:

```sh
path=$(readlink /proc/$pid/exe | sed 's/ (deleted)$//')
dpkg -S "$path"     # Debian/Ubuntu;  dpkg-query --search
rpm  -qf "$path"    # RHEL/Fedora/SUSE
```

A binary at `/usr/local/bin/` or `/opt/` that belongs to no package is not proof of malice (cloudflared, xray and frp are *normally* hand-installed there), but a binary under `/tmp`, `/dev/shm` or `~/.cache` never is.

### 1.4 Related cheap signals

- `systemctl list-units --type=service --state=running` and `systemd-cgls` — a long-lived tunnel almost always becomes a unit (e.g. `/etc/systemd/system/cloudflared.service`, which `cloudflared service install` writes, config in `/etc/cloudflared/config.yml` — [linux_service.go](https://github.com/cloudflare/cloudflared/blob/master/cmd/cloudflared/linux_service.go)).
- Processes at the very root of the cgroup tree (`0::/`) with no unit and no parent shell — escaped/systemd-less payloads.
- `ss -x -p` for the unix sockets of the *management* side (docker.sock, dbus) if you suspect lateral use.

---

## 2. Socket tables

### 2.1 Listening and established, with owners

`ss` ships in **iproute2** (`/usr/bin/ss`), present by default on Debian/Ubuntu/RHEL/Fedora (verified locally: `ss utility, iproute2-7.3.0` at `/usr/bin/ss`). `netstat` comes from `net-tools`, which current RHEL and Debian releases no longer install by default — treat that specific claim as unverified here.

```sh
ss -H -tulpn                    # all listeners, numeric, with process (root)
ss -H -tulpn | grep -vE ':(22|25|53|80|443|3306|5432)\b'   # crude baseline diff
ss -Htnp state established '( dport = :7844 or sport = :7844 )'   # cloudflared
ss -Hunp                                                        # QUIC/UDP side
ss -H -e -tulpn                 # adds uid:<n> ino:<inode> sk:<cookie>-e
```

`-e` prints `uid:<uid_number> ino:<inode_number> sk:<cookie>` ([ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html)); the `ino` is the value you match against `socket:[inode]` in `/proc/<pid>/fd/*` ([proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)), which is also how `ss -p` itself joins sockets to PIDs.

**Privilege reality check:** readlink of `/proc/<pid>/fd/*` is governed by a `PTRACE_MODE_READ_FSCREDS` check, so as a non-root user `ss -p` silently omits other users' processes. In this sandbox (`uid=966`), `ss -tulpn` printed *no* `users:(...)` column even for root-owned `sshd` on :22. Run the audit as root.

If `ss` is unavailable, `/proc/net/tcp`, `tcp6`, `udp`, `udp6` give the same data in hex — local address `010310AC:9C4C` = `172.16.3.1:40012`, with the inode in column 10 ([kernel doc: proc/net/tcp](https://docs.kernel.org/networking/proc_net_tcp.html)). 7844 decimal = `0x1EA4`.

### 2.2 Port signature table

| Port / proto | Software | Role | Source |
|---|---|---|---|
| **7844 tcp+udp** | cloudflared | **egress only** to Cloudflare edge (http2 = TCP, quic = UDP) | [Cloudflare Tunnel configuration](https://developers.cloudflare.com/tunnel/configuration/) |
| 20241-20245 tcp | cloudflared | Prometheus metrics on `127.0.0.1` (container: `0.0.0.0`); random port if all taken | [Metrics](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/monitor-tunnels/metrics/) |
| 7000 tcp | frps | `bind_port` client control port (kcp variant reuses 7000/udp) | [frps_full.ini](https://raw.githubusercontent.com/fatedier/frp/v0.51.3/conf/frps_full.ini) |
| 7500 tcp | frps | `dashboard_port`, default `admin`/`admin` | same file, lines 41-49 |
| 80/443 tcp | frps | `vhost_http_port` / `vhost_https_port` | same file |
| 2333 tcp | rathole server | example `bind_addr = "0.0.0.0:2333"` — must be set explicitly | [rathole README](https://github.com/rathole-org/rathole) |
| 8080 tcp | chisel server | `--port` defaults to env `PORT`, else 8080 | [chisel README](https://github.com/jpillora/chisel) |
| 8080 tcp | gost | `gost -L :8080` = HTTP+SOCKS5 on 8080 | [GOST v2 getting started](https://v2.gost.run/en/getting-started/) |
| 8080 tcp | qBittorrent-nox | WebUI default port (`WebUI/Port`, 8080) | [preferences.cpp L868](https://raw.githubusercontent.com/qbittorrent/qBittorrent/master/src/base/preferences.cpp) |
| 4040 tcp | ngrok agent | local web inspection UI / API on `localhost:4040` | [ngrok web inspection interface](https://ngrok.com/docs/agent/web-inspection-interface) |
| 1080 tcp | microsocks | default `listenip 0.0.0.0`, port 1080 | [microsocks README](https://github.com/rofl0r/microsocks) |
| 1080 tcp | 3proxy `socks` | SOCKS 4/4.5/5 default | [3proxy.cfg(5)](https://3proxy.org/doc/man5/3proxy.cfg.5.html) |
| 3128 tcp | 3proxy `proxy` | HTTP/HTTPS proxy default | same |
| 1080 tcp | dante `sockd` | `internal: … port = 1080` in official minimal config | [dante minimal server config](https://www.inet.no/dante/doc/latest/config/server.html) |
| 1080 tcp | v2ray | shipped `release/config/config.json` socks inbound on `127.0.0.1:1080` | [v2ray-core config.json](https://raw.githubusercontent.com/v2fly/v2ray-core/master/release/config/config.json) |
| 443 tcp | xray / sing-box / naive | REALITY/VLESS examples listen on 443 | [XTLS/Xray-examples](https://github.com/XTLS/Xray-examples) |
| 443 udp | hysteria2 | `listen` omitted ⇒ `:443` ("default HTTP/3 port") | [Hysteria 2 full server config](https://v2.hysteria.network/docs/advanced/Full-Server-Config) |
| 9091 tcp / 51413 | transmission-daemon | `rpc_port` default 9091, `peer_port` default 51413 | [Editing-Configuration-Files.md](https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md) |
| 8112 tcp / 58846 tcp | deluge-web / deluged | web UI `'port': 8112`; daemon RPC `port=58846` | [web/server.py](https://raw.githubusercontent.com/deluge-torrent/deluge/develop/deluge/ui/web/server.py), [core/rpcserver.py](https://raw.githubusercontent.com/deluge-torrent/deluge/develop/deluge/core/rpcserver.py) |

Two caveats that matter more than the table: (a) every one of these is a *configurable* port, so a signature hit is a lead, not a verdict; (b) `xray`/`sing-box`/`tuic`/`naive` have **no compiled-in default listener** — only example configs — so "unusual port + Go binary + no package owner" is the real detector.

### 2.3 Outbound-only programs

`cloudflared`, `ngrok`, `frpc`, `rathole` (client), `chisel client`, `tmate`, `ssh -R` and `socat` create **no listening socket** on the victim. Detect them by flows:

```sh
ss -Htnp state established '( dport = :7844 )'
ss -Htnp state established '( dport = :443 )' | grep -vE 'chrome|firefox|apt|curl'
ss -Htnp state established | wc -l      # crude fan-out baseline
```

GuidePoint's in-the-wild writeup lists the DNS side of a Cloudflare tunnel: `protocol-v2.argotunnel.com`, `_v2-origintunneld._tcp.argotunnel.com`, `region1.v2.argotunnel.com`, `region2.v2.argotunnel.com`, plus `update.argotunnel.com` for autoupdates ([Tunnel Vision: Cloudflared Abused in the Wild](https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild)). On a host that has no business running a tunnel, one `resolvectl query`-free grep of the journal or a `tcpdump -nn port 53` is decisive.

`nsenter` note: `ss` only sees the current netns. Loop and compare inodes, then enter:

```sh
for n in /proc/[0-9]*/ns/net; do readlink "$n"; done | sort -u   # distinct netns
nsenter -t "$pid" -n -- ss -Htulpn                                # needs root (CAP_SYS_ADMIN)
```

---

## 3. Container artifacts

Docker is how most of this gets deployed: Akamai's proxyjacking campaign used SSH access, pulled a public image, named the workdir `_postfixd_`, and explicitly killed competing `peer2profit`/`p2pclient` containers; Sysdig measured `fazalfarhan01/peer2profit` at >10 million pulls ([Akamai](https://www.akamai.com/blog/security-research/proxyjacking-new-campaign-cybercriminal-side-hustle), [Sysdig](https://www.sysdig.com/blog/proxyjacking-attackers-log4j-exploited)).

```sh
docker ps --no-trunc --format '{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Ports}}'
docker ps -q | xargs -r docker inspect \
  --format '{{.Name}} net={{.HostConfig.NetworkMode}} priv={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} img={{.Config.Image}}'
docker events --since 24h --filter type=container     # starts you did not do
```

- `NetworkMode: host` means *the container shares the host's networking namespace* — its listeners appear in the host's `ss`, and `-p`/`--publish` is ignored with a warning ([Docker host network driver](https://docs.docker.com/engine/network/drivers/host/)). This is the single most useful field: proxy images are usually run with host networking so the "unused bandwidth" is not NAT'd.
- `PidMode: host` plus `Privileged: true` on a stranger's image is an immediate escalation.
- Namespace-inode proof, independent of the Docker CLI:
  ```sh
  readlink /proc/$pid/ns/net    # compare with readlink /proc/1/ns/net
  cat /proc/$pid/cgroup         # cgroup v2: 0::/system.slice/docker-<id>.scope
  ```
- Images to look for by name: `peer2profit/*`, `*honeygain*`, `enwaiax/peer2profit`, `fazalfarhan01/peer2profit`, `jujudna/peer2profit`, `gqkkk/p2p`, `computeofficial/pawnsapp` (Sysdig, same URL).

---

## 4. Greppable file artifacts and published IoCs

```sh
# tunnel/proxy configuration and credentials
ls -l /etc/cloudflared/config.yml /root/.cloudflared/*.json 2>/dev/null
ls -l /root/.config/ngrok/ngrok.yml /etc/ngrok.yml 2>/dev/null
ls -l /usr/local/etc/xray/config.json /etc/sing-box/config.json \
      /etc/frp/frps.toml /etc/frp/frpc.toml /etc/sockd.conf /etc/3proxy/3proxy.cfg 2>/dev/null
ls -l /etc/systemd/system/{cloudflared,xray,sing-box,frps,frpc}.service 2>/dev/null

# content sweep (tokens, tunnel UUIDs, proxy directives)
grep -rIl -e 'tunnel run --token' -e 'trycloudflare' -e 'argotunnel' -e 'peer2profit' \
     -e 'honeygain' -e 'pawns' /etc /root /home /var/spool/cron /usr/local/etc 2>/dev/null
```

Default paths confirmed upstream: cloudflared uses `/etc/cloudflared` + `config.yml` + `cloudflared.service` and otherwise `~/.cloudflared`, `/usr/local/etc/cloudflared` ([cloudflared source](https://github.com/cloudflare/cloudflared/blob/master/cmd/cloudflared/linux_service.go), [Cloudflare default directory](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/local-tunnel-terms/)); ngrok's agent config is `~/.config/ngrok/ngrok.yml` on Linux ([ngrok docs](https://ngrok.com/docs/agent/config/)); the Xray installer writes `/usr/local/etc/xray/config.json` and `/etc/systemd/system/xray.service` ([install-release.sh](https://github.com/XTLS/Xray-install/blob/main/install-release.sh)); dante's file is `/etc/sockd.conf` (FILES section of [sockd.conf(5)](https://man.archlinux.org/man/sockd.conf.5.en)).

Published hashes (verbatim, nothing added):

| Hash | File / note | Source |
|---|---|---|
| `6927833415c4879728707574c0849bfc` (MD5) | `/tmp/p32` — Peer2Profit ELF dropped via Log4j | [Sysdig](https://www.sysdig.com/blog/proxyjacking-attackers-log4j-exploited) |
| `f10861ea968770effbd61cda573b6ff8` (MD5) | `/tmp/b`, `/tmp/c` | same |
| `6f1ac1e711e662edad32713c135ce29562d636794cf5a21a44bbb34955610f0a` (SHA256) | `vksp` — cryptominer on the same distro server | [Akamai](https://www.akamai.com/blog/security-research/proxyjacking-new-campaign-cybercriminal-side-hustle) |

Treat these as *campaign* IoCs (2023), not family signatures: a fresh `cloudflared` from GitHub is byte-identical to a "malicious" one.

---

## 5. Putting it in one cron-able script

```sh
#!/bin/sh
# rdonly proxy/tunnel sweep — run as root, writes nothing
echo "== suspicious process images"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in
    */tmp/*|*/dev/shm/*|*/var/tmp/*|*"(deleted)"|/memfd:*)
      printf '%s %s %s\n' "$pid" "$exe" "$(tr '\0' ' ' <"$p/cmdline")";;
  esac
done
echo "== listeners (non-standard)"
ss -H -tulpn | grep -vE ':(22|25|53|80|443|631|3306|5432)\s'
echo "== tunnel egress"
ss -Htnp state established '( dport = :7844 )'
echo "== containers"
command -v docker >/dev/null && docker ps --format '{{.Image}} {{.Names}} {{.Ports}}'
```

Everything used here is in `procps`, `iproute2` and `coreutils`. `lsof`, `auditd` (`-a always,exit -F arch=b64 -S execve`), `bpftrace` (`kprobe:do_execveat_common`) give *event* history rather than a snapshot and are worth adding later, but none is required for the snapshot above.

---

## Sources

- proc: [proc_pid_comm(5)](https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html), [proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html), [proc_pid_cmdline(5)](https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html), [proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html), [ps(1)](https://man7.org/linux/man-pages/man1/ps.1.html)
- syscalls: [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html), [PR_SET_NAME(2const)](https://man7.org/linux/man-pages/man2/PR_SET_NAME.2const.html)
- sockets: [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html), [kernel: /proc/net/tcp](https://docs.kernel.org/networking/proc_net_tcp.html)
- Cloudflare: [Tunnel configuration / 7844](https://developers.cloudflare.com/tunnel/configuration/), [Metrics / 20241-20245](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/monitor-tunnels/metrics/), [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels), [linux_service.go](https://github.com/cloudflare/cloudflared/blob/master/cmd/cloudflared/linux_service.go)
- tool defaults: [frps_full.ini](https://raw.githubusercontent.com/fatedier/frp/v0.51.3/conf/frps_full.ini), [rathole](https://github.com/rathole-org/rathole), [chisel](https://github.com/jpillora/chisel), [GOST v2](https://v2.gost.run/en/getting-started/), [microsocks](https://github.com/rofl0r/microsocks), [3proxy.cfg(5)](https://3proxy.org/doc/man5/3proxy.cfg.5.html), [dante](https://www.inet.no/dante/doc/latest/config/server.html), [sockd.conf(5)](https://man.archlinux.org/man/sockd.conf.5.en), [ngrok agent config](https://ngrok.com/docs/agent/config/), [ngrok 4040](https://ngrok.com/docs/agent/web-inspection-interface), [hysteria2](https://v2.hysteria.network/docs/advanced/Full-Server-Config), [v2ray sample config](https://raw.githubusercontent.com/v2fly/v2ray-core/master/release/config/config.json), [Xray-examples](https://github.com/XTLS/Xray-examples)
- torrents: [transmission config docs](https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md), [qBittorrent preferences.cpp](https://raw.githubusercontent.com/qbittorrent/qBittorrent/master/src/base/preferences.cpp), [deluge web/server.py](https://raw.githubusercontent.com/deluge-torrent/deluge/develop/deluge/ui/web/server.py), [deluge core/rpcserver.py](https://raw.githubusercontent.com/deluge-torrent/deluge/develop/deluge/core/rpcserver.py)
- containers: [Docker host network driver](https://docs.docker.com/engine/network/drivers/host/), [docker container ls](https://docs.docker.com/reference/cli/docker/container/ls/), [Docker format templates](https://docs.docker.com/go/formatting/)
- threat: [Akamai proxyjacking](https://www.akamai.com/blog/security-research/proxyjacking-new-campaign-cybercriminal-side-hustle), [Sysdig proxyjacking](https://www.sysdig.com/blog/proxyjacking-attackers-log4j-exploited), [GuidePoint Tunnel Vision](https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild), [ATT&CK T1090](https://attack.mitre.org/techniques/T1090), [ATT&CK T1496.002](https://attack.mitre.org/techniques/T1496/002), [DET0445](https://attack.mitre.org/detectionstrategies/DET0445), [DET0028](https://attack.mitre.org/detectionstrategies/DET0028)

## What I could not verify

- **`ss -p` privilege semantics.** Not stated in ss(8); the "root or same UID" rule is inferred from the ptrace access-mode check on `/proc/<pid>/fd` plus local observation (non-root `ss -tulpn` printed no process column). Upstream inet_diag's only explicit `CAP_NET_ADMIN` branch is bytecode validation, not dump visibility.
- **qBittorrent default peer port 6881.** Not found in `preferences.cpp` or `sessionimpl.cpp` at the paths I checked; third-party Docker readmes say 6881. Treat as unverified.
- **rathole's 2333.** The upstream example uses it, but `bind_addr` is documented as "Necessary", i.e. there is no compiled default.
- **Second Akamai SHA256** (`72e7dd199bed6eefa0ae763c399e0d8a56e2b1dfacc089046706226a5f2a`) is truncated to 60 hex chars in the published page — do not use it as a match string.
- **sing-box config path** `/etc/sing-box/config.json`: widely used in tutorials and third-party installers, but I found no first-party install script in `SagerNet/sing-box`'s `release/` directory to confirm it.
- **tmate.** The upstream README appears to reference a hosted-service shutdown (commit dated Oct 2026); I did not confirm whether `tmate.io` still operates, so "outbound SSH to tmate.io:22" is stated as the documented model, not as current status.
- **Whether `cloudflared` binds anything besides the metrics port by default.** Docs describe only the metrics endpoint; no documented local control socket.
- **No live execution** of `docker`, `nsenter`, `auditctl` or `bpftrace` was performed here (shared sandbox, no privileged state changes); command syntax was validated against upstream docs and, where possible, parsed locally (`ss` filter syntax tested on iproute2-7.3.0).

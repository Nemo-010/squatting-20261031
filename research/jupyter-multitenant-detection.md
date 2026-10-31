# Detecting proxyjacking inside Jupyter: kernels, connection files and per-user egress accounting on one Linux box

*Scope: JupyterHub and standalone Jupyter Server on a single host, using only software already shipped with the distro (systemd, nftables, iproute2, sqlite3, /proc). No NDR, no commercial agent.*

## Summary

- A Jupyter "kernel" is just a child process: `<python> -m ipykernel_launcher -f {connection_file}`, spawned by `jupyterhub-singleuser` or `jupyter-server`. Any bandwidth-hijacking payload (proxyware, SOCKS5 server, torrent client, tunnel) is therefore a grandchild of the notebook server that inherits **no** resource control under JupyterHub's default `LocalProcessSpawner`, which the docs say "does not support limits and guarantees".
- Every live session leaves a durable, readable trail: `~/.local/share/jupyter/runtime/kernel-<kernel_id>.json` (ports + HMAC key), `~/.local/share/jupyter/runtime/jpserver-<pid>.json` (**includes the server token**), and `~/.ipython/profile_default/history.sqlite` (every cell's source text).
- `systemd` has built-in per-unit network accounting: `IPAccounting=yes` (systemd 235, Linux 4.11 cgroup/eBPF hooks) exposes `IPEgressBytes`/`IPIngressBytes` via `systemctl show` and an `IP:` line in `systemctl status`. This is the cheapest per-user egress meter available.
- `IPAccounting` is **not recursive** (a slice cannot aggregate its children) and, per an open systemd bug, undercounts TCP flows because of GSO aggregation — treat it as a trend signal, not a billing meter.
- `IPAddressAllow=`/`IPAddressDeny=` give you a per-notebook **allow-list** (loopback-only notebook = no proxyjacking possible), `SocketBindDeny=any` (systemd 249) stops a notebook from opening any listening socket — the direct control for "tunnel squatting".
- Rate limiting is not a systemd feature. Use `nft` `socket cgroupv2` + `limit rate over N mbytes/second drop` (policing), or mark packets with `nft` and shape with `tc htb` + `fw` filter.
- Cgroup-based filtering only affects sockets **created after** the process joined the cgroup — you must spawn notebooks into the unit, you cannot retrofit by moving a running PID.
- JupyterHub's `Authenticator`/`Authorizer` (RBAC, JupyterHub 2.0) controls **who may call which API**; it has no concept of egress. What it gives the defender is attribution: user, server name, spawn/stop events, token scope.
- Structured events (`jupyter_events`, `server-action` schema) record only successful server `start`/`stop` — no bytes, no destinations, no failures.

## 1. What is actually running, and why it is invisible

JupyterHub binds port **8000** by default (`c.JupyterHub.port = 8000`, `bind_url` default `http://:8000`) — https://jupyterhub.readthedocs.io/en/stable/reference/config-reference.html. Each user's server is started by `Spawner.cmd`, default `['jupyterhub-singleuser']`, bound to `Spawner.ip`/`Spawner.port` = `127.0.0.1:{random}`; the bind URL is handed over in `JUPYTERHUB_SERVICE_URL`, and the server also gets `JUPYTERHUB_USER` and `JUPYTERHUB_API_TOKEN` (which doubles as its OAuth client secret) — https://jupyterhub.readthedocs.io/en/stable/reference/spawners.html.

Standalone Jupyter Server listens on `127.0.0.1:8888` by default — https://jupyter-server.readthedocs.io/en/latest/operators/public-server.html.

The default spawner is `LocalProcessSpawner`, which the same doc says "does not support limits and guarantees". On a stock install there is no cgroup, no counter and no quota between a notebook and the internet.

Process tree and kernel command line:

```bash
pstree -sp $(pgrep -f jupyterhub-singleuser | head -n1)
pgrep -af 'jupyterhub-singleuser|ipykernel_launcher|jupyter-server'
```

`ipykernel`'s kernelspec argv is exactly `[executable, "-m", "ipykernel_launcher", "-f", "{connection_file}"]` — https://github.com/ipython/ipykernel/blob/main/ipykernel/kernelspec.py. A terminal tab is a separate `bash` child of the single-user server (`/api/terminals` REST endpoints, https://jupyter-server.readthedocs.io/en/latest/developers/rest-api.html); `ServerApp.terminals_enabled` turns them off — https://github.com/jupyter-server/jupyter_server/blob/main/jupyter_server/serverapp.py.

Attribute any PID to a user and a unit:

```bash
cat /proc/<pid>/cgroup            # cgroup path, e.g. .../system.slice/jupyter-alice-singleuser.service
cat /proc/<pid>/environ | tr '\0' '\n' | grep -E 'JUPYTER_RUNTIME_DIR|JUPYTERHUB_(USER|SERVICE_URL)'
systemd-cgls /system.slice/jupyter-alice-singleuser.service   # full cgroup path form
```

Real campaigns use the same door: Aqua Nautilus's "Sobolan" entered an **unauthenticated JupyterLab instance**, pulled `temp.tar` from a remote IP, unpacked 13 files into `/var/tmp/.lol11/.ICE-Temp`, added cron persistence and ran a miner — https://www.aquasec.com/blog/stopping-sobolan-with-aqua-runtime-protection/. Bandwidth hijacking (ATT&CK **T1496.002**) is that pattern with a proxy/tunnel payload, so the observable is a long-lived outbound connection owned by a kernel child. MITRE's AN0081 names "curl, wget, masscan, or proxy clients" and AN0083 covers "Containerized apps… leveraged for proxy networks" — https://attack.mitre.org/detectionstrategies/DET0028/.

## 2. Artifacts a notebook session leaves behind

Runtime files live in a `runtime/` subdirectory of the user data dir; `jupyter --runtime-dir` prints it — https://docs.jupyter.org/en/stable/use/jupyter-directories.html. On Linux the data dir is `${XDG_DATA_HOME:-~/.local/share}/jupyter` and the runtime dir is `jupyter_data_dir()/runtime`; `JUPYTER_RUNTIME_DIR` overrides it — https://github.com/jupyter/jupyter_core/blob/main/jupyter_core/paths.py. **`JUPYTER_RUNTIME_DIR` is attacker-settable**, so check `/proc/<pid>/environ` before concluding "no artifacts".

Three file classes matter:

1. **Kernel connection files.** `MultiKernelManager` writes `kernel-%s.json % kernel_id` into `connection_dir`, and `ServerApp` sets `connection_dir = runtime_dir` — https://github.com/jupyter/jupyter_client/blob/main/jupyter_client/multikernelmanager.py and https://github.com/jupyter-server/jupyter_server/blob/main/jupyter_server/serverapp.py. Contents: `ip`, `transport`, five random TCP ports (`shell`, `iopub`, `stdin`, `control`, `hb`), and the HMAC `key` used to sign messages (`write_connection_file`, 0600 via `secure_write`, sticky bit on the directory) — https://github.com/jupyter/jupyter_client/blob/main/jupyter_client/connect.py. A connection file is a **live credential** into that kernel.
2. **Server info files.** `jpserver-<pid>.json` (`ServerApp.info_file` default) and `server_info()` includes `"token": self.identity_provider.token` — https://github.com/jupyter-server/jupyter_server/blob/main/jupyter_server/serverapp.py. This is why `jupyter server list` can print `http://127.0.0.1:PORT/?token=...`. Anyone who can read that file owns the server; hunting for world-readable ones is a fast win.
3. **IPython history.** `HistoryManager` / `HistoryAccessor` default to `Path(locate_profile(profile)) / "history.sqlite"`, i.e. `~/.ipython/profile_default/history.sqlite`, with tables `sessions(session, start, end, num_cmds, remark)`, `history(session, line, source, source_raw)` and `output_history(session, line, output)` (output storage off by default; `store_display_history` defaults to False) — https://github.com/ipython/ipython/blob/main/IPython/core/history.py and https://github.com/ipython/ipykernel/blob/main/ipykernel/zmqshell.py. Kernels are built with `profile_dir=self.profile_dir`, so cell source lands in the profile DB.

Forensic queries (read-only):

```bash
# what this user executed, newest last
sqlite3 ~/.ipython/profile_default/history.sqlite \
  "SELECT s.start, h.line, substr(h.source_raw,1,300)
     FROM history h JOIN sessions s USING(session)
    ORDER BY h.session DESC, h.line DESC LIMIT 40;"

# egress tooling in notebook source/outputs
grep -rlE 'proxy|socks|tun2socks|peer2profit|earnfm|xmrig|stratum\+tcp|iproyal|honeygain' \
     --include='*.ipynb' /home 2>/dev/null
jq -r '.cells[]?.source | if type=="array" then join("") else . end' some.ipynb
```

JupyterHub's state DB is `sqlite:///jupyterhub.sqlite` by default (`c.JupyterHub.db_url`), cookie secret file `jupyterhub_cookie_secret` — https://jupyterhub.readthedocs.io/en/stable/reference/config-reference.html. Tables include `users`, `servers`, `spawners`, `api_tokens`, `oauth_clients` (https://github.com/jupyterhub/jupyterhub/blob/main/jupyterhub/orm.py):

```bash
sqlite3 /srv/jupyterhub/jupyterhub.sqlite \
  "SELECT name, admin, last_activity FROM users ORDER BY last_activity DESC LIMIT 20;"
sqlite3 /srv/jupyterhub/jupyterhub.sqlite \
  "SELECT id, proto, ip, port FROM servers;"
sqlite3 /srv/jupyterhub/jupyterhub.sqlite \
  "SELECT user_id, prefix, expires_at FROM api_tokens;"
```

## 3. Per-user egress accounting with systemd scopes

`IPAccounting=` (systemd **235**) "turns on IPv4 and IPv6 network traffic accounting for packets sent or received by the unit… all IPv4 and IPv6 sockets created by any process of the unit are accounted for", and it is "currently only available for system services, not for per-user services" — https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html. The kernel prerequisite is the cgroup eBPF hooks from **Linux 4.11** — https://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html.

Wrap a notebook server manually:

```bash
systemd-run --unit=jupyter-alice --uid=alice --slice=jupyter.slice \
  -p IPAccounting=yes -p MemoryMax=8G -p CPUQuota=200% \
  /usr/local/bin/jupyterhub-singleuser
```

Read it back (property names verified in the D-Bus API):

```bash
systemctl show jupyter-alice -p IPIngressBytes -p IPIngressPackets -p IPEgressBytes -p IPEgressPackets
# IPIngressBytes=37776
# IPIngressPackets=449
systemctl status jupyter-alice | grep ' IP:'
```

Those four are readonly properties on `org.freedesktop.systemd1.Unit` — https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html.

**Caveats that matter for correctness:**

- IP accounting is **not recursive**; a slice does not sum its members ("IP accounting is currently not recursive… you cannot use a slice unit to join the accounting of multiple units") — https://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html. Poll each unit.
- Counters undercount TCP: GSO aggregates are split after the accounting hook, so `IPEgressBytes` systematically under-reports; the reporter notes nftables counters share the flaw — https://github.com/systemd/systemd/issues/34775 (open since Oct 2024).
- Counters only cover sockets created while accounting is on, and `--user` managers are excluded, so rootless JupyterHub cannot use this at all.

**With JupyterHub + systemdspawner** (`pip install jupyterhub-systemdspawner`; requires systemd ≥ 245, JupyterHub run as root; `unit_name_template` default `jupyter-{USERNAME}-singleuser`) the same properties are injected because `unit_extra_properties` is passed to `systemd-run --property=`:

```python
c.JupyterHub.spawner_class = "systemd"
c.SystemdSpawner.unit_name_template = "jupyter-{USERNAME}-singleuser"
c.SystemdSpawner.disable_user_sudo = True          # default True
c.SystemdSpawner.readonly_paths = ["/"]
c.SystemdSpawner.readwrite_paths = ["/home/{USERNAME}"]
c.SystemdSpawner.unit_extra_properties = {
    "IPAccounting": "yes",
    "IPAddressDeny": "any",
    "IPAddressAllow": "localhost",   # Hub/proxy on loopback only
}
```

Source for all of the above options: https://github.com/jupyterhub/systemdspawner (README). `dynamic_users = True` gives every session an ephemeral UID, which breaks UID-based firewall rules — relevant to §4.

## 4. Capping and rate-limiting egress per notebook

**a) Allow-list (blocking, no rate).** `IPAddressAllow=`/`IPAddressDeny=` filter "IP packets sent and received over `AF_INET` and `AF_INET6` sockets… In case of egress traffic the destination IP address is checked". Allow wins over deny; unrecognised ⇒ allowed. The documented pattern is `IPAddressDeny=any` on an upper slice plus per-service `IPAddressAllow=` — https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html. A notebook that may only reach `localhost` cannot exfiltrate or relay — at the cost of no pip installs, no data downloads, and no external DNS (add `IPAddressAllow=10.0.0.53/32` if you keep a resolver).

**b) Stop the notebook from serving anyone (tunnel squatting).** `SocketBindAllow=`/`SocketBindDeny=` (systemd **249**, cgroup/bind4+bind6 hooks) restricts `bind(2)` per unit and "cannot be bypassed by prefixing `+` to the executable path… it applies to the whole control group". Be careful: a blanket `SocketBindDeny=any` also breaks the kernel, which must bind five loopback ZMQ ports, and the bind-rule grammar (`{address-family:[transport-protocol:][ip-ports:]}`) has no address or interface selector, so you cannot allow "loopback only". The precise control is at the input hook — drop inbound packets aimed at any socket owned by the notebook cgroup and arriving from a non-loopback interface:

```
chain in { type filter hook input priority 0; policy accept;
  iifname != "lo" socket cgroupv2 level 2 \
    "system.slice/jupyter-alice-singleuser.service" drop
}
```

`RestrictNetworkInterfaces=` (systemd **243**) narrows the unit to named interfaces — same man page as (a).

**c) Policing with nftables (no systemd dependency).** `nft` can match a packet to the **socket's** cgroup:

`/etc/nftables.d/jupyter.nft`, loaded with `nft -f /etc/nftables.d/jupyter.nft`:

```
table inet egress {
  chain out { type filter hook output priority 0; policy accept;
    socket cgroupv2 level 2 "system.slice/jupyter-alice-singleuser.service" \
      limit rate over 2 mbytes/second drop
    socket cgroupv2 level 2 "system.slice/jupyter-alice-singleuser.service" counter
  }
}
```

`socket cgroupv2 level NUM` matches "the socket cgroupv2 at a given ancestor level… ancestor level 1 checks for a matching on cgroup a and ancestor level 2 checks for a matching on cgroup b"; the path is relative to `/sys/fs/cgroup` (https://netfilter.org/projects/nftables/manpage.html). `limit rate over N mbytes/second` is a token bucket that matches *above* the rate, which is exactly a drop rule — same man page. Note `meta cgroup` "reads zero on cgroupv2-only hosts without an active net_cls hierarchy", so do not use `meta cgroup`.

For units whose cgroup ID changes (restarts, `DynamicUser=`), `NFTSet=cgroup:inet:egress:jupyter` (systemd **260**) makes systemd maintain a `cgroupsv2`-type nft set, so the rule becomes `socket cgroupv2 level 2 @jupyter` — same man page.

Kernel support: community documentation states `socket cgroupv2` matching needs Linux **5.13+** (https://github.com/mk-fg/systemd-cgroup-nftables-policy-manager) — **unverified against a primary kernel source**; the iptables equivalent `-m cgroup --path …` is exercised in https://www.suse.com/blog/net_cls-in-the-time-of-cgroup-v2/.

**Critical ordering rule:** "migrating a process between two cgroups will not affect rules applied to already created sockets (those remain associated to their original cgroup)" — https://www.suse.com/blog/net_cls-in-the-time-of-cgroup-v2/. Cgroup-based egress control must be applied at spawn time (systemdspawner / `systemd-run`), never retrofitted.

**d) Shaping instead of dropping.** Mark by cgroup, shape by mark: `nft … socket cgroupv2 level 2 "…" meta mark set 0x10`, then

```bash
tc qdisc add dev eth0 root handle 1: htb default 9999
tc class add dev eth0 parent 1: classid 1:1  htb rate 1gbit
tc class add dev eth0 parent 1:1 classid 1:10 htb rate 5mbit ceil 20mbit
tc filter add dev eth0 parent 1: protocol ip handle 0x10 fw classid 1:10
```

`fw` classifies "based on a previously set fwmark" (https://man7.org/linux/man-pages/man8/tc-fw.8.html); HTB syntax from https://man7.org/linux/man-pages/man8/tc-htb.8.html. On cgroup-v1 hosts the older path is `net_cls.classid` plus `tc filter … cgroup` (https://docs.kernel.org/admin-guide/cgroup-v1/net_cls.html).

**e) Containers.** `docker stats` reports a `NET I/O` column per container (https://docs.docker.com/reference/cli/docker/container/stats/); for KubeSpawner pods the equivalent number is cAdvisor's `container_network_transmit_bytes_total` (https://github.com/google/cadvisor/blob/master/docs/storage/prometheus.md).

## 5. What JupyterHub's auth model gives the defender

JupyterHub separates authentication (`Authenticator`) from authorization (`Authorizer`, RBAC since **2.0**): scopes are permissions, roles are bundles, and `self` expands for a user to `servers!user`, `access:servers!user`, `users:activity!user`, etc.; server tokens get `access:servers!user` + `users:activity!user` — https://jupyterhub.readthedocs.io/en/stable/rbac/index.html and https://jupyterhub.readthedocs.io/en/stable/rbac/scopes.html.

This model answers "who may drive which API" and nothing about packets. It gives you:

- **Attribution**: every kernel belongs to a user and a named server; the `servers`/`spawners` tables and `JUPYTERHUB_USER` in the process environment tie a PID to a human.
- **A structured event stream**: `EventLogger.handlers` with a `logging.FileHandler` emits JSON per event (https://jupyterhub.readthedocs.io/en/stable/reference/event-logging.html); the `server-action` schema records `action` (`start`/`stop`), `username`, `servername` — but "This does not record all server starts / stops" and "Events are only recorded when an action succeeds" (https://jupyterhub.readthedocs.io/en/stable/reference/server-actions.html).
- **Token blast radius**: `JUPYTERHUB_API_TOKEN` is in every kernel's environment; code running in a hijacked notebook can mint/act with it within its scopes.

On a systemd install both hub and servers log to the journal, one unit per user:

```bash
journalctl -u jupyterhub --since -24h
journalctl -u jupyter-alice-singleuser --since -24h
journalctl -u jupyterhub | grep -E 'Spawning|Stopping|logged in|403|token'
```

(Unit-per-user pattern from https://tljh.jupyter.org/en/latest/troubleshooting/logs.html.) The rule that a user must never be able to modify their own server, its packages or its config is in https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html — read it as a list of what an attacker can persist.

## 6. A 3-minute triage loop

```bash
# 1. notebook processes and their units
for p in $(pgrep -f ipykernel_launcher); do
  u=$(cat /proc/$p/cgroup | sed 's#.*/##'); echo "$p $u $(tr '\0' ' ' </proc/$p/cmdline)";
done

# 2. sockets owned by those processes (root needed to see other users)
ss -tnp state established | grep -v '127.0.0.1' | grep python

# 3. per-unit egress bytes, sorted
for u in $(systemctl list-units --type=service --no-legend 'jupyter-*' | awk '{print $1}'); do
  printf '%-50s %s\n' "$u" "$(systemctl show $u -p IPEgressBytes --value)"
done

# 4. non-loopback listeners (tunnel squatting)
ss -tlnp | grep -vE '127\.0\.0\.1|\[::1\]'

# 5. credential-bearing runtime files
find /home /var/lib -path '*/jupyter/runtime/*' -name 'jpserver-*.json' -perm -o+r 2>/dev/null
```

Anything in step 2 or 4 inside a kernel cgroup is the finding; check step 5 for stolen tokens and `history.sqlite` for the payload text.

## Sources

- https://jupyterhub.readthedocs.io/en/stable/reference/config-reference.html (port 8000, db_url, cookie_secret_file)
- https://jupyterhub.readthedocs.io/en/stable/reference/spawners.html (Spawner.cmd, ip/port, env vars, LocalProcessSpawner limits)
- https://github.com/jupyterhub/systemdspawner (requirements, unit_name_template, unit_extra_properties, dynamic_users)
- https://jupyterhub.readthedocs.io/en/stable/rbac/index.html ; .../rbac/scopes.html ; .../reference/event-logging.html ; .../reference/server-actions.html ; .../explanation/websecurity.html
- https://github.com/jupyterhub/jupyterhub/blob/main/jupyterhub/orm.py (db tables)
- https://jupyter-server.readthedocs.io/en/latest/developers/rest-api.html ; .../operators/public-server.html (default 8888)
- https://github.com/jupyter-server/jupyter_server/blob/main/jupyter_server/serverapp.py (info_file, server_info token, connection_dir)
- https://github.com/jupyter/jupyter_client/blob/main/jupyter_client/multikernelmanager.py ; .../connect.py
- https://github.com/jupyter/jupyter_core/blob/main/jupyter_core/paths.py ; https://docs.jupyter.org/en/stable/use/jupyter-directories.html
- https://github.com/ipython/ipython/blob/main/IPython/core/history.py ; https://github.com/ipython/ipykernel/blob/main/ipykernel/kernelspec.py ; .../zmqshell.py
- https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html (IPAccounting 235, IPAddressAllow/Deny, SocketBind 249, RestrictNetworkInterfaces 243, NFTSet 260)
- https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html ; .../systemctl.html ; .../org.freedesktop.systemd1.html
- https://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html (Linux 4.11, non-recursive, status output)
- https://github.com/systemd/systemd/issues/34775 (GSO undercount)
- https://netfilter.org/projects/nftables/manpage.html (socket cgroupv2, limit statement, meta cgroup caveat)
- https://www.suse.com/blog/net_cls-in-the-time-of-cgroup-v2/ (path form, socket/cgroup affinity)
- https://man7.org/linux/man-pages/man8/tc-fw.8.html ; https://man7.org/linux/man-pages/man8/tc-htb.8.html
- https://docs.kernel.org/admin-guide/cgroup-v1/net_cls.html
- https://docs.docker.com/reference/cli/docker/container/stats/ ; https://github.com/google/cadvisor/blob/master/docs/storage/prometheus.md
- https://attack.mitre.org/techniques/T1496/002/ ; https://attack.mitre.org/detectionstrategies/DET0028/
- https://www.aquasec.com/blog/stopping-sobolan-with-aqua-runtime-protection/ (unauthenticated JupyterLab → malware/cryptominer, `/var/tmp` staging, cron persistence)
- https://tljh.jupyter.org/en/latest/troubleshooting/logs.html ; https://github.com/jupyterhub/jupyterhub/blob/main/docs/source/howto/log-messages.md

## What I could not verify

- **Kernel version for `nft socket cgroupv2`.** Only a third-party README claims "linux-5.13+"; no primary kernel or netfilter release note was reachable (git.kernel.org sits behind an anti-bot challenge). Treat 5.13 as indicative and syntax-check with `nft -c -f` on the target.
- **`systemd-run --scope` + `IPAccounting=yes`.** The man page documents both independently and scopes do participate in cgroup accounting, but I found no upstream example of accounting on a transient *scope*; a transient *service* (default, no `--scope`) is the documented path. Verify with `systemctl show` on a test unit.
- **Whether every ipykernel build writes `history.sqlite`.** The default `HistoryManager` file is `profile_dir/history.sqlite` and kernels are constructed with `profile_dir=self.profile_dir`, but I did not find an explicit "kernels persist history to sqlite" statement in the docs; `HistoryManager.enabled` and DB write permissions can suppress it. Confirm on the host with `sqlite3 … "select count(*) from history"`.
- **`NFTSet=` (systemd 260)** is documented and is the clean way to bind a unit's numeric cgroup ID into an nft set that survives restarts, but I did not test it; the path-based `socket cgroupv2` form is the safer default.
- **Exact `systemctl status` rendering** of the `IP:` line varies by systemd version (sample from a 2018 blog post); prefer `systemctl show -p IPEgressBytes`.
- **Which systemd version ships in which distro.** Not enumerated; `IPAccounting` needs ≥ 235, `SocketBind*` ≥ 249, `NFTSet` ≥ 260.

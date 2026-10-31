# External vantage and entry-catching: what the outside sees, and cheap tripwires for what gets in

Scope: two views of one box you own. **Outside-in** — asking third parties (Shodan, Censys, Certificate Transparency, passive DNS, ASN registry, blocklists) what a stranger already knows about your IP: ports you did not open, hostnames in certificates you never issued, domains pointing at you that you do not control. **Entry-catching** — tripwires that fire when someone arrives: an endlessh SSH tarpit, a Cowrie honeypot, canarytokens, fake credentials, immutable-file semantics, `systemd.path` watchers and `auditd` read rules, alerting via ntfy/healthchecks/Telegram with no SIEM. Spamhaus/AbuseIPDB taxonomy lives in `tor-exit-relays-and-IP-reputation.md`; egress flow analysis in `network-flow-heuristics-proxyjacking.md`. Measurements are from 2026-10-31 in this sandbox; nothing was installed and no firewall or sysctl state changed.

## Summary

- The free, keyless outside-in lookup is **Shodan InternetDB**, `https://internetdb.shodan.io/<IP>` → `ip`, `ports`, `hostnames`, `cpes`, `tags`, `vulns`. Measured for `8.8.8.8`: `ports:[53,443]`, `hostnames:["flowlink-dashboard…scania.com","dns.google"]`. The **keyed API needs a paid Membership** — "one-time payment of $49 for lifetime account upgrade" (<https://help.shodan.io/developer-fundamentals/looking-up-ip-info>).
- **Censys's current Platform API is `https://api.platform.censys.io/v3/global/`, host lookup `GET /v3/global/asset/host/{ip}`**, with `Authorization: Bearer censys_…` and `Accept: application/vnd.censys.api.v3.host.v1+json`; it supersedes the legacy `/api/v2/hosts/{ip}`. Free tier = **100 credits/month, five free actions/day**, 1 credit per entity lookup (<https://docs.censys.com/reference/get-started>, <https://docs.censys.com/docs/platform-credits-free-starter>).
- **CT is the cheapest way to find hostnames you forgot you had**, but `https://crt.sh/?q=%25.example.com&output=json&exclude=expired` **returns 502 under load** — I got a 502 on the first call, HTTP 200 after `sleep 4`.
- **Passive DNS at mnemonic answers "which domains point at my IP" keyless**: `https://api.mnemonic.no/pdns/v3/<IP>` returned `count:1000` with `query`/`answer`/`rrtype`/`times`.
- **`endlessh` is in Debian trixie as 1.1-5.1** (defaults `Delay 10000`, `MaxLineLength 32`, `MaxClients 4096`, `Port 2222`); **Cowrie is not packaged in Debian at all** (all-suite search: "no results").
- **`chattr +i` is a write tripwire, not a read tripwire** — it blocks write/delete/rename/link but not reads, so it cannot detect credential theft.
- **`systemd.path` disarms itself after its burst limit**: `TriggerLimitIntervalSec=` defaults `2s`, `TriggerLimitBurst=` `200`, and on trip "the unit is placed into a failure mode, and will not watch the paths anymore until restarted" (<https://www.freedesktop.org/software/systemd/man/latest/systemd.path.html>).
- **Alerting is one `curl`**: `curl -d "msg" ntfy.sh/<topic>` needs no signup, and `https://hc-ping.com/<uuid>` supplies the *absence* signal no in-band alert can.

## 1. Outside-in: a snapshot of your own IP

### 1.1 Free first — InternetDB

```bash
IP=203.0.113.10
curl -s "https://internetdb.shodan.io/$IP" | python3 -m json.tool
```

Keys are `cpes`, `hostnames`, `ip`, `ports`, `tags`, `vulns` (<https://internetdb.shodan.io/>). Documented as 1 req/sec; commercial use needs a paid plan (unverified). Loop with `sleep 1`.

### 1.2 Shodan keyed API

```bash
curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY&minify=true" | python3 -m json.tool
curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY&history=true"
curl -s "https://api.shodan.io/dns/reverse?ips=$IP&key=$SHODAN_KEY"
curl -s "https://api.shodan.io/api-info?key=$SHODAN_KEY"     # plan + remaining credits
```

`history=true` returns "a list of **all the banners that were ever seen**" — how you date the moment a service appeared. Without a key the API answers HTTP 401 (measured). All plans are limited to 1 request/second (<https://developer.shodan.io/api/requirements>, unverified — did not load); only **Corporate** does bulk lookups. Shodan **Monitor** watches CIDR networks, domains or raw queries continuously and flags changes, including "shadow IT; i.e. services that belong to you but aren't yet known by your IT department" (<https://help.shodan.io/shodan-monitor/network-vs-domain-vs-query>).

### 1.3 Censys Platform API

```bash
curl -s "https://api.platform.censys.io/v3/global/asset/host/$IP" \
  -H "Authorization: Bearer $CENSYS_TOKEN" \
  -H "Accept: application/vnd.censys.api.v3.host.v1+json" \
  -H "X-Organization-ID: $CENSYS_ORG_ID" | python3 -m json.tool
```

Base URLs by API set: `https://api.platform.censys.io/v3/global/`, `/v3/threat-hunting/`, `/v3/collections/`, `/v3/accounts/`. Rate limiting is a leaky bucket "smoothed to one request every 40ms" (~25 rps), burst 125, HTTP 503 on excess.

### 1.4 Diff outside against inside

The difference is the finding: `ss -Hltn | awk '{print $4}' | sed 's/.*://' | sort -n -u > /tmp/local-tcp.txt`, the same port list from InternetDB into `/tmp/ext-tcp.txt`, then `diff /tmp/local-tcp.txt /tmp/ext-tcp.txt`.

Only in `ext-tcp.txt` → stale scan, NAT/load-balancer in front, or a listener in another netns. Only in `local-tcp.txt` → firewalled, or not rescanned. A port being open says nothing about *which* vhost answered: `openssl s_client -connect "$IP:443" -servername example.com | openssl x509 -noout -subject -ext subjectAltName`.

### 1.5 Reverse DNS and the neighbourhood

`dig`, `host` and `nslookup` are often absent (none installed here), so use DoH JSON:

```bash
curl -s "https://dns.google/resolve?name=10.113.0.203.in-addr.arpa&type=PTR" \
  | python3 -c 'import json,sys;print([a["data"] for a in json.load(sys.stdin).get("Answer",[])])'
# ["dns.google."]   (measured for 8.8.8.8)
```

A PTR naming a service you do not run is provider squatting or a previous tenant's leftover.

### 1.6 ASN and prefix without BGP tools

```bash
REV=10.113.0.203
curl -s "https://dns.google/resolve?name=$REV.origin.asn.cymru.com&type=TXT" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["Answer"][0]["data"])'
# 15169 | 8.8.8.0/24 | US | arin | 2023-12-28          (measured)
```

Format is `ASN | prefix | CC | registry | allocation date`; `AS15169.asn.cymru.com` instead adds the holder name (measured `15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US`). IPv6 uses `origin6` with a nibble-reversed address — an IPv4 address there returns NXDOMAIN (`Status: 3`, measured), easy to misread as "not announced".

## 2. Certificate sprawl and CT

```bash
for i in 1 2 3 4 5; do
  curl -sf "https://crt.sh/?q=%25.example.com&output=json&exclude=expired" -o /tmp/ct.json && break
  sleep $((i * 5))
done
python3 -c '
import json
for r in json.load(open("/tmp/ct.json")):
    for n in set(r["name_value"].split("\n")):
        print(r["not_after"][:10], n.strip().lower())' | sort -u
```

Traps: `name_value` is **newline-separated** and carries both precertificate and leaf, so dedupe. A wildcard needs `%` as `%25` because `%` is the SQL LIKE wildcard. And **crt.sh 502s under load** — reproduced here (150-byte nginx 502 page, then HTTP 200 after `sleep 4`); a script treating 502 as "no certificates" lies to you.

Keyless second source: `https://api.certspotter.com/v1/issuances?domain=…&include_subdomains=true&expand=dns_names` returns an array of `id`, `tbs_sha256`, `cert_sha256`, `dns_names[]`, `issuer`; `expand=dns_names` flattens certificates into names. Google's log list is the coverage baseline — measured 2026-10-31 as `version 95.17`, 11 operators, 26 logs (<https://www.gstatic.com/ct/log_list/v3/log_list.json>).

**The actual detection** — keep CT names that resolve to you but are not in your inventory:

```bash
python3 -c '
import json, socket
own = {"203.0.113.10"}
for r in json.load(open("/tmp/ct.json")):
    for n in set(r["name_value"].split("\n")):
        n = n.strip().lstrip("*.").lower()
        try:
            if {i[4][0] for i in socket.getaddrinfo(n, 80)} & own: print("HIT", n)
        except OSError: pass'
```

Unrecognised names landing on your IP are the shadow-service signal: a forgotten staging vhost, a contractor dashboard, or someone else's certificate covering your address.

## 3. Passive DNS

CT catches names from certificates; passive DNS catches names from *resolution history*, including plain HTTP and internal naming. The free endpoint is `https://api.mnemonic.no/pdns/v3/<IP>?limit=100`:

```bash
curl -s "https://api.mnemonic.no/pdns/v3/$IP?limit=100" | python3 -c '
import json,sys; d=json.load(sys.stdin); print("total:", d["count"])
[print(x["rrtype"], x["query"], "->", x["answer"], "seen", x["times"]) for x in d["data"]]'
```

Rows carry `lastUpdatedTimestamp` (epoch **milliseconds**), `times`, `query`, `answer`, `rrtype`, `flags` (`partialResult`). Keyless, no quota published. `count` is the total, not the page: a `limit=3` call still reported `count: 1000` — the signature of a shared address.

## 4. Blocklists, briefly

Full taxonomy in `tor-exit-relays-and-IP-reputation.md`; here only the no-`dig` query form:

```bash
curl -s "https://dns.google/resolve?name=$REV.zen.dq.spamhaus.net&type=A"
```

Do **not** trust that through a public resolver: it yields `127.255.255.254` ("query via public/open resolver"), an error, not a listing. Use your own resolver or the DQS API with a query key.

```bash
curl -s -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=$IP" --data-urlencode "maxAgeInDays=90" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json"
```

Response fields: `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`, `isTor`. Free tier: **1,000 Check/Report per day, 100 block checks/day** (<https://www.abuseipdb.com/pricing>).

## 5. Catching the entry

### 5.1 endlessh — SSH tarpit, ships with Debian

```bash
apt-get install endlessh        # Debian trixie: endlessh 1.1-5.1
```

Usage: `endlessh [-vhs] [-d MS] [-f CONFIG] [-l LEN] [-m LIMIT] [-p PORT]` — `-4`/`-6` restrict address family, `-d` delay [10000 ms], `-f` config [/etc/endlessh/config], `-l` max line length (3-255) [32], `-m` max clients [4096], `-p` port [2222], `-s` syslog, `-v` verbose (repeatable).

Minimal `/etc/endlessh/config`: `Port 2222`, `Delay 10000`, `MaxLineLength 32`, `MaxClients 128`.

```bash
endlessh -f /etc/endlessh/config -s
kill -USR1 "$(pidof endlessh)"     # dump connection stats
kill -HUP  "$(pidof endlessh)"     # reload config
```

**Argument order matters**: the config is parsed when `-f` is processed, so flags *before* `-f` are overridden by it. The Debian unit is hardened (`PrivateTmp=`, `ProtectSystem=full`, `NoNewPrivileges=`, `MemoryDenyWriteExecute=`). Payoff: a connect to the tarpit is unambiguously a scanner, so any auth attempt against the real sshd port from that source is unambiguously targeted.

### 5.2 Cowrie — when you want what they typed

Not in Debian; PyPI only. `pyproject.toml` declares `requires-python = ">=3.11, <4"`.

```bash
python3 -m venv ~/cowrie-env && . ~/cowrie-env/bin/activate
python3 -m pip install --upgrade pip && python3 -m pip install cowrie
mkdir -p /opt/cowrie && cd /opt/cowrie
cowrie init            # non-idempotent: refuses with non-zero exit if etc/cowrie.cfg exists
cowrie start
```

`cowrie.cfg` merges *over* `cowrie.cfg.dist`, so write only what you change:

```ini
# /opt/cowrie/etc/cowrie.cfg
[honeypot]
hostname = srv01

[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
```

`listen_endpoints = tcp:2222:interface=0.0.0.0` and both `[output_jsonlog]` keys are shipping defaults (also `tcp6:…`, and a `haproxy:` prefix behind a PROXY-protocol LB); lines land in `var/log/cowrie/cowrie.json`. Output modules include `telegram`, `slack`, `abuseipdb`, `hpfeeds3`, `misp`. Event IDs: `cowrie.session.connect`, `cowrie.client.version`, `cowrie.login.failed`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.file_download`, `cowrie.session.closed` (<https://docs.cowrie.org/en/latest/OUTPUT.html>).

Filter `var/log/cowrie/cowrie.json` for the two event IDs that matter — `cowrie.login.success` and `cowrie.session.file_download` — and POST each match's `eventid`/`session`/`src_ip`/`username` to ntfy with `curl`.

`cowrie.login.success` on a honeypot means an attacker's pair worked against a fake — the highest-signal line in the file.

### 5.3 Canarytokens — cheapest tripwire that exists

Free, email alerts, no agent. Types: **web bug** (any HTTP request to the token URL fires — put it in a config file, a wiki page, `.git/config`), **DNS** (any resolution fires), plus AWS keys, fake files, Office docs, MySQL, QR (<https://canarytokens.org/nest/>). Self-host via `thinkst/canarytokens-docker`.

The DNS token doubles as an exfil detector — query format `<b32>.<b32>.G<2-random-digits>.<dns-token>`. Base32 the payload, strip `=` padding; the hostname caps at **253 bytes**, so ~**125 raw bytes** per query, and non-UTF-8 decodes come back hexlified (<https://docs.canarytokens.org/guide/dns-token.html>).

```bash
python3 -c 'import base64;print(base64.b32encode(b"test-payload").rstrip(b"=").decode().lower())'
# then: https://dns.google/resolve?name=<that>.G42.<your-token-host>&type=A
```

**Fake credentials.** Put a plausible, *unused* secret where an intruder looks in the first five minutes: `.aws/credentials` with a tokenised key, an `id_rsa` that is a canarytoken fake key, `.env` with `DB_PASSWORD=`. Cowrie ships `src/cowrie/data/etc/userdb.example`. It must never be read by a legitimate process, or you have built a false-positive generator.

## 6. Filesystem tripwires

### 6.1 `chattr +i`

```bash
chattr +i /srv/canary/notes.txt && lsattr /srv/canary/notes.txt
chattr -i /srv/canary/notes.txt
```

chattr(1): with `i` the file "cannot be modified: it cannot be deleted or renamed, no link can be created to this file, most of the file's metadata can not be modified, and the file can not be opened in write mode", and only a process with `CAP_LINUX_IMMUTABLE` can set or clear it (<https://man7.org/linux/man-pages/man1/chattr.1.html>). It **stops writes, not reads** — a tamper detector, not a theft detector, and root can `chattr -i` it anyway. Do **not** use `atime`: the kernel defaults to `relatime`, where access time "is always updated if it is more than 1 day old" (mount(8)), so a same-day read leaves no trace.

### 6.2 `systemd.path` — ships with the distro, two traps

```ini
# /etc/systemd/system/canary.path
[Path]
PathModified=/srv/canary/credentials.txt
Unit=canary-alert.service

[Install]
WantedBy=paths.target
```

The companion `canary-alert.service` is `Type=oneshot` with `ExecStart=/usr/local/bin/alert.sh`.

```bash
systemctl daemon-reload && systemctl enable --now canary.path
systemctl status canary.path          # look for "failed"
```

Directives: `PathExists=`, `PathExistsGlob=`, `PathChanged=`, `PathModified=`, `DirectoryNotEmpty=`, `Unit=`. `PathChanged=` fires when a file "which was open for writing gets closed" (one event per editor save); `PathModified=` "is similar, but additionally … on simple writes" (catches `>>`); `PathExists=` fires **immediately** if the path already exists at activation, so use it to assert "this marker must never exist".

**Trap 1 — burst limit.** `TriggerLimitIntervalSec=` defaults `2s`, `TriggerLimitBurst=` `200`; exceeding it puts the unit "into a failure mode, and [it] will not watch the paths anymore until restarted", so a busy directory silently disarms your watch. Set `TriggerLimitIntervalSec=0` to disable. **Trap 2 — silence looks like safety.** A tripped limit yields a *failed unit*, not an alert, so poll `systemctl is-failed canary.path`.

### 6.3 `auditd` for read detection

`auditctl -w path` is deprecated: "The `-w` form of writing watches is for backwards compatibility and is deprecated due to poor system performance". The syscall form, which also gives read detection (unlike `chattr`):

```bash
auditctl -a always,exit -F path=/srv/canary/credentials.txt -F perm=r -k canary_read
ausearch -k canary_read -i
```

`perm=r` triggers on read, `perm=wa` on write/attribute-change. Persist into `/etc/audit/rules.d/canary.rules` rather than re-running `auditctl` at boot.

## 7. Alerting without a SIEM

```bash
curl -d "canary read on srv01 $(date -Is)" https://ntfy.sh/CHANGEME-long-random-topic
curl -fsS -m 10 --retry 5 -o /dev/null https://hc-ping.com/CHANGEME-UUID
curl -fsS -m 10 --retry 5 -o /dev/null https://hc-ping.com/CHANGEME-UUID/fail
```

Telegram and mail are the same shape — `curl -s "https://api.telegram.org/bot$TG/sendMessage" -d chat_id=$CHAT -d text=$MSG`, or `logger -p user.alert`. ntfy: "the topic is essentially a password, so pick something that's not easily guessable" — anyone who learns it can read *and* inject (<https://docs.ntfy.sh/publish/>). healthchecks.io: don't ping "more than 5 times per minute"; `/start`, `/fail` and `/<uuid>/<exit-status>` are distinct paths (<https://healthchecks.io/docs/http_api/>).

```ini
# /etc/systemd/system/notify@.service
[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsS -m 10 -d "unit %i failed on %H" https://ntfy.sh/CHANGEME-topic
```

Add `OnFailure=notify@%n.service` to `[Unit]` of the canary, Cowrie and endlessh units — that closes trap 2, because a disarmed `systemd.path` now generates a push. **Every watcher pings healthchecks.io on success and posts to ntfy on trigger**: missing pings mean the watcher died, a push means something fired.

## 8. Detection recipe, cheapest first

Each step stands alone. *FP:* names the false-positive mode.

0. **Free outside-in snapshot (~2 min).** InternetDB, Cymru via DoH, one PTR; commit the baseline. *FP:* InternetDB can be weeks stale, and on shared NAT/CGNAT/cloud LB you see other tenants' ports — check the Cymru prefix first and discard the snapshot if it is not yours.
1. **Diff outside vs inside (~3 min).** `ss -Hltn` against InternetDB `ports`. *FP:* CDN/WAF fronting means the IP you queried is not the origin; a listener in another netns is invisible to both sides.
2. **Blocklist self-check (~2 min).** AbuseIPDB `check`; Spamhaus DQS via your own resolver. *FP:* a public-resolver query returns `127.255.255.x` — an error, never a listing.
3. **CT sweep, quarterly (~10 min).** crt.sh with `%25` and a retry loop; Cert Spotter second. Resolve every name, keep what lands on your IPs. *FP:* 502 read as "empty"; precert/leaf duplicates; a customer's cert legitimately covering you.
4. **Passive DNS sweep (~5 min).** mnemonic `pdns/v3/$IP`. *FP:* a `count` in the thousands with `flags: partialResult` means a shared address — the names belong to the address, not to you.
5. **endlessh on an unused port (~5 min).** Baseline the rate for a week first. *FP:* scanner radiation is constant — alert on *change*, never on the first connection.
6. **Canarytokens: web bug + DNS token (~10 min).** Web bug in a file only a human opens; DNS token in a fake `.env`. *FP:* your own crawler, backup indexer, AV URL scanner and mail-gateway link detonation all fetch URLs — exclude by source IP.
7. **Cowrie on a second port (~30 min).** Alert only on `cowrie.login.success` and `cowrie.session.file_download`. *FP:* credential-stuffing bots occasionally "succeed" against the deliberately weak fake account — expected, and why it must exist nowhere real.
8. **`auditd` read rule + `systemd.path` watch on canaries (~20 min).** *FP:* `perm=r` fires on `stat`-driven reads by backup tools; `PathModified=` fires on `chmod`; `PathExists=` fires on activation; a tripped `TriggerLimitBurst` disarms the unit silently.
9. **Deadman's switch per watcher (~5 min).** healthchecks.io ping from each cron/unit, `/fail` on error. It catches failure of steps 5–8 and works even when the box cannot alert in-band.

## Sources

- Shodan: <https://internetdb.shodan.io/>; <https://internetdb.shodan.io/docs>; <https://help.shodan.io/developer-fundamentals/looking-up-ip-info>; <https://developer.shodan.io/api>; <https://developer.shodan.io/api/requirements>; <https://www.shodan.io/pricing>; <https://help.shodan.io/shodan-monitor/network-vs-domain-vs-query>
- Censys: <https://docs.censys.com/reference/get-started>; <https://docs.censys.com/docs/platform-credits-free-starter>; <https://docs.censys.com/docs/platform-api-transition-guide>
- CT and DNS: <https://crt.sh/>; <https://api.certspotter.com/v1/issuances>; <https://www.gstatic.com/ct/log_list/v3/log_list.json>; <https://api.mnemonic.no/pdns/v3/>; <https://dns.google/resolve>, <https://cloudflare-dns.com/dns-query>; Team Cymru TXT `<rev>.origin.asn.cymru.com`, `AS<n>.asn.cymru.com`, `<rev6>.origin6.asn.cymru.com`
- Reputation: <https://www.abuseipdb.com/pricing>; <https://docs.abuseipdb.com/>; <https://www.spamhaus.org/resource-hub/dnsbl/spamhaus-dnsbl-return-codes-technical-update>
- endlessh: <https://github.com/skeeto/endlessh>; <https://packages.debian.org/trixie/endlessh>
- Cowrie: <https://docs.cowrie.org/en/latest/INSTALL.html>; <https://docs.cowrie.org/en/latest/FAQ.html>; <https://docs.cowrie.org/en/latest/OUTPUT.html>; <https://github.com/cowrie/cowrie/blob/main/src/cowrie/data/etc/cowrie.cfg.dist>; <https://github.com/cowrie/cowrie/blob/main/pyproject.toml>; <https://packages.debian.org/search?keywords=cowrie&searchon=names&suite=all&section=all>
- Canarytokens: <https://canarytokens.org/nest/>; <https://docs.canarytokens.org/guide/dns-token.html>; <https://github.com/thinkst/canarytokens-docker>
- Local: <https://man7.org/linux/man-pages/man1/chattr.1.html>; <https://man7.org/linux/man-pages/man8/mount.8.html>; <https://man7.org/linux/man-pages/man8/auditctl.8.html>; <https://www.freedesktop.org/software/systemd/man/latest/systemd.path.html>
- Alerting: <https://docs.ntfy.sh/publish/>; <https://healthchecks.io/docs/http_api/>

## What I could not verify

- **Shodan pricing above the $49 membership.** `https://www.shodan.io/pricing` is JS-rendered and returned no currency amounts; the $1,099/mo Corporate figure and the $59/$99/$299 tiers are unverified.
- **The 1 request/second API limit as a documented statement.** `developer.shodan.io/api/requirements` did not load and `help.shodan.io/the-basics/rate-limits` returns an explicit 404. Only 401-without-key was confirmed live.
- **Shodan Monitor free-tier asset limits** — not stated on any page that loaded. **InternetDB's exact rate limit and commercial-use wording** — `internetdb.shodan.io/docs` did not render.
- **Censys Free's per-account request rate and the legacy `/api/v2/hosts/{ip}` path.** 25 rps is documented generally; a smaller Free bucket is unstated, and I did not call the v2 path without credentials.
- **The systemd version that introduced `TriggerLimitIntervalSec`/`TriggerLimitBurst`** (commonly cited as 250) — the man page documents behaviour, not the version, and no systemd is installed here. Likewise `fs.inotify.max_user_watches`: I measured `524288` here, a distro sysctl default, not a kernel constant.
- **canarytokens.org's alert retention, delivery and rate limits** — not published on the pages I could read.
- **Whether crt.sh publishes a rate limit or backoff guidance.** The 502 is reproducible but no policy is documented; the retry loop above is mine.

# Tor Exit Relays and IP Reputation: What a Cloud Address Publishes, Which Lists It Lands On, and How to Audit Your Own IP From Outside

> **Hardened 2026-11-01 — adversarial review: D39, D42, D43.** The bulk exit list is IPv4-only, so an IPv6-only exit is unlisted; `checks/external-vantage.sh` now queries both families. RDAP abuse extraction has a fallback chain when the object has no `abuse-c`. Reputation is a lagging indicator that account churn is designed to outrun.
> The corrected checks and the residual bypasses are in
> [HARDENING.md](../HARDENING.md). Read that before relying on the commands below.

This file covers one slice: the server that becomes a Tor relay or exit, the public record that act creates (Onionoo, the bulk exit list, `check.torproject.org`), and the blocklists that a cloud IP accumulates independently of Tor (Spamhaus ZEN/SBL/XBL/CSS/PBL/DROP, SpamCop SCBL, CINS, Emerging Threats, AbuseIPDB), plus RIR/RDAP abuse-contact lookup. The emphasis is on what each source's API actually returns, how long each listing survives, and which checks an operator can run on their own box in under a minute. All live measurements below were taken 2026-10-31 from this sandbox; numbers are marked where I measured them.

## Summary

- **`check.torproject.org/api/ip` is the cheapest external verdict**: JSON `{"IsTor":bool,"IP":"a.b.c.d"}` for the caller's egress. Measured: `{"IsTor":false,"IP":"38.25.151.89"}`.
- **Onionoo `search=<ip>` is the authoritative "am I an exit" query** and it searches both `or_addresses` and `exit_addresses`; `exit_addresses` is documented as "IPv4 addresses that the relay used to exit to the Internet in the past 24 hours", so a relay that stopped exiting lingers for up to a day (<https://metrics.torproject.org/onionoo.html>).
- **Measured 2026-10-31: 2,893 relays carried the `Exit` flag, mapping to 1,225 unique exit addresses across 62 countries and 235 ASNs; `torbulkexitlist` returned 1,225 bare IPv4 lines and zero IPv6.**
- **The DNS exit list that Tor's 2020 blog describes (`127.0.0.2` + TXT fingerprint at `ip-port.exitlist.torproject.org`) no longer resolves** — `exitlist.torproject.org` returns NXDOMAIN/NODATA at the zone level (measured via two resolvers). Do not build on it.
- **Spamhaus cannot be queried through a public resolver.** `2.0.0.127.zen.spamhaus.org` — the RFC 5782 test point — returned `127.255.255.254` from Cloudflare DoH and NXDOMAIN from Google DoH. `127.255.255.254` is Spamhaus's *error* code for "query via public/open resolver", not a listing (<https://www.spamhaus.org/resource-hub/dnsbl/spamhaus-dnsbl-return-codes-technical-update>).
- **XBL is the list a proxyjacked cloud box lands on**, and Spamhaus names the exact mechanism: `"Free VPN" type applications using the customer device as a proxy to do network activity on behalf of other unknown people` (<https://www.spamhaus.org/blocklists/exploits-blocklist/>).
- **Persistence is asymmetric**: SpamCop delists 24 h after the last report; AbuseIPDB decays scores daily with a 25 % floor; XBL "automatically expire[s] after a period of time"; SBL is removed only by the network owner after the cause is fixed; DROP churns daily by design.
- **AbuseIPDB free tier is 1,000 check/report requests per day**, score is `ln(distinct reporters)` decayed over time, report window default 30 days, max 365 (<https://www.abuseipdb.com/pricing>, <https://www.abuseipdb.com/faq.html>).
- **DROP is a firewall list, not a mail list**: measured 1,757 networks in `drop_v4.json`, NDJSON with `cidr`/`sblid`/`rir`, refreshed "on a daily basis".
- **RDAP gives you the abuse desk without WHOIS scraping**: IANA bootstrap at `data.iana.org/rdap/ipv4.json`, abuse contact = entity with role `abuse`. Measured: `104.248.1.2` → `abuse@digitalocean.com`; `171.25.193.25` (netname `SE-TORNET`) had no abuse entity at all — a real false-negative.

## 1. What running an exit actually publishes

A relay's public footprint is its server descriptor, mirrored into Onionoo. Minimum torrc that produces an exit (flags verified against `tor(1)`, <https://gitlab.torproject.org/tpo/core/tor/-/raw/main/doc/man/tor.1.txt>):

```
Nickname        myrelay
ContactInfo     tor-admin@example.net
ORPort          9001
ExitRelay       1
ExitPolicy      accept *:80
ExitPolicy      accept *:443
ExitPolicy      reject *:*
```

Facts that matter for identification:

- `ExitRelay auto` (the default) behaves as `1` if any of `ExitPolicy`, `ReducedExitPolicy`, `IPv6Exit` is set, else `0`. So merely writing an `ExitPolicy` makes you an exit.
- The default exit policy is `reject *:25, *:119, *:135-139, *:445, *:563, *:1214, *:4661-4666, *:6346-6429, *:6699, *:6881-6999` then `accept *:*` — BitTorrent (6881-6999) and Gnutella (6346-6429) are blocked out of the box, which is why "Tor exit" traffic never looks like a torrent swarm unless the operator widened the policy (<https://support.torproject.org/relays/running/default-exit-ports/>).
- `ContactInfo` "must be set to a working address if you run more than one relay or bridge".
- The Tor Project's own advice for exits is to set a PTR containing `tor-exit` and to "use a domain name that you own. Definitely do not use `torproject.org`" (<https://community.torproject.org/relay/setup/exit/>). Reverse DNS is therefore a first-class external identifier.

Onionoo fields to read: `or_addresses` (onion-routing addresses used in the last 24 h), `exit_addresses` (IPv4 used to exit in the last 24 h), `flags`, `as`/`as_name`, `country`, `exit_policy_summary`, `host_name` (PTR, "updated at most once in 12 hours").

## 2. Mechanisms that put a cloud IP on a list

| List | Trigger | Cloud relevance |
|---|---|---|
| XBL (127.0.0.4) | "compelling evidence that suggests that a machine … is insecure, compromised, or infected"; explicitly includes "Free VPN type applications using the customer device as a proxy" | Highest — a squatting proxy or a leaked SOCKS5 listener is exactly this |
| SBL (127.0.0.2) | spam, snowshoe, malicious hosting, bulletproof hosting, hijacked space | Lower, but SBL *escalates*: "to that entire network or networks related by ASN or RIR assignment" if the host ignores notices |
| CSS (127.0.0.3) | SMTP-only, port 25 detections, snowshoe and compromised CMS | Only if port 25 egress exists; Tor's default policy blocks 25 |
| PBL (127.0.0.10/.11) | policy: end-user ranges that must not send mail directly | Usually *no* — cloud ranges are not end-user ranges; a PBL hit on a cloud IP means the block owner or Spamhaus policy assigned it |
| DROP (127.0.0.9) | netblocks "leased or stolen by professional spam or cyber-crime operations" | Rare, and when it happens the whole /22 or /24 is condemned |
| SCBL | "IP addresses which have transmitted reported email to SpamCop users" | Only with a mail path |
| AbuseIPDB | user reports (brute force, scanning, proxy abuse, web spam…) | High for proxyjacking: SSH brute-force and scanner reports arrive fast |

Spamhaus publishes sizes so you can judge blast radius: SBL "30-40 thousand listings"; CSS "2 and 4 million listings, with 300,000 to 400,000 new listings added every 24 hours"; XBL "on average contains 2 million listings, with 650,000 new detections … every 24 hours"; PBL "more than 1.4 billion IPv4s, corresponding to almost 40% of the routable IPv4 space" (<https://www.spamhaus.org/blocklists/spamhaus-blocklist/>, <https://www.spamhaus.org/blocklists/combined-spam-sources/>, <https://www.spamhaus.org/blocklists/exploits-blocklist/>, <https://www.spamhaus.org/blocklists/policy-blocklist/>). PBL is explicitly not a judgement: "The IPs in this dataset are not necessarily 'bad'".

## 3. Free authoritative "am I a Tor exit" sources

**check.torproject.org** (HTML + undocumented JSON). The page prints `Sorry. You are not using Tor.` plus `Your IP address appears to be: <ip>`. The JSON endpoint is what automation uses:

```
curl -qfsS https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"185.220.101.1"}
```

**Bulk list** — one IPv4 per line, no header, no IPv6:

```
curl -qfsS https://check.torproject.org/torbulkexitlist | grep -Fx "$MYIP"
```

**Onionoo** (JSON, hourly `relays_published`):

```
curl -qfsS "https://onionoo.torproject.org/details?search=$MYIP&fields=nickname,fingerprint,flags,exit_addresses,as,country"
```

An empty answer is an empty array, not an error: `{"version":"8.0", … "relays":[], "bridges":[]}` (HTTP 200 — verified). Per the Onionoo docs, search on an IP covers "all known addresses used for onion routing and for exiting to the Internet", and only the *beginning* of an IP matches, so `?sear.8.96.` returns every relay in 204.8.96.0/24 (verified), while a `/` in the query yields HTTP 400, not the "empty results" the docs promise.

**Retired interfaces.** Tor's 2020 post documents a DNS exit list returning `A 127.0.0.2` plus a `TXT` record with the relay fingerprint, and notes that "queries of the exit list based on exit policy are no longer permitted" (<https://blog.torproject.org/changes-tor-exit-list-service/>). Measured 2026-10-31: `exitlist.torproject.org` SOA/NS → NXDOMAIN with `torproject.org` authority; `*.ip-port.exitlist.torproject.org` → NXDOMAIN. CollecTor still archives the raw TorDNSEL measurements (`metrics.torproject.org/collector.html#type-tordnsel`), the only historical record.

**Deduplication detail**: `exit_addresses` ≠ `or_addresses`. Measured: 1,225 unique exit addresses vs 2,287 unique OR addresses, with only 3 exit IPs absent from the OR set. A relay behind NAT can exit from an address it never listens on.

## 4. DNSBL mechanics, and the resolver trap

RFC 5782 defines the protocol (<https://www.rfc-editor.org/rfc/rfc5782.html>): the query is the IPv4 address with octets reversed, appended to the zone; "IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes"; clients "MUST respect the TTL values and discard expired records". NXDOMAIN and NODATA both mean *not listed*; a positive answer is one or more A records inside `127.0.0.0/8` encoding which sublist matched.

`dig` needs `bind-utils` (RHEL) or `dnsutils`/`bind9-dnsutils` (Debian); `getent` is in glibc and always present:

```
getent ahostsv4 7.113.0.203.zen.spamhaus.org | head -1 | cut -d' ' -f1
dig +short +time=2 +tries=1 7.113.0.203.zen.spamhaus.org A
```

**The trap:** Spamhaus returns `127.255.255.254` when your query arrives via a public/open resolver, `127.255.255.255` on excessive volume, and `127.255.255.250/251` for disabled/illegally used DQS keys; `127.255.255.252` is "typing error in DNSBL name" (<https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html>, <https://www.spamhaus.org/resource-hub/dnsbl/spamhaus-dnsbl-return-codes-technical-update>). Spamhaus's own warning: "any software which does not distinguish response codes … is, unfortunately, already out of date". Measured here with a resolver chain ending at 1.1.1.1:

```
$ getent ahostsv4 2.0.0.127.zen.spamhaus.org
127.255.255.254 STREAM 2.0.0.127.zen.spamhaus.org
```

A parser that treats any answer as "listed" therefore marks *every* queried IP as listed — the failure is total, not partial. Run your own recursor (unbound) on the box, or use DQS with a key.

## 5. Spamhaus: zones, codes, DROP, lifetime

ZEN = SBL + CSS + XBL + PBL in one zone; with ZEN "there is no need … to also query other Spamhaus IP blocklists".

| Code | Meaning (zone `zen`) |
|---|---|
| 127.0.0.2 | SBL |
| 127.0.0.3 | CSS |
| 127.0.0.4 | XBL |
| 127.0.0.9 | DROP (always in addition to SBL) |
| 127.0.0.10 / .11 | PBL, ISP-maintained / Spamhaus-maintained |
| 127.0.0.30 | BCL (botnet controller) |

DROP as a self-check, parseable without `jq` (verified; the file ends with a metadata line that has no `cidr`, hence the guard):

```
curl -qfsSL https://www.spamhaus.org/drop/drop_v4.json | python3 -c '
import sys,json,ipaddress
ip=ipaddress.ip_address("2.56.192.5")
for l in sys.stdin:
    d=json.loads(l)
    if "cidr" in d and ip in ipaddress.ip_network(d["cidr"]):
        print("DROP:",d["cidr"],d["sblid"],d["rir"])'
# DROP: 2.56.192.0/22 SBL459831 ripencc
```

Format from the same fetch: `{"cidr":"…","sblid":"SBL…","rir":"apnic|ripencc|arin|afrinic|lacnic"}`; metadata record `{"type":"metadata","records":1757,…}`. Measured: arin 716, ripencc 539, apnic 370, afrinic 83, lacnic 49. eDROP was merged into DROP on **10 April 2024** because IPv4 exhaustion made the allocation-based split meaningless (<https://www.spamhaus.org/resource-hub/network-security/spamhaus-drop-and-edrop-to-become-a-single-list>).

Lifetime: SBL removal is owner-driven — "It is the network owner's responsibility to notify Spamhaus … and to request removal when the conditions that caused the SBL listing no longer apply", and only the hosting company can request it (<https://www.spamhaus.org/blocklists/spamhaus-blocklist/>). XBL "will automatically expire after a period of time once the malicious behavior is no longer detected" (no duration published). DROP "change[s] on a daily basis". SBL also carries informational (non-blocking) listings that act as an early warning.

## 6. SpamCop, CINS, Emerging Threats, AbuseIPDB

**SpamCop SCBL** is time-boxed by design: "without any additional reports, a reported address stays on the SCBL for only 24 hours" (<https://www.spamcop.net/fom-serve/cache/297.html>). Its documented test point did not answer: `127.0.0.2.bl.spamcop.net` → NXDOMAIN from Google DoH, Cloudflare DoH, *and* the local stub resolver, while the zone still has an SOA (TTL 0). Treat SCBL as unqueryable/unmaintained in practice; no retirement notice was found.

**CBL is gone.** `www.abuseat.org` now redirects to <https://www.spamhaus.org/blocklists/exploits-blocklist/> (final_url verified), and `cbl.abuseat.org` returns SOA from `hostmaster.spamhaus.org` but no A record for the test point. The CBL's function lives inside XBL now; any tooling still parsing `cbl.abuseat.org` is reading an empty zone.

**CINS / ci-badguys.** `https://cinsscore.com/list/ci-badguys.txt` over HTTPS returned exactly **15,000** lines of IPv4 (looks like a hard cap), plain text, no header. No API, no update-interval documentation.

**Emerging Threats compromised IPs** — free, plain text, no key:

```
curl -qfsSL https://rules.emergingthreats.net/blockrules/compromised-ips.txt | grep -Fx "$MYIP"
```

Measured: **542** lines on 2026-10-31. These are hosts observed *attacking outward* — precisely the signature of a box that has been turned into a proxy/relay.

**AbuseIPDB v2.** Free ("Individual") tier: 1,000 check/report requests per day, and by the same table 100 block checks, 5 bulk reports and 5 blacklist pulls of up to 10,000 IPs per day (<https://www.abuseipdb.com/pricing>).

```
curl -qfsS -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=$MYIP" -d maxAgeInDays=90 -d verbose \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json"
```

Returns `data.abuseConfidenceScore` (0-100), `data.totalReports`, `data.numDistinctUsers`, `data.lastReportedAt`, `data.usageType`, `data.isWhitelisted`, and with `verbose` up to 10,000 report objects. The score is "the natural logarithmic value of distinct user reports", all weights decay, "recalculated daily"; the bulk blacklist applies a floor of 25 % and AbuseIPDB recommends 75-100 % "for denial of service" (<https://docs.abuseipdb.com/>, <https://www.abuseipdb.com/faq.html>). Reporting `127.0.0.2` "will simulate a short term rate limit" — a documented way to test your error handling.

## 7. RIR / RDAP and the abuse contact

Bootstrap per RFC 9224: `https://data.iana.org/rdap/ipv4.json` (also `ipv6.json`, `asns.json`); `https://rdap.org/ip/<ip>` redirects to the right RIR. Roles are defined in RFC 9083; the abuse desk is the entity whose `roles` contains `abuse`:

```
curl -qfsSL "https://rdap.arin.net/registry/ip/104.248.1.2" | python3 -c 'import sys,json
def walk(e):
    if "abuse" in (e.get("roles") or []):
        for it in (e.get("vcardArray") or [None,[None]])[1]:
            if it[0]=="email": print(it[3])
    for c in e.get("entities",[]): walk(c)
walk(json.load(sys.stdin))'
# abuse@digitalocean.com
```

Measured outputs: `104.248.1.2` → `NET-104-248-0-0-1 DIGITALOCEAN-104-248-0-0`, abuse entity `DIGIT19-ARIN` <abuse@digitalocean.com>; `204.8.96.141` (a live exit) → `QUINTEX96`, registrant "Quintex Alliance Consulting"; `171.25.193.25` → RIPE `SE-TORNET`, `ASSIGNED PI`, and **no abuse entity at all**. RIPE models that contact as the `abuse-c`/`abuse-mailbox` attribute, so RDAP may legitimately come back empty; fall back to `abuse@ripe.net` and to the PTR.

## Detection recipe (cheapest first)

1. **Know which egress you are measuring.** `curl -qs https://api.ipify.org`. Measured trap: this box's direct egress is `38.25.151.89`, but fetching the same page through an HTTP proxy showed `172.68.12.222`. An "am I listed" answer describes the IP that reached the service, not the one in `ip addr`.
2. **Tor verdict, 1 request:** `curl -qfsS https://check.torproject.org/api/ip`. Caveat: it sees only that one connection's source IP.
3. **Local bulk match, 0 requests to third parties:** `curl -qfsS https://check.torproject.org/torbulkexitlist | grep -Fx "$MYIP"`. IPv4 only — an IPv6-only exit will not appear (measured: 0 of 1,225 lines contain `:`).
4. **Onionoo for detail:** `?search=$MYIP&fields=nickname,flags,exit_addresses,as,country`. Empty `relays:[]` = not a relay. False positive: `exit_addresses` holds addresses used in the *last 24 h*, so a decommissioned exit shows for up to a day; OR addresses are also 24 h-scoped.
5. **DROP/FW check offline:** the `drop_v4.json` snippet above. Diff it on a schedule; a range listing is a routing decision, not a reputation score.
6. **ET compromised:** `grep -Fx` against `compromised-ips.txt`. False negative: fresh compromises appear only after ET observes outbound attack traffic.
7. **AbuseIPDB once, with a key:** `abuseConfidenceScore` and `numDistinctUsers`. False positive: a score above 0 with `numDistinctUsers=1` is one reporter; the 25 % floor guarantees any single report floors at 25.
8. **DNSBL sweep, only from your own recursor:** for each zone, reverse the octets and look for an A record in `127.0.0.0/8`, then **discard anything in `127.255.255.0/24` as an error**, never a listing; this is the single most common way a self-audit produces a fake positive. Measured on this host: `zen.spamhaus.org → 127.255.255.254`, `bl.spamcop.net → NXDOMAIN`, `dnsbl-1.uceprotect.net → NXDOMAIN`.
9. **Attribute before you act:** RDAP abuse contact (snippet above) plus PTR. False negative: RIPE objects without `abuse-c` return nothing, as measured on `SE-TORNET`.

Provider-side fact worth quoting rather than discovering: Tor's community "Good Bad ISPs" table records OVH/Kimsufi — "Running a Tor exit node is strictly forbidden and can lead to the suspension and even termination of your server and account"; Gcore — "They don't allow exits and will suspend your active services"; Alwyzon — exits "expressively prohibited"; Hetzner — "It is not a Problem, however, abuse reports can lead to a server lock"; Linode — "We allow Tor exits as long as they have a reduced exit policy" (<https://community.torproject.org/relay/community-resources/good-bad-isps/>).

## Sources

- <https://metrics.torproject.org/onionoo.html>
- <https://onionoo.torproject.org/details>
- <https://check.torproject.org/> and <https://check.torproject.org/api/ip>
- <https://check.torproject.org/torbulkexitlist>
- <https://blog.torproject.org/changes-tor-exit-list-service/>
- <https://metrics.torproject.org/collector.html#type-tordnsel>
- <https://community.torproject.org/relay/setup/exit/>
- <https://community.torproject.org/relay/community-resources/good-bad-isps/>
- <https://support.torproject.org/relays/running/default-exit-ports/>
- <https://gitlab.torproject.org/tpo/core/tor/-/raw/main/doc/man/tor.1.txt>
- <https://www.rfc-editor.org/rfc/rfc5782.html>
- <https://www.rfc-editor.org/rfc/rfc9083>
- <https://data.iana.org/rdap/ipv4.json>
- <https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html>
- <https://www.spamhaus.org/resource-hub/dnsbl/spamhaus-dnsbl-return-codes-technical-update>
- <https://www.spamhaus.org/blocklists/spamhaus-blocklist/>
- <https://www.spamhaus.org/blocklists/exploits-blocklist/>
- <https://www.spamhaus.org/blocklists/combined-spam-sources/>
- <https://www.spamhaus.org/blocklists/policy-blocklist/>
- <https://www.spamhaus.org/blocklists/zen-blocklist/>
- <https://www.spamhaus.org/blocklists/do-not-route-or-peer>
- <https://www.spamhaus.org/drop/drop_v4.json>
- <https://www.spamhaus.org/resource-hub/network-security/spamhaus-drop-and-edrop-to-become-a-single-list>
- <https://check.spamhaus.org/>
- <https://www.spamcop.net/fom-serve/cache/297.html>
- <https://www.abuseipdb.com/api>, <https://docs.abuseipdb.com/>, <https://www.abuseipdb.com/faq.html>, <https://www.abuseipdb.com/pricing>
- <https://cinsscore.com/list/ci-badguys.txt>
- <https://rules.emergingthreats.net/blockrules/compromised-ips.txt>
- <https://www.arin.net/resources/registry/whois/rdap/>
- <https://rdap.arin.net/registry/ip/104.248.1.2>, <https://rdap.db.ripe.net/ip/171.25.193.25>

## What I could not verify

- **Spamhaus free-tier daily query volume.** No page states a number for the free DNSBLs; the DQS FAQ is JS-rendered.
- **SBL/XBL delisting durations in hours.** Spamhaus gives mechanisms ("automatically expire after a period of time", owner-requested removal) but no SLA number.
- **Whether `bl.spamcop.net` is formally retired.** The zone answers with an SOA but the RFC 5782 test point returns NXDOMAIN from three independent resolvers; no announcement either way was found.
- **CINS ownership, update cadence, and whether 15,000 is a cap.** The file is served, but no documentation page was reachable.
- **AWS/Azure/GCP terms on Tor exits.** I did not find a quotable clause in any of the three AUPs within scope; the secondary compilation in Tor's "Good Bad ISPs" is the only concrete text I could cite.
- **The full list of Spamhaus error codes.** The docs table truncates at `127.255.255.252`; the enumeration of newer codes (if any) was not retrievable.
- **Onionoo's exact refresh cadence.** `relays_published` was `2026-10-31 07:00:00`; the docs describe hourly publication but I did not find an explicit interval statement.
- **AbuseIPDB's exact decay constants.** "All report weights decay with time" is documented; the half-life is not.

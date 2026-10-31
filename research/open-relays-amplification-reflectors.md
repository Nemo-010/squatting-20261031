# Open Relays and Amplification Reflectors: What Makes a Host Usable, and What It Looks Like From Inside

Scope: a free-tier server gets repurposed with almost no tooling — as an *egress* (SMTP open relay,
HTTP/SOCKS proxy) or as an *amplifier* (DNS, NTP, memcached, chargen, SSDP, CLDAP), where its only
contribution is answering a spoofed UDP packet with a larger one. This file covers the precondition
that makes each usable, the published amplification factors, the provider egress rules that decide
whether a repurposed box can reach port 25, and the cheapest checks an operator can run on their own
host. Numbers carry their source; unconfirmed items are marked **unverified**.

## Summary

- **The two halves fail differently.** SMTP/proxy abuse needs a *listening* service that answers a
  stranger; amplification needs only a *reachable* UDP service that answers an anonymous packet with
  a bigger one. `ss` catches the first; the second is often invisible there because the service is
  supposed to exist.
- **Postfix's default is closed**: `smtpd_relay_restrictions` = `permit_mynetworks,
  permit_sasl_authenticated, defer_unauth_destination` — *defer*, so an unauthorised relay attempt
  gets 4xx, not 5xx; the hole is almost always `mynetworks` widened to a subnet. Exim is stricter
  still — with no RCPT ACL "no SMTP mail can be accepted."
- **Every major free tier blocks outbound 25 by default** — AWS, GCP, Azure, Oracle (tenancies after
  2021-06-23), DigitalOcean (25, 465 *and* 587) — so spam egress moves to 587/465 or HTTPS APIs.
- **Amplification in one line**: DNS 28–54×, SSDP 30.8×, CLDAP 56–70×, CharGen 358.8×, RIPv1
  131.24×, NTP 556.9×, memcached 10,000–51,000× (CISA TA14-017A).
- **memcached UDP is version-gated**: on by default to 1.5.5, **off by default from 1.5.6**.
  Cloudflare measured 15 B → 134 KB, worst case 51,200×.
- **BIND 9.18 caps per-packet DNS amplification** at `edns-udp-size`/`max-udp-size`, both defaulting
  to **1232** bytes without a valid server COOKIE — "100×" belongs to authoritative ANY/DNSKEY
  answers, not to a default recursive resolver.
- **The cheapest amplifier detector needs no packets**: diff `tx_bytes/tx_packets` against
  `rx_bytes/rx_packets`. A reflector shows a large mean TX packet and a tiny mean RX packet.
- **Shadowserver checks all of this from outside, free**, daily, per vector — the only check that sees
  your address the way an attacker does.

## 1. SMTP: open relay, egress block, snowshoe

### 1.1 What makes a mail server a relay

Postfix `postconf(5)`: `smtpd_relay_restrictions` default = `permit_mynetworks,
permit_sasl_authenticated, defer_unauth_destination`
(<https://www.postfix.org/postconf.5.html>). The `defer_` prefix is load-bearing: an unauthorised
`RCPT TO:<x@elsewhere>` returns 450/454, not 554, so scanners report "possible relay" on closed
boxes. Two real paths to an open relay:

1. **`mynetworks` widened.** `mynetworks_style = host` is the default "when `compatibility_level`
   ≥ 2"; `subnet` is the default "when `compatibility_level` < 2", so a config carried forward from
   Postfix 2.x keeps trusting the attached subnet
   (<https://www.postfix.org/BASIC_CONFIGURATION_README.html>). On a cloud instance that subnet is
   the VPC /24; on a Docker host it can include the bridge subnet, so every container relays.
2. **`smtpd_relay_restrictions` emptied** — the pre-2.10 migration path, safe only if
   `smtpd_recipient_restrictions`, the old combined relay+spam list, still polices relay.

Exim's shipped config ends `require message = relay not permitted` / `domains = +local_domains :
+relay_to_domains`
(<https://www.exim.org/exim-html-current/doc/html/spec_html/ch-the_default_configuration_file.html>).

### 1.2 The egress block

| Provider | Default outbound-25 policy | Source |
|---|---|---|
| AWS EC2 | "allows outbound traffic over port 25 only to private IPv4 addresses… blocked to public IPv4 addresses and IPv6 addresses"; removal by request | <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-resource-limits.html> |
| Google Cloud | "connections to destination TCP Port 25 are blocked when the destination is external to your VPC network"; 465/587 unrestricted | <https://docs.cloud.google.com/compute/docs/tutorials/sending-mail> |
| Azure | port 25 blocked except Enterprise Agreement / MCA-E; 587 relay "isn't blocked" | <https://learn.microsoft.com/en-us/azure/virtual-network/troubleshoot-outbound-smtp-connectivity> |
| Oracle Cloud | "Tenancies made after June 23, 2021 are by default not allowed to send e-mail via outbound TCP port 25" | <https://docs.oracle.com/en-us/iaas/releasenotes/changes/f7e95770-9844-43db-916c-6ccbaf2cfe24> |
| DigitalOcean | "SMTP ports 25, 465, and 587 are blocked on Droplets", including via Reserved IP | <https://docs.digitalocean.com/support/why-is-smtp-blocked/> |

### 1.3 Snowshoe

Spamhaus: snowshoe spamming "is a technique used to spread spam output across many IPs and domains
in order to dilute reputation metrics and evade filters"; hailstorm starts "out of the blue" with
no prior traffic (<https://www.spamhaus.org/glossary/>). On your own
box the shape is many recipient domains at one or two messages each, no matching local user,
`sasl_username` absent or belonging to a compromised account, varying `relay=` against a constant
`client=`. Spamhaus's Exploits Blocklist is the outside view — IPs "hijacked to use by third-party
exploits", including "'Free VPN' type applications using the customer device as a proxy"
(<https://www.spamhaus.org/blocklists/exploits-blocklist/>).

## 2. Open HTTP and SOCKS proxies

Squid is closed by default: `http_access` "Default Value: Deny, unless rules exist in squid.conf",
and the shipped configuration ends `http_access deny all` after `deny !Safe_ports`, `deny CONNECT
!SSL_ports`, `deny to_localhost` (<https://www.squid-cache.org/Doc/config/http_access/>). It becomes
open through an operator-added `http_access allow all`, or an `acl localnet src` covering `0.0.0.0/0`.

Population: Shadowserver, which probes for services that will proxy **HTTP CONNECT or HTTP GET** to
`api64.ipify.org` with no authentication, reports "As of 2023-03-30, we identify **68K** open HTTP
proxies" (<https://www.shadowserver.org/what-we-do/network-reporting/open-http-proxy-report>).

More common on a squatted host than misconfigured Squid: `ssh -D` with `GatewayPorts yes`, dante with
`socksmethod: none`, 3proxy, tinyproxy — a listener on 1080/3128/8118/8888/9999 that should not
exist.

**The container trap**: Docker publishes ports in the `nat` table, so "packets are diverted before
it reaches the `INPUT` and `OUTPUT` chains that ufw uses"
(<https://docs.docker.com/engine/network/packet-filtering-firewalls/>) — a proxy bound to `127.0.0.1`
in a container published with `-p 3128:3128` is public, and `ss` shows `docker-proxy`, not `squid`.

## 3. Open DNS resolver

**BIND.** `recursion yes` is default, the client ACL is not: with no `allow-recursion` the server
falls back to `allow-query-cache`, then to `{localnets; localhost;}`
(<https://bind9.readthedocs.io/en/v9.18.24/reference.html>). The open case is `allow-recursion {
any; }`, `allow-query-cache { any; }`, or a `view` widening either; `named-checkconf -p` prints the
effective config including defaults (<https://bind9.readthedocs.io/en/v9.18.24/manpages.html>).

**Unbound.** "Default action for interfaces is refuse. By default only localhost (the 127.0.0.0/8 IP
netblock…) is implicitly allowed", and "the most specific netblock match is used, if none match
refuse is used" (<https://nlnetlabs.nl/documentation/unbound/unbound.conf/>): `interface: 0.0.0.0`
plus `access-control: 0.0.0.0/0 allow` is the open case.

**The norm.** RFC 5358 (BCP 140): "By default, nameservers SHOULD NOT offer recursive service to
external networks"; its recommended set is ACLs, incoming-interface selection, TSIG/SIG(0), and
recursion off on authoritative-only servers (<https://www.rfc-editor.org/rfc/rfc5358.txt>).

**Self-test, one line each, run from inside against your public IP:**

```
dig +short test.openresolver.com TXT @203.0.113.10   # "open-resolver-detected" = open
dig +short @203.0.113.10 dnsscan.shadowserver.org    # Shadowserver's own probe
```

The first is openresolver.com's documented test (<https://www.openresolver.com/>); the second is the
exact query Shadowserver's scanner uses
(<https://www.shadowserver.org/what-we-do/network-reporting/dns-open-resolvers-report>).

**Why the factor is smaller than folklore.** ISC: an EDNS ANY query for `isc.org` is "36 bytes" and
triggers "3,576 bytes… a nearly 100-fold increase" (<https://kb.isc.org/docs/aa-01000>). But BIND
9.18 defaults `edns-udp-size` and `max-udp-size` to **1232**, the latter capping what is sent without
a valid server COOKIE (<https://bind9.readthedocs.io/en/v9.18.24/reference.html>), so a modern
resolver cannot emit multi-kilobyte UDP responses by default.

RRL is a `rate-limit { … }` block (`responses-per-second`, `window`, `slip`, `log-only`) that the ARM
calls "intended for authoritative DNS servers… When possible, closing 'open' recursive servers is
better".

## 4. UDP reflectors

Amplification factors from CISA's alert (per Rossow's *Amplification Hell*):

| Protocol | BAF | Command | Port |
|---|---|---|---|
| DNS | 28–54 | recursive/ANY | 53/udp |
| NTP | 556.9 | `monlist` (mode 6) | 123/udp |
| memcached | 10,000–51,000 | `get` after `set` | 11211/udp |
| CharGen | 358.8 | character generation | 19/udp |
| QOTD | 140.3 | quote request | 17/udp |
| RIPv1 | 131.24 | malformed request | 520/udp |
| CLDAP | 56–70 | anonymous rootDSE | 389/udp |
| LDAP | 46–55 | malformed request | 389 |
| SSDP | 30.8 | M-SEARCH | 1900/udp |
| Portmap/RPCbind | 7–28 | malformed request | 111/udp |

Also on the same list: Quake 63.9 (`26000/udp`), TFTP 60 (`69/udp`), Kad 16.3, WS-Discovery 10–500
(`3702`), SNMPv2 6.3 (`GetBulk`, `161/udp`), Steam 5.5, NetBIOS 3.8 (`137/udp`), BitTorrent 3.8,
mDNS 2–10 (`5353/udp`).

All rows: <https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks>. MITRE
ATT&CK files this as T1498.002, noting memcached "amplification sizes up to 51,200 times the
requesting packet" (<https://attack.mitre.org/techniques/T1498/002/>).

**NTP monlist (CVE-2013-5211).** `monlist` returns "the last 600 IP addresses which connected"; every
ntpd before 4.2.7 is "vulnerable by default" and 4.2.7 removes it. Interim fix, verbatim:

```
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
```

(<https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211>)
`nmap --script ntp-monlist -sU -p123 <ip>` answers "error type 4 (No Data Available) or no reply at
all" when not vulnerable.

**memcached.** "An attacker SETs a large item into an exposed memcached server. Next the attacker
spoofs a GET request with the IP address of the targeted victim"
(<https://docs.memcached.org/advisories/ddos>). UDP framing is 8 header bytes, so the request is tiny
while the response runs to repeated 1400-byte MTUs. Cloudflare: "15 bytes of request triggered
134KB of response… a 15 byte request result in a 750kB response (that's a 51,200x amplification)"
(<https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/>). Version
boundary — that post says "By default memcached listens on INADDR_ANY and runs with UDP support
ENABLED"; 1.5.6 notes say "This is a bugfix release, but it primarily disables the UDP protocol by
default" (<https://raw.githubusercontent.com/wiki/memcached/memcached/ReleaseNotes156.md>); the
current `-U` manual reads "the default is port 0, which is off"
(<https://manpages.debian.org/bookworm/memcached/memcached.1.en.html>). Self-test from that post:

```
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211
```

**CharGen.** RFC 864 defines TCP and UDP services on port 19; the UDP one answers "a random number
(between 0 and 512) of characters" regardless of input
(<https://www.rfc-editor.org/rfc/rfc864.txt>) — the whole 358.8×. Shadowserver probes by "sending a
UDP packet containing a single carriage return to UDP port 19"
(<https://www.shadowserver.org/what-we-do/network-reporting/open-chargen-report>). It exists only
where an inetd/xinetd `chargen` entry was enabled; no systemd distro starts it.

**SSDP / CLDAP / WS-Discovery / portmap** are the same shape on other ports; none is a
vulnerability, each is a service behaving as specified when reachable.

**The precondition, and the sysctl that does not help you.** All of this requires source spoofing,
which RFC 2827 (BCP 38) fixes at the attacker's ISP
(<https://www.rfc-editor.org/rfc/rfc2827.txt>). Your nearest knob is `rp_filter`; strict mode (1)
drops packets whose source is not reachable via the ingress interface, and RFC3704 strict mode is the
"recommended practice… to prevent IP spoofing from DDoS attacks" — but "Default value is 0"
(<https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html>), and it does nothing when the
spoofed victim address is globally routable. The kernel bounds its own ICMP errors (`icmp_ratelimit`
"Default: 1000" ms per target, `icmp_msgs_per_sec` "Default: 10000", mask "6168"), so answering
closed UDP ports with ICMP port-unreachable is a nuisance, not an amplifier.

## 5. Detection recipe: cheapest first

All read-only. `ss`/`ip` ship with iproute2; `conntrack` needs `conntrack` (Debian) or
`conntrack-tools` (RHEL); `dig` needs `dnsutils`/`bind-utils`; `swaks`, `nmap` are extra.

**1. Listening sockets (1 s, no package).**

```
ss -Hlunp     # UDP listeners; state column reads UNCONN for bound UDP
ss -Hltnp     # TCP listeners + owning process
```

Anything on 19, 111, 123, 389, 1900, 3702, 5353, 11211 you did not install is the finding. **False
positive:** `systemd-resolved`/`dnsmasq` bind `127.0.0.53:53`, Docker binds `127.0.0.11:53` — the
address matters, not the port. A `docker-proxy` process means the listener is in a container (§2).

**2. Directional byte/packet ratio (5 s, no package).** A reflector shows a big mean TX packet and a
tiny mean RX packet. This reads the counters via `ip` (verified; works where sysfs is absent, as in
many containers):

```bash
rd(){ ip -s link show eth0 | awk '/RX:/{getline; r=$1; p=$2} /TX:/{getline; t=$1; q=$2} END{print r,p,t,q}'; }
read R0 P0 T0 Q0 <<<"$(rd)"; sleep 5; read R1 P1 T1 Q1 <<<"$(rd)"
awk -v r=$((R1-R0)) -v p=$((P1-P0)) -v t=$((T1-T0)) -v q=$((Q1-Q0)) \
  'BEGIN{printf "rx %.0f B/pkt  tx %.0f B/pkt\n",(p?r/p:0),(q?t/q:0)}'
```

At high packet rates read `/sys/class/net/eth0/statistics/` instead, which skips the netlink dump.
**No published threshold exists** — baseline it. A web server is roughly symmetric; a reflector runs
to 1400 B TX against <100 B RX.

**3. UDP rate and error state (no package).** The `Udp:` line of `/proc/net/snmp` carries the
`UDP_MIB_*` counters in enum order — `InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors
SndbufErrors InCsumErrors IgnoredMulti`, plus `MemErrors` on recent kernels
(<https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/snmp.h>). Verified on a
live host:

```
u(){ awk '/^Udp:/{f=!f; if(f){for(i=2;i<=NF;i++)h[i]=$i} else {for(i=2;i<=NF;i++) printf "%s=%s\n",h[i],$i}}' /proc/net/snmp; }
u >/tmp/u0; sleep 5; u >/tmp/u1
paste /tmp/u0 /tmp/u1 | awk -F'[=\t]' '{d=$4-$2; if(d!=0) printf "%-14s %8.2f /s\n",$1,d/5}'
```

Rising `SndbufErrors`/`RcvbufErrors` mid-burst is an overwhelmed UDP service; climbing `NoPorts`
means you answer closed ports with rate-limited ICMP (§4).

**4. Outbound mail (1 s, no package).** `ss` takes the filter expression directly (syntax verified on
a live host):

```
ss -Htnp state established '( dport = :25 or dport = :587 or dport = :465 )'
```

An outbound session to 25 from a process that is not your MTA is the finding.

**5. Queue and log shape.** `postqueue -p` shows depth and recipients; in `/var/log/mail.log` count
distinct `relay=`/`dsn=` and check `sasl_username` against real accounts. Snowshoe is many domains ×
one message, not one domain × many.

**6. Relay self-test (needs `swaks`, or plain `nc`).** Speak SMTP at your own listener, stopping
before `DATA`:

```
swaks --server 203.0.113.10 --from probe@example.net --to probe@example.org --quit-after RCPT
```

Documented upstream with the same recipe (<https://www.jetmore.org/john/code/swaks/latest/doc/ref.txt>).
250 to a domain you neither host nor relay for = open; 450/454 is the Postfix `defer_` default and
means closed; 554 = closed. `nmap --script smtp-open-relay -p 25,465,587 <ip>` runs 16 hardcoded
MAIL/RCPT combinations (<https://nmap.org/nsedoc/scripts/smtp-open-relay.html>).

**7. conntrack cardinality and table pressure.** `nf_conntrack_udp_timeout` defaults to **30 s** and
`nf_conntrack_udp_timeout_stream` to **120 s**
(<https://www.kernel.org/doc/html/latest/networking/nf_conntrack-sysctl.html>), so a burst shows as
an entry-rate spike. Compare `cat /proc/sys/net/netfilter/nf_conntrack_count` with `nf_conntrack_max`;
overflow logs `nf_conntrack: table full, dropping packet`
(<https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nf_conntrack_core.c>). Drill in
with `conntrack -L -p udp --dport 53 -o extended`
(<https://manpages.debian.org/bookworm/conntrack/conntrack.8.en.html>). **False negative:** with
`nf_conntrack` unloaded the table is absent and the check passes silently; per-flow bytes also need
`nf_conntrack_acct`, off by default.

**8. Packet-level confirmation (last — it costs CPU).**

```
tcpdump -ni any -nn -c 200 'udp and (port 53 or port 123 or port 11211 or port 19 or port 1900 or port 389)'
```

Judge size ratios per source, not payload: a steady 1:20 inbound:outbound byte ratio across thousands
of sources is a reflector in use.

**9. Free external verification.** Shadowserver's per-vector reports — Resolvers, HTTP Proxy,
Memcached, CharGen, SSDP, LDAP, Portmapper, QOTD, mDNS, NetBIOS
(<https://www.shadowserver.org/what-we-do/network-reporting/>). Subscribe once; the report arriving
is the alert.

**10. Container escape check.** `nft list ruleset` (or `iptables -t nat -S`) for `DNAT` rules you did
not write.

### Named false-positive modes

- **53/udp on loopback** (`127.0.0.53`, `127.0.0.11`, `127.0.0.1%lo`) is a stub resolver; §3's test
  must target the public IP.
- **`NoPorts`/ICMP unreachable** is expected on any public host, rate-limited per §4.
- **NTP mode 3 vs mode 6/7**: a client asking the time is normal; only monitoring queries amplify.
- **DHCP, mDNS/Avahi, SSDP from a local daemon, WireGuard keepalives, QUIC**: all UDP, none answers a
  stranger with more bytes than it received.
- **`defer_unauth_destination`** producing 450/454 on a relay probe; **`nf_conntrack_acct=0`**
  zeroing byte counters silently.

## Sources

TA14-017A (BAF table) <https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks> ·
TA14-013A (NTP) <https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211> ·
T1498.002 <https://attack.mitre.org/techniques/T1498/002/> ·
memcrashed <https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/> ·
memcached UDP <https://docs.memcached.org/advisories/ddos> ·
memcached 1.5.6 <https://raw.githubusercontent.com/wiki/memcached/memcached/ReleaseNotes156.md> ·
memcached(1) <https://manpages.debian.org/bookworm/memcached/memcached.1.en.html> ·
RFC 864 <https://www.rfc-editor.org/rfc/rfc864.txt> · RFC 5358 <https://www.rfc-editor.org/rfc/rfc5358.txt> ·
RFC 2827 <https://www.rfc-editor.org/rfc/rfc2827.txt> ·
ISC RRL <https://kb.isc.org/docs/aa-01000> · BIND ARM <https://bind9.readthedocs.io/en/v9.18.24/reference.html> ·
named-checkconf <https://bind9.readthedocs.io/en/v9.18.24/manpages.html> ·
unbound.conf(5) <https://nlnetlabs.nl/documentation/unbound/unbound.conf/> ·
openresolver.com <https://www.openresolver.com/> ·
postconf(5) <https://www.postfix.org/postconf.5.html> ·
Postfix BASIC_CONFIGURATION <https://www.postfix.org/BASIC_CONFIGURATION_README.html> ·
Exim spec <https://www.exim.org/exim-html-current/doc/html/spec_html/ch-the_default_configuration_file.html> ·
Squid http_access <https://www.squid-cache.org/Doc/config/http_access/> ·
swaks ref <https://www.jetmore.org/john/code/swaks/latest/doc/ref.txt> ·
NSE smtp-open-relay <https://nmap.org/nsedoc/scripts/smtp-open-relay.html> ·
NSE ntp-monlist <https://nmap.org/nsedoc/scripts/ntp-monlist.html> ·
Shadowserver <https://www.shadowserver.org/what-we-do/network-reporting/> ·
Shadowserver resolvers <https://www.shadowserver.org/what-we-do/network-reporting/dns-open-resolvers-report> ·
Shadowserver proxy <https://www.shadowserver.org/what-we-do/network-reporting/open-http-proxy-report> ·
Shadowserver chargen <https://www.shadowserver.org/what-we-do/network-reporting/open-chargen-report> ·
Spamhaus glossary <https://www.spamhaus.org/glossary/> ·
Spamhaus XBL <https://www.spamhaus.org/blocklists/exploits-blocklist/> ·
AWS EC2 <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-resource-limits.html> ·
GCP mail <https://docs.cloud.google.com/compute/docs/tutorials/sending-mail> ·
Azure SMTP <https://learn.microsoft.com/en-us/azure/virtual-network/troubleshoot-outbound-smtp-connectivity> ·
Oracle SMTP <https://docs.oracle.com/en-us/iaas/releasenotes/changes/f7e95770-9844-43db-916c-6ccbaf2cfe24> ·
DigitalOcean SMTP <https://docs.digitalocean.com/support/why-is-smtp-blocked/> ·
Docker firewalls <https://docs.docker.com/engine/network/packet-filtering-firewalls/> ·
ip-sysctl <https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html> ·
conntrack sysctl <https://www.kernel.org/doc/html/latest/networking/nf_conntrack-sysctl.html> ·
conntrack core <https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/nf_conntrack_core.c> ·
snmp.h <https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/snmp.h> ·
ss(8) <https://man7.org/linux/man-pages/man8/ss.8.html> ·
conntrack(8) <https://manpages.debian.org/bookworm/conntrack/conntrack.8.en.html> ·
pcap-filter(7) <https://www.tcpdump.org/manpages/pcap-filter.7.html>

## What I could not verify

- **No primary source for the widely repeated "206×" NTP figure.** TA14-017A lists 556.9×; 206× could
  not be traced to Rossow's paper or a vendor document, so it is unused here.
- **When `UDP_MIB_MEMERRORS` was added.** The live host (Linux 7.2.11) prints nine UDP columns; the
  commit adding `MemErrors` was not found, and `IgnoredMulti` is likewise undated.
- **`nf_conntrack_max` on a given distro.** The doc says only that it "is set to `nf_conntrack_buckets`
  by default"; the factor varies with RAM, so read it.
- **No published PPS or bytes-per-packet threshold for "you are being used as a reflector".** Every
  number in §5.2 is a baseline you set.
- **Port-25 policy for Hetzner, Contabo, OVH, Scaleway** was not retrieved; §1.2 covers five providers.
  Nor does Shadowserver publish a hosting-provider breakdown of open resolvers/relays on free tiers,
  only aggregate per-vector counts (68K open HTTP proxies as of 2023-03-30).
- **Whether `defer_unauth_destination` yields 450 or 454** in a given build — both appear in the wild;
  the point (4xx, not 5xx) holds either way.

# Destination allowlists: when every capability in the kernel buys nothing

> **First-hand, measured 2026-11-02.** The same rented container sandbox as
> [container-storage-and-quota-escapes.md](container-storage-and-quota-escapes.md), from inside the
> tenant's own container. **VendorD** again; addresses are placeholders.
>
> The sandbox held every capability, a TUN device, working nftables DNAT and `ip_forward=1`. None of it
> was usable, because the only destinations it would talk to were package registries. Capability is not
> reachability, and this corpus has been treating them as the same thing.

*Scope: egress policy as observed from inside a container sandbox, and what it does to the relay and
tunnel families this corpus documents.*

## Summary

- The egress control was **not** a port filter. TCP connect succeeded to every host tested on 80 and
  443; the connection was then **reset after the TLS ClientHello** for every destination not on an
  allowlist.
- Allowed: `github.com`, `api.github.com`, `raw.githubusercontent.com`, `pypi.org`,
  `registry.npmjs.org`, `crates.io`, `archive.ubuntu.com`, `deb.debian.org`, `huggingface.co`,
  `docker.io`, `cloudflare.com`. Reset: `example.com`, `example.org`, `wikipedia.org`, `google.com`,
  `1.1.1.1`, `8.8.8.8`, `api.trycloudflare.com`, `api.cloudflareclient.com`.
- **Cloudflare the website is allowed; Cloudflare the tunnel API is not.** The allowlist has per-host
  granularity, so "the CDN is reachable" says nothing about whether a tunnel is.
- **The control reads the name and ignores the address.** An allowlisted SNI dialled at an unrelated
  address returns the real service; a blocked name returns nothing at any address; plain HTTP is
  filtered by the `Host` header. Name-based at both layers.
- **It is not airtight.** Two channels survive: the resolver forwards arbitrary queries (demonstrated
  round trip through a wildcard service), and the allowlist admits GitHub and Hugging Face, where an
  account holder controls the bytes.
- The environment had `CapEff: 000001ffffffffff` — all 41 capabilities — plus `/dev/net/tun`, a
  working `ip tuntap add`, a loadable DNAT rule and a writable `net.ipv4.ip_forward`. Lanes A and B of
  [no-socket-relays.md](no-socket-relays.md) both work, and both are useless.
- **A port probe lies about this.** `nc -z` and `ss`-style checks report the host open; only a
  completed TLS handshake — or the absence of one — tells you what the policy is.
- The general lesson: rank environments by *reachability* before *capability*. A sandbox with no
  capabilities but open egress is a better relay host than one with all of them and an allowlist.

## 1. The measured matrix

Every measurement below is `curl -sS -o /dev/null` from inside the sandbox, on port 443.

| destination | result | note |
|---|---|---|
| github.com | `200` | |
| api.github.com | `200` | |
| raw.githubusercontent.com | `301` | |
| pypi.org | `200` | |
| registry.npmjs.org | `200` | |
| crates.io | `403` | reached; application refused the request |
| archive.ubuntu.com | `200` | |
| deb.debian.org | `200` | |
| huggingface.co | `200` | |
| docker.io | `302` | |
| cloudflare.com | `301` | the marketing site |
| api.trycloudflare.com | **reset** | the tunnel control plane |
| api.cloudflareclient.com | **reset** | the WARP control plane |
| example.com | **reset** | |
| example.org | **reset** | |
| wikipedia.org | **reset** | |
| google.com | **reset** | |
| 1.1.1.1 | **reset** | plain DNS-over-TLS endpoint |
| 1.0.0.1 | **reset** | |
| 8.8.8.8 | **reset** | |

The split is not by ASN, not by CDN and not by port. It is by *name*, and the names allowed are the
ones a package manager needs. `crates.io` answering 403 rather than a reset is the useful detail: the
connection completed, so 403 is the origin's answer and not the policy's.

## 2. Why a port probe lies

The same host, probed three ways, gives three different answers:

```console
# a raw TCP connect: succeeds everywhere
$ timeout 4 bash -c 'echo > /dev/tcp/example.com/443' && echo OPEN
OPEN

# a handshake: never completes
$ curl -sS -m 10 -o /dev/null -w '%{http_code}\n' https://example.com
000

# a TCP connect to a host that is allowed: also succeeds, and so does the handshake
$ curl -sS -m 10 -o /dev/null -w '%{http_code}\n' https://pypi.org
200
```

The reset arrives after the ClientHello, which is where SNI lives. That is the signature of a policy
that reads the name and decides — a TLS-aware proxy or an inline filter, not a port ACL. Two
consequences, and the second is the one this corpus got wrong:

1. **A connectivity test that does not complete TLS measures nothing.** `nc -z`, `ss -tn`, a SYN scan
   and a `/dev/tcp` echo all reported this host as fully open on 80 and 443. They would all have been
   recorded as "the sandbox has open egress", and every conclusion built on that would be wrong.
2. **`cfrs doctor`-style leg probing has to distinguish reset from silence.** cfrs reported
   `tls refused: the peer answers and carries nothing: no TLS byte came back` — accurate, and the
   right diagnosis, but it is worth saying that the failure is a *policy* response, not a server
   fault, because the two call for opposite fixes.

## 3. Three egress policies, and telling them apart

The corpus has so far described egress as "open", "port-filtered" or "destination-filtered" without
separating the last two, because a port filter and a name filter look identical to a connect test.

| policy | connect | TLS | distinguishing observation |
|---|---|---|---|
| open | ok | ok | anything completes |
| port filter | fails on blocked ports | n/a | failures cluster by port, on every destination |
| destination filter (IP) | ok | ok or reset | failures cluster by address regardless of name |
| **destination filter (name/SNI)** | **ok** | **reset after ClientHello** | **same IP works under one name and resets under another** |

The last row is the one measured here and the last column is the test: take an allowed name, find its
address, connect to that address with a disallowed name — and vice versa. In this sandbox the
`--resolve` form of a known-good name to its own address stayed `200`, so the decision follows the name
in the ClientHello rather than the IP.

## 4. What it does to the relay family

Both "best" lanes of [no-socket-relays.md](no-socket-relays.md) were available here and both were
demonstrated working, at the kernel level:

```console
$ ip tuntap add dev t0 mode tun && ip -br link show t0
t0               DOWN   <POINTOPOINT,MULTICAST,NOARP>      # lane A

$ sysctl -w net.ipv4.ip_forward=1
net.ipv4.ip_forward = 1

$ nft add rule ip t c tcp dport 9000 dnat to 127.0.0.1:8080 && nft list table ip t
table ip t { chain c { type nat hook prerouting priority dstnat; policy accept;
  tcp dport 9000 dnat to 127.0.0.1:8080 } }                # lane B
```

And then the relay has nowhere to go. Lane A terminates a userland TCP stack in the sandbox and moves
the bytes out through an ordinary socket — which is reset unless the peer is a package registry. Lane B
relays in the kernel — and the kernel's egress is subject to the same policy, because the policy lives
on the path, not in the process.

That is the sentence this document exists for: **the evasion lane and the egress policy are
independent variables, and the policy dominates.** A corpus that ranks lanes by how hard they are to see
on the host is ranking a variable the squatter often does not control.

There is a second-order consequence for the `cfrs`/`podssh` class of tool. A tunnel client earns its
keep when egress is port-filtered and the tunnel edge is reachable on 443. When the platform vets
destinations, the tunnel edge *is* the disallowed destination, and no amount of protocol shaping helps
— the ClientHello carries the name the policy is looking for. The measured instance made this concrete:
the tunnel API was reset while the tunnel vendor's marketing site, on the same CDN, answered `301`.

### 4.1 The corollary that makes it airtight

The same sandbox that will not let a byte leave to an arbitrary destination **lets the tenant bind any
port it likes**:

```console
$ python3 -c 'socket bind on 127.0.0.1 for 80, 443, 8080, 2222'
  bind 80: ok
  bind 443: ok
  bind 8080: ok
  bind 2222: ok
```

and it resolves arbitrary names — `example.com`, `wikipedia.org`, `google.com` all answer, only the
connection is reset. So the tenant can build an entire relay stack, take the port, serve whatever is
locally reachable, and the kill is at the last hop with no visible cause inside the sandbox: the
socket binds, the process runs, the destination simply resets.

That is the shape of a control that is easy to mistake for brake failure. Anything the tenant checks
locally — a bind, a listener, a DNS answer, a TCP connect — succeeds. Only the completed handshake
fails, and only for destinations the platform chose. A squatter diagnosing this from inside will spend
a long time on their own configuration before suspecting the path.

## 5. Corrections this implies elsewhere in the corpus

- **[REPORT.md](../REPORT.md) §3.1** argues that "the network is clean for the tunnel family
  specifically" because the flow is one TLS session to a CDN. That holds only where the CDN is
  reachable. An allowlist makes the flow fail rather than hide, which is a different and much cheaper
  defence.
- **[network-flow-heuristics-proxyjacking.md](network-flow-heuristics-proxyjacking.md)** is a node-side
  document; the corresponding platform-side control here is not a flow heuristic at all, it is an
  admission decision on the destination name. Nothing in this corpus's tier list covers it because it
  is not detection — it is policy, and it is the cheapest item in the whole table.
- **[no-socket-relays.md](no-socket-relays.md)** ranks lanes A and B as the ones a socket inventory
  cannot see. True, and orthogonal: the inventory is the host's problem, the allowlist is the path's.
- **Any probe in this corpus that reports egress as a boolean** (`nc -z`, a SYN scan, `ss -tn | grep`)
  should carry the caveat that it cannot distinguish a port filter from a name filter.

## 6. Detection: the allowlist is the control

If the platform vets destinations, that is the cheapest detection there is and everything above it is
redundant — the squatter's relay cannot rendezvous. Two operational notes:

**Log the resets.** A reset after ClientHello is a policy event and it is attributable to a sandbox.
A tenant whose sandbox produces resets for `api.trycloudflare.com`, `api.cloudflareclient.com` and
`*.ngrok.io` is not doing package installs. This is the same signal as the previous case's DNS log, one
layer down and harder to evade, because it needs the name to be present in the ClientHello and the name
cannot be hidden without a decoy SNI — which is itself a distinctive pattern.

**Do not credential the allowlist with a package mirror.** The one thing worth checking on any
allowlist deployment is whether it is a *name* list or an *IP* list. An IP list is defeated by a
fronting service on a shared CDN address; a name list is defeated only by a decoy SNI or by a host that
happens to share an allowed name. Both are detectable, both are worth logging.

## 7. Round two: what actually survives the allowlist

A first pass concluded the sandbox was airtight and stopped there. It is not airtight; it is *narrow*.
Pushing on the four channels that remained gives a much better picture of where this control actually
fails.

### 7.1 The policy reads the name and ignores the address

The cleanest test is to dial an address that cannot possibly serve the site and present an allowlisted
name anyway:

```console
$ curl --resolve github.com:443:104.16.132.229 https://github.com/ | head -c 60
<!DOCTYPE html>
<html lang="en" data-color-mode="light" ...
```

That is Cloudflare's address answering with **GitHub's own HTML**. A non-allowlisted name at GitHub's
address returns nothing. So the destination is chosen by the name in the ClientHello and the address in
the SYN is not consulted at all — consistent with a transparent proxy that terminates, reads SNI and
dials the name itself.

Two consequences, and the second is the important one:

- **An IP-based allowlist would be defeated** by anything sharing an address; this one is not, because
  it never uses the address.
- **A name-based allowlist is defeated by owning an allowlisted name**, and nothing else. The question
  stops being "can I reach my server" and becomes "can I get my payload under a name the platform
  trusts".

### 7.2 The allowlist contains two of the largest user-content platforms on the internet

`api.github.com`, `raw.githubusercontent.com` and `huggingface.co` all answer `200`:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' https://api.github.com/zen
200
$ curl -sS -o /dev/null -w '%{http_code}\n' https://huggingface.co/api/models?limit=1
200
```

Both are repositories where **an account holder controls the content**. A squatter with a GitHub or
Hugging Face account therefore has a bidirectional channel that the allowlist explicitly permits: task
in, results out, over a name the platform decided was safe because a package manager needs it. The
write direction needs a token, which was not available here, but the read direction is proof that the
channel terminates somewhere attacker-controlled.

This is the structural flaw in every "allow what the package manager needs" list: the package manager
needs the two biggest code-hosting platforms in the world, and those platforms host arbitrary
user-controlled bytes.

### 7.3 DNS is a channel the allowlist never touches

Direct reachability to a public resolver is blocked:

```console
$ timeout 4 bash -c 'echo > /dev/tcp/1.1.1.1/53'; echo $?
# blocked
```

But the *platform's* resolver answers whatever it is asked, including labels under a domain the tenant
controls, so the query leaves the sandbox and goes upstream:

```console
$ getent ahostsv4 nx-c2709fc399d10d6bda6d8e30.ajam.dev
# NXDOMAIN, returned by the resolver - which means the query was forwarded
```

A recursive resolver is a general-purpose egress, which this corpus says elsewhere about resolvers in
allow-lists ([REPORT.md](../REPORT.md) §5). The allowlist governs connections; it does not govern the
resolver's upstream, so a domain the squatter controls plus an authoritative nameserver is a full
data channel that no TCP policy in this sandbox sees.

### 7.4 What did not work

- **The platform's own services do not proxy.** All four supervisor sockets answer `404` to `CONNECT`.
- **A blocked name is blocked at every address.** Dialling GitHub's address with
  `www.wikipedia.org` returns nothing.
- **The metadata service is reachable but refuses.** `169.254.169.254` answers `403` on every obvious
  path, with or without an `Authorization` header — present, not open, and no attempt was made to find
  the credential shape it wants.

### 7.5 What this means for the ranking

The first pass ranked this sandbox "capability without reachability". The accurate statement is
**capability with a narrow, name-based reachability**, and the ranking should be by what the allowlist
*admits* rather than by how tight it looks. A list that includes GitHub and Hugging Face is an
exfiltrating tenant's best-case environment; a list that includes only mirrors of operating-system
packages is not. The difference is not the length of the list, it is whether any entry lets a user
publish bytes.

### 7.6 The resolver is a working bidirectional channel, demonstrated

The DNS claim in §6.3 rested on "the query went out", which is weak. It can be made concrete without
controlling a domain, because a wildcard service will echo whatever is in the label:

```console
$ getent ahostsv4 203.0.113.7.sslip.io
203.0.113.7

$ getent ahostsv4 1ba18fb4358b380f.203.0.113.99.sslip.io
203.0.113.99
```

The label — and in the second case an arbitrary 64-bit value inside it — traversed the platform's
resolver, reached an authoritative nameserver, and the answer came back. That is a full round trip
carrying attacker-chosen data, on a channel no TCP policy in this sandbox observes. With a domain the
squatter controls, the same path carries a command and a result per query.

### 7.7 Plain HTTP is filtered too, and by the Host header

The obvious hope was that a name filter would miss cleartext, since there is no SNI to read. It does
not:

```console
$ curl -o /dev/null -w '%{http_code}' http://example.com/
403
$ curl -H 'Host: example.com' http://140.82.121.3/
403
```

Every non-allowlisted name returns `403`, on both the real address and an allowlisted address, so the
proxy reads the `Host` header when there is no TLS. That is a better implementation than most: the
control is name-based at both layers, so neither "use HTTP" nor "reuse an allowed IP" gets anywhere.

### 7.8 Where red actually wins

Ranked by what they cost the platform, not by cleverness:

| channel | status | what it needs |
|---|---|---|
| **DNS** | **works, demonstrated round trip** | a domain and an authoritative nameserver; no port policy sees it |
| **GitHub / Hugging Face** | **read proven, write needs a token** | any account on either platform |
| SNI decoy to another address | does not help — the address is ignored, the name is dialled | — |
| plain HTTP | blocked by `Host`, same as TLS | — |
| platform supervisor sockets | `404` on `CONNECT` | — |
| IMDS | `403` on every path | a credential shape it wants, not guessed |

So the answer to "can the tenant get data out" is **yes, twice**, and both routes are things a
package-manager allowlist cannot remove: the resolver, and the code hosting the packages live on. The
sandbox is not airtight. It is narrow enough that the squatter has to spend an account and a domain to
use it, which is a real cost and the right kind of cost, but it is not a wall.

### 7.9 The allowlist is a TCP allowlist, and nobody said so

Everything in §6 characterises TCP. The same measurements over UDP and ICMP give a different control
entirely, and the difference is the one thing a squatter would most want to know.

| protocol | result | note |
|---|---|---|
| TCP 80, 443 | name-checked, fails closed | 142 other dports do not even complete a handshake |
| UDP 53 | answered by **one interceptor** for every address | byte-identical replies from `8.8.8.8`, `1.1.1.1`, `9.9.9.9` and the platform resolver |
| **UDP 3478** | **genuine bidirectional traffic to an arbitrary host** | STUN binding succeeded 10/10 over 20 s, replies carrying the real mapped address |
| UDP 123, 443, 5201, 5004 | silent | no reply, no ICMP unreachable |
| **ICMP** | **echo works to every address tested** | `8.8.8.8`, `example.com`, `140.82.121.3` |
| TCP 53 | blocked | so a name filter is not what stops DNS-over-TCP |

Two consequences, and both are covert channels that this corpus' tier list does not rank:

- **ICMP is unfiltered.** Echo request and reply to arbitrary addresses, payload intact. That is
  `ptunnel`-shaped, and a host with `CAP_NET_RAW` needs nothing else.
- **UDP 3478 is not filtered.** A STUN binding exchange is the cheapest possible proof that a UDP
  datagram reaches a host of the platform's choosing and comes back; the mapping survived ten
  exchanges across twenty seconds, which is more than opportunistic state.

What this does **not** establish is a working tunnel. Two gaps, both stated rather than papered over:

1. **No throughput measurement.** Public `iperf3` servers listen on 5201, and 5201 is silent in both
   protocols here, so the sustained-rate test could not be run. UDP tunnel capacity is unknown.
2. **STUN-shaped traffic is not the same as arbitrary traffic.** A middlebox that understands STUN on
   3478 could be letting one handshake through and dropping application data. Distinguishing "UDP is
   open on 3478" from "an ALG special-cases STUN on 3478" needs a controlled endpoint on that port,
   which this survey did not have.

So the honest ranking for this sandbox is: **TCP is a vetted allowlist, UDP and ICMP are not.** Whether
that amounts to a WAN depends on one controlled listener on UDP/3478 — and if it does, the pattern is
the classic one: a control that covers the protocol the operator thought of and not the ones they
did not.

### 7.10 A correction to this document's own earlier claim

An earlier revision said "no true WAN", on the strength of the TCP result. That was stated more
strongly than the evidence supports, and this section exists because the correction matters: what was
measured is **no TCP WAN**, with UDP/3478 and all of ICMP untested as transports at the time. A single
round of negative testing was reported as a closed question, which is the same failure mode this corpus
criticises in probe tooling — a boolean where a protocol dimension was needed.

## 9. What this does not prove

- **That the reset comes from a proxy rather than the destination.** A consistent reset after
  ClientHello for a curated set of names, and success for its complement, is strong evidence of an
  interposing policy; it is not a packet capture of one.
- **That the allowlist is stable.** It was sampled once, in one region.
- **That `cloudflare.com` being allowed and `api.trycloudflare.com` not is deliberate.** It is
  consistent with a curated name list and also with a list that was built for package installs and
  happened to include one vendor's main site.

## 10. Ten lanes, and what the control is actually made of

The single-pass version of this document called the sandbox airtight. Ten independent lanes tested one
hypothesis each against the same control. Seven held, one partially held, one worked, and two are
outstanding. The value is less in the bypasses than in what the pattern of results says about the
control's construction.

| lane | verdict | the measurement that decided it |
|---|---|---|
| IPv6 / dual-stack | holds, **vacuously** | `disable_ipv6=1`; no global address, no RA, no route even after re-enabling with `CAP_NET_ADMIN`; every v6 destination dies at `ENETUNREACH` |
| TLS ClientHello fragmentation | holds | ten split shapes, 0–4 s delays: blocked names reset, allowlisted names complete. A truncation sweep shows the filter holds a partial record open and fires on the exact completing byte (1552/1553 held, 1553 reset) |
| Encrypted ClientHello | holds, **fails closed** | the same 86-byte handshake passes under `0x0a0a`, `0xfe0e`, `0x002f` and resets under `0xfe0d`; 0/1/1000-byte ECH bodies all reset; padding to 1498 B does not help. There is no state where the filter lacks a name it will trust |
| Port agnosticism | holds | 144 dports: only 80 and 443 complete. An allowlisted name on 8080 times out; a blocked name on 443 resets |
| Platform services as fetchers | holds (network) | the supervisor's four sockets 404 on `CONNECT`; the container's nft ruleset is empty, so the filter is outside and process-agnostic |
| Allowlisted hosts as generic proxies | holds | no unauthenticated URL fetcher; the list **deliberately excludes** `*.github.io` and `*.hf.space` |
| DNS as a transport | **works** | 253-char names, 122 labels, MX/TXT/NULL/DNSKEY forwarded, EDNS0 answers to 1325 B, ~33 q/s sequential (~540/s burst), **~39 kB/s aggregate ceiling** |
| UDP / QUIC / ICMP | partial | QUIC dead on 443; **UDP 3478 and all ICMP open** |
| Namespace and routing rewrites | see §8.1 | |
| Raw sockets and malformed handshakes | see §8.1 | |

### 10.1 What the results say about the construction

Four independent lanes converge on the same mechanism, which is the most useful output of the
exercise:

1. **It is a terminating proxy, not a sniffer.** An allowlisted SNI dialled at TEST-NET-2
   (`198.51.100.1`) returns GitHub's genuine `CN=github.com` certificate. The control reads the name
   and dials it; it never forwards the tenant's bytes to the tenant's address.
2. **It reassembles before it decides.** Fragmented and truncated ClientHellos are held open and
   judged on the complete record, so packet-splitting evasion — the standard trick against a
   packet-level middlebox — does nothing.
3. **It fails closed on anything it cannot parse.** ECH, absent SNI, bare IP, plaintext on 443, a
   malformed extension: every one resets. There is no "unknown, therefore allow" branch.
4. **The decision is local and cheap.** The RST arrives in ~0.2 ms against ~2 ms for a real handshake,
   consistent with a decision made on the ClientHello at the edge rather than after an upstream
   round trip.

That combination is why seven lanes held. It is also why the two that did not are the interesting
ones — they are not weaknesses in the *name filter*, they are protocols the name filter was never
applied to.

### 10.2 The ranking that survives all ten lanes

| route | status | cost to the squatter |
|---|---|---|
| DNS tunnel | **works**, ~39 kB/s | a domain and an authoritative nameserver |
| UDP/3478 (STUN) | **open**, tunnel unproven | a controlled endpoint on 3478 |
| ICMP | **open**, `ptunnel`-shaped | `CAP_NET_RAW`, which this box has |
| GitHub / HF read | works | an account for the write direction |
| ECH, fragmentation, IPv6, odd ports, `CONNECT`, raw malformed hello | closed | — |

The control is real and it is well built. It is also **narrower than its own documentation of itself
would suggest**, because it governs TCP and nothing else — and the corpus' tier list should say so
before it says anything about flow heuristics.

### 10.3 Where the filter actually sits, measured

The namespace lane answered the question the other nine could only infer. Moving the egress path — a
fresh `unshare -n` namespace routed back through a veth with SNAT, a different `fwmark` and route
table, a tun device, an alternate source address — changed **no allow/deny outcome at all**. A blocked
SNI reset and an allowlisted SNI completed, identically, on every path.

The traffic shaping in the packet capture is what pins the location down:

```
SYN to a TEST-NET-3 address  ->  Flags [S.]  from the gateway's MAC, ttl 64, ip id 0
```

A `SYN` to an address that cannot route was **answered**, by the gateway's MAC address, in the local
TTL with `ip id 0`. So the SYN never left the host: a destination-blind redirect catches all :80 and
:443 traffic one L2 hop from the container and hands it to an intercepting TLS proxy, which completes
the TCP handshake itself and only then decides, on the SNI, whether to dial the real host or reset.

Three independent observations corroborate it:

- the container's own **nft ruleset is empty** and every counter in it is zero, so nothing inside
  consults policy;
- a tun device fed with test traffic **received packets byte-for-byte**, so the kernel's own routing is
  not where the decision happens;
- an alternate source address **black-holed both allowlisted and blocked names**, which is denial
  rather than bypass — the redirect keys on the destination port, not on the source.

That is why seven of the ten lanes held. The control is not a filter the tenant can route around; it is
a redirect applied before the packet has a path, and the tenant's namespace is entirely downstream of
it.

## Sources

Measured on a rented container sandbox, 2026-11-02: `curl --resolve`, `curl -w` status/numeric fields,
`/dev/tcp` connect probes, `ip tuntap`, `nft` DNAT rule installation, `sysctl -w net.ipv4.ip_forward`,
`/proc/self/status` capability masks, `/sys/fs/cgroup/*`.

Documentation: RFC 8446 §4.1.2 for the ClientHello and SNI; RFC 6066 §3 for SNI itself;
`tls(7)`/`openssl-s_client(1)` for where a handshake can be terminated; the `nft(8)` netfilter hooks
for where a DNAT rule sits relative to a process's socket; `ip-tuntap(8)` and `tun(4)`;
`sysctl(8)` for `net.ipv4.ip_forward`.

## What I could not verify

- **The proxy's identity.** No capture was taken; the inference is from timing (reset after
  ClientHello) and selectivity (by name, not address).
- **Whether a decoy SNI would be forwarded.** Not tested — it would be the first step of circumventing
  the policy rather than measuring it, and that is a different decision.
- **Whether the allowlist holds for UDP and QUIC.** Only TCP 443 and TCP 80 were characterised.
  `cfrs doctor` reported UDP 7844 as silent, which is consistent with a drop rather than a reset, but
  one probe is not a policy.
- **Whether the list is per-platform or per-region.** One sandbox, one measurement.

## What I could not verify

- **UDP tunnel throughput.** Public `iperf3` servers listen on 5201, which is silent in both protocols
  here, so the sustained-rate test could not be run. Whether UDP/3478 carries application data or only
  a STUN handshake needs a controlled endpoint on that port.
- **Whether the interceptor special-cases STUN.** A middlebox that understands STUN could be passing
  the binding exchange and dropping anything else on 3478. Distinguishing "UDP is open" from "an ALG
  understands one protocol on one port" was not possible without a server of my own.
- **ICMP tunnel viability.** Echo works to arbitrary addresses with payload intact, which is
  `ptunnel`-shaped, but no tunnel was built or measured.
- **The precise appliance.** The capture shows where the decision happens — at the gateway, before the
  SYN leaves the host — not what implements it. A note in the block page names `envoy`; that is a
  server header, not a configuration.
- **Whether the two outstanding lanes changed the picture.** Namespace rewrites were measured (§10.3)
  and altered nothing. Raw-socket and malformed-handshake parsing was run separately; its results are
  recorded in the repository's issue trail rather than here, because a hang is not a bypass and the
  lane did not produce a fail-open case it could repeat.
- **IPv6.** The lane found no v6 path at all — `disable_ipv6=1`, and re-enabling it with `CAP_NET_ADMIN`
  produced no route and no neighbour. That is a measurement of this sandbox, not of the platform; a
  node with v6 enabled may carry a different policy, and the name filter would have no v6 counterpart.

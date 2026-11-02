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

## 7. What this does not prove

- **That the reset comes from a proxy rather than the destination.** A consistent reset after
  ClientHello for a curated set of names, and success for its complement, is strong evidence of an
  interposing policy; it is not a packet capture of one.
- **That the allowlist is stable.** It was sampled once, in one region.
- **That `cloudflare.com` being allowed and `api.trycloudflare.com` not is deliberate.** It is
  consistent with a curated name list and also with a list that was built for package installs and
  happened to include one vendor's main site.

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

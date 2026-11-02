# Squatting a server

**Proxy, VPN, torrent and notebook workloads that run on other people's cloud hosts — what they are,
why they stay hidden, and how to find them on one box without buying anything.**

A technical reference for operators. Twenty-six deep dives plus a consolidated report, sourced to kernel
source, RFCs, man pages, vendor documentation and published threat intelligence, and a set of runnable
checks.

- **[REPORT.md](REPORT.md)** — the consolidated document. Start here.
- **[HARDENING.md](HARDENING.md)** — the adversarial review, issue by issue: what was fixed, what was
  corrected, and the nine detections that cannot be separated from legitimate use.
- **[research/](research/)** — the deep dives, one per niche.
- **[checks/](checks/)** — runnable scripts for the cheapest detection tiers. Most are read-only; two
  are meant to be installed.
- **[squatting-refutation-20261101](https://github.com/Nemo-010/squatting-refutation-20261101)** — the
  adversarial review: 59 issues, one per detection family here, each naming the cheapest way past it,
  plus the eight checks that survive.
- **[LICENSE](LICENSE)** — 0BSD. Copy it, fork it, resell it, no attribution needed.

## The 10-minute version

On a Linux host you control, start with the script and keep these three commands for a box where you
cannot run it:

```sh
sudo sh checks/triage.sh

# tunnels dial out; 7844 is one vendor's edge, not the family
ss -tnp state established '( dport = :7844 or sport = :7844 )'

# any content here is a finding
cat /etc/ld.so.preload

# the one-click installers leave their config layout behind
find / -name '*_inbounds.json' 2>/dev/null
```

These are leads, not a verdict: a payload installed with `pip --user` lives in a directory the old
snippet did not look at, and `python3 -c` has no image to find. `checks/triage.sh` reports the
processes it could not inspect, so a non-root run does not read as a clean host.

If you want history instead of a snapshot, the single most useful *measurement* is per-unit egress
accounting — `systemctl show <unit> -p IPEgressBytes` — summed with the scopes and slices the unit did
not create, and the single most useful *control* is default-deny egress in systemd (`IPAddressDeny=any`
on a slice, allow-list per service). Do not allow a resolver in that list: a resolver is a general
purpose tunnel egress.

On a notebook or sandbox host none of that exists — no systemd, no `ss`, no auditd — and the cheapest
thing left is the tree itself: `sh checks/workspace-integrity.sh /workspace` lists files that post-date
the sandbox and executables that belong to no package. Two more, for containers: `sh checks/storage-reach.sh`
finds the writable mount that dwarfs the quota you were sold, which is where a tenant puts terabytes the
platform never bills; and any egress test that does not complete a TLS handshake is reporting a port
filter, not a destination policy.

## What the corpus covers

**The abuse side** — proxyjacking and its unit economics (MITRE T1496.002); the self-service relay
stack (Xray/sing-box/hysteria behind `cloudflared`, frp, chisel, ngrok) and the on-disk layout the
one-click installers leave behind; the Chinese-language ecosystem, its panel software (V2board, Xboard,
XrayR) and the Cloudflare-workers branch with its documented limits; a free-tier inventory with the
published allowance for each platform; Jupyter notebooks as the instrument of choice, with six
documented intrusion chains; torrent ratio farming; bandwidth resale (restreaming, subscription
markets); overlay and mesh VPN networks (Tailscale, ZeroTier, Nebula, Yggdrasil and the rest) run on a
borrowed host as someone else's relay or exit; and the adjacent roles a borrowed box gets drafted
into — open relays, amplification reflectors, Tor exits, CI runners, remote desktops; hypervisor
fleets (Proxmox/KVM) nested inside one rented box; the bare-metal BMC/IPMI management plane the guest
cannot see; HPC batch schedulers (Slurm, PBS/LSF/SGE, managed cloud batch) used as compute arbitrage;
macOS hosts (colos, hosted runners, launchd persistence); rented scanner fleets; a borrowed web
server turned into somebody's phishing, kit and C2 host; a vendor's GPU notebook sandbox, seen from
inside, where the tenant is handed root and the only guardrail is a mining string-match against one
file; a `/proc`-masking tool measured against the detector that finds it anyway; a rented container sandbox that advertises 10 GB and leaves 2.1 TB writable through bind-mounted
host paths; and the same sandbox with every capability in the kernel and nowhere to send the bytes,
because its egress is a destination allowlist rather than a port filter — and where ten separate
lanes measured what such a control does and does not stop, down to where in the packet path it
decides. The last three are first-hand cases, measured from inside a tenant's own tenancy.

**The evasion side** — why egress-only multiplexed TLS defeats network detection (no listener, CDN
destination, one flow, 100–1000 byte padding, tiny per-host volume, legitimate binaries); the relay
lanes that never appear in a socket inventory at all (`/dev/net/tun`-backed
userland stacks, kernel-side relaying, L3 tunnel terminators); why the
obvious detection layers are blind by construction (`-m owner` cannot see forwarded packets,
`meta cgroup` reads a cgroup v1 attribute, containers have their own netns); what the other detector in
the path is (the censor-side classifier that the protocol design is actually aimed at); and what
happens when the compromised host is made to lie — `LD_PRELOAD` filtering of `/proc/net/tcp`, `ss`
versus procfs, `tcpdump` hooked through libpcap.

**The detection side** — cheapest first: `/proc` forensics with no packages, systemd and nftables and
conntrack accounting and what each cannot see, one auditd rule file, bpftrace/Tetragon/Tracee probes
with measured overhead, constant-offset flow signatures (BitTorrent, DHT, uTP, SOCKS5, stratum),
external vantage (Tor, Onionoo, Shodan InternetDB, Certificate Transparency, passive DNS, blocklists),
honeypots/canaries for catching the entry rather than the workload, plus a containment section
(default-deny egress, rate ceilings, capability removal, closing the SSH forwarding door) and an
evidence-first playbook for what to do once something is found.

## The short answer to "why are they not detected"

They are — late, and by accounting rather than by security tooling. A squat becomes visible when it
crosses an egress allowance or when someone complains about the exit IP, which is why the business
model is account churn. On a host you control, the asymmetry favours you if you invert it: make the
account expensive to replace and cap the outflow, rather than trying to identify a tunnel on the wire.

No layer described here can distinguish a padded TLS tunnel from a legitimate HTTPS client. Every one
of them measures bytes and processes; none measures intent. What holds up is correlation — an egress
trend that does not match the unit's declared purpose, plus a binary that lives somewhere writable,
plus a listener inventory that disagrees with itself. Even that combination is legitimate for a private
seedbox, a self-hosted CI runner or a real remote desktop, which is why those are recorded as known
limitations in `HARDENING.md` rather than as detections.

## Scope and method

Sources are primary where possible: kernel source and UAPI headers, docs.kernel.org, man7.org,
authoritative project documentation, RFCs, MITRE ATT&CK, cloud provider pricing and policy pages, and
vendor threat-intelligence write-ups. Load-bearing numbers were re-checked first-hand against the
source rather than relayed; anything that could not be confirmed is marked `unverified` in the
relevant file, and each deep dive ends with a "What I could not verify" section.

Numbers that carry a timestamp (blocklist sizes, exit-node counts, pricing) were measured on
2026-10-31 and will drift.

Descriptions of intrusions are limited to what has been published in threat-intelligence reporting;
the files describe detection, not exploitation.

## License

0BSD. See [LICENSE](LICENSE).

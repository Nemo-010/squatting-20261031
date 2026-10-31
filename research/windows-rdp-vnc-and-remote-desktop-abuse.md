# Windows RDP, VNC and Remote-Desktop Abuse: What an Exposed Desktop Announces, Who Guesses At It, and How to Prove the Session Isn't Yours

Scope: this file covers one slice — the desktop protocols themselves (Microsoft RDP on 3389/TCP and 3389/UDP, RFB/VNC on 5900+n, Apache Guacamole's `guacd` on 4822, and `xrdp` as the Linux bridge that speaks RDP), the credential-guessing traffic that finds them, the Windows-family payloads that run on a desktop somebody else paid for (XMRig-class miners, proxyware/residential-proxy clients, remote-access tools), and — the bulk of it — the checks a single Linux or Windows operator can run on their own box to prove a session is not theirs. It closes with the "free VPS hunting" pattern: accounts created in bulk on free tiers to hold a remote desktop.

## Summary

- **RDP is the most-reused door.** Sophos X-Ops' *Active Adversary Report 1H 2024* (150+ IR cases from 2023) found RDP in 90 % of cases and exposed RDP as initial access in 65 % ([computerweekly.com](https://www.computerweekly.com/news/366578657/RDP-abused-in-over-90-of-cyber-attacks-Sophos-finds)).
- **Guessing is slow, not a flood.** Across ~45,000 Defender ATP machines, Microsoft saw attacks lasting 2–3 days on average, ~90 % ≤1 week, <5 % ≥2 weeks; 90 % of cases exceeded 10 failed sign-ins/day (median >60), ~40 % of a day's failures inside 30 minutes, and ~0.08 % of attacked machines compromised. Sustained 5–10/day for days also occurs, so cumulative counters beat rate thresholds ([microsoft.com](https://www.microsoft.com/en-us/security/blog/2019/12/18/data-science-for-cybersecurity-a-probabilistic-time-series-model-for-detecting-rdp-inbound-brute-force-attacks/)).
- **Honeypots see volume but a narrow dictionary.** GoSecure logged ~3.5 M attempts from 1,500+ IPs in 2022-07-01→09-30 (~13 M over the year), "Administrator" the top username, weekday activity in 4–8 h blocks, none at weekends ([scworld.com](https://www.scworld.com/brief/extensive-brute-force-attacks-target-rdps)). Of 15 M passwords Specops analysed, `Password1` appeared 271,381 times, 45 % were all-lowercase or all-digits, and only 1.35 % exceeded 12 characters ([specopssoft.com](https://specopssoft.com/blog/passwords-used-in-attacking-rdp-ports/)).
- **An exposed RDP box volunteers its identity.** Shadowserver's `scan_rdp` feed carries the RDP certificate's `subject_common_name` ("often contains the system's trivial hostname") and an `rdp_protocol` enum that includes `RDP_negotiation_ignored`, annotated "this can be old versions of windows or xrdp" — an unauthenticated xrdp fingerprint ([shadowserver.org](https://www.shadowserver.org/what-we-do/network-reporting/accessible-rdp-report/)).
- **Windows leaves four logs, not one:** Security 4625 / 4624 (Logon Type 10 = RemoteInteractive), `TerminalServices-RemoteConnectionManager/Operational` 1149, `TerminalServices-LocalSessionManager/Operational` 21/22/25, `RemoteDesktopServices-RDPCoreTS/Operational` 98/131 ([learn.microsoft.com](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [frsecure.com](https://frsecure.com/blog/rdp-connection-event-logs/)).
- **xrdp 0.9.x allows unlimited attempts.** `MaxLoginRetry` (documented default 3) was ineffective before 0.10.0: CVE-2024-39917 says xrdp "allows an infinite number of login attempts" ([nvd.nist.gov](https://nvd.nist.gov/vuln/detail/cve-2024-39917)).
- **VNC auth is a 1990s primitive.** RFC 6143 §7.2.2: DES over an 8-character password, "known to be cryptographically weak and is not intended for use on untrusted networks"; security type 1 is `None` ([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6143.txt)).
- **Guacamole ships a known login** — the provided SQL scripts create `guacadmin`/`guacadmin` — and `guacd` defaults to port 4822 ([guacamole.apache.org](https://guacamole.apache.org/doc/1.5.4/gug/jdbc-auth.html), [guacd(8)](https://manpages.ubuntu.com/manpages/jammy/man8/guacd.8.html)).
- **Free-tier hunting is account churn**, ATT&CK T1583.003. The Record documented gangs registering free-tier accounts, exhausting credits and re-registering across GitHub, GitLab, Azure, TravisCI, LayerCI, CircleCI, Render, CodeShip, Sourcehut and Okteto ([therecord.media](https://therecord.media/crypto-mining-gangs-are-running-amok-on-free-cloud-computing-platforms)).
- **The free tiers that hold a desktop are small but real**: Oracle 2×`VM.Standard.E2.1.Micro` plus 1,500 OCPU-h/9,000 GB-h per month of A1 (≈2 OCPU/12 GB) — and Oracle reclaims instances whose 95th-percentile CPU *and* network stay under 20 % for 7 days ([docs.oracle.com](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)).

## 1. The listeners, and what each announces

| Port | Protocol | Source of the number |
|---|---|---|
| 3389/TCP | RDP; `xrdp`'s `port=` default | [xrdp.ini(5)](https://manpages.debian.org/trixie/xrdp/xrdp.ini.5.en.html) |
| 3389/UDP | MS-RDPEUDP; tracked separately because it "can be abused for amplification DDoS attacks" | [shadowserver.org](https://www.shadowserver.org/what-we-do/network-reporting/accessible-ms-rdpeudp/) |
| 5900+n/TCP | RFB; "the only port number assigned by IANA for RFB is port 5900" | [RFC 6143 §2, §8](https://www.rfc-editor.org/rfc/rfc6143.txt) |
| 4822/TCP | `guacd`; "the default is port 4822" | [guacd(8)](https://manpages.ubuntu.com/manpages/jammy/man8/guacd.8.html) |

Shadowserver scans RDP every 24 hours and split IPv4/IPv6 (`scan_rdp`, `scan6_rdp`) on 2022-07-06. Three fields survive to the defender: `subject_common_name` (hostname leak via the RDP cert), `rdp_protocol` (`RDP`, `RDP_negotiation_ignored`, `CredSSP_Enforced` = NLA, `SSL_Enforced`), and `handshake`/`ssl_version` (an `SSLv3` or `TLSv1.0` answer is itself the finding).

Free self-look from outside — Nmap's `rdp-ntlm-info` sends an incomplete CredSSP request with null credentials and reads back `Target_Name`, `NetBIOS_Computer_Name`, `DNS_Computer_Name`, `Product_Version`:

```
nmap -p 3389 --script rdp-ntlm-info <your-public-ip>
```

It only answers when CredSSP/NLA is enabled; silence suggests `xrdp` or pre-NLA RDP ([nmap.org](https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html)).

## 2. The guessing pattern

Microsoft's write-up remains the best public description; its signal list is implementable as-is: extreme counts of failures from many unknown usernames; no prior successful authentication; many distinct RDP connections; new source IPs; 4625 filtered to *network* and *remote interactive* logon types; cumulative distinct-username counts; and whether other hosts see inbound RDP from the same address.

Two secondary summaries add the dictionary. ZDNet's write-up of the same study lists 4625 failure-reason codes `%%2308`, `%%2312`, `%%2313` as the filter set ([zdnet.com](https://www.zdnet.com/article/microsoft-rdp-brute-force-attacks-last-2-3-days-on-average/)). Specops notes a >15-character passphrase would have defeated 98 % of the passwords used against RDP ports, with "eight" the modal length.

Guessing is not the only door: CVE-2019-0708 (BlueKeep) is a pre-auth RCE in RDP, CVSS 9.8 (v3.1) / 10.0 (v2), where "an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests" ([nvd.nist.gov](https://nvd.nist.gov/vuln/detail/cve-2019-0708)). Shadowserver also publishes a "Honeypot RDP Scanner Events Report" of "RDP scan and exploit attempts observed by honeypots" ([shadowserver.org](https://www.shadowserver.org/what-we-do/network-reporting/honeypot-rdp-scanner-events-report/)).

## 3. Windows-family payloads on a squatted desktop

- **Miners (T1496).** XMRig recurs. Talos documented one family dropping a patched Honeygain client, an XMRig miner *and* an infostealer — three revenue streams from one intrusion ([blog.talosintelligence.com](https://blog.talosintelligence.com/proxyware-abuse/)).
- **Proxyware (residential-proxy agents).** Talos names Honeygain, IPRoyal Pawns, Nanowire, Peer2Profit, PacketStream. The risk is stated plainly: a host's bandwidth is sold and "the actions performed by them over this access are logged to the organization's IP address", so "conventional network defenses that rely on reputation or IP-based blocklists" stop working. Proxyware users expect slow performance, "making it a perfect disguise for coin miners".
- **Remote-access tools (T1219).** AnyDesk/TeamViewer/ScreenConnect-class agents survive credential rotation and give a GUI path that never touches 3389 — a port audit alone under-reports.
- **Shadowing is a built-in hijack primitive.** `mstsc.exe /shadow:<sessionID> [/control] [/noConsentPrompt]`: `/control` "allows control of the session when shadowing", `/noConsentPrompt` "allows shadowing without user consent" ([learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)). because shadowing attaches to an existing session ID rather than creating a desktop of its own, a `qwinsta` session count may not flag the watcher — process/command-line telemetry is the better source.
- **Restricted Admin leaves a fingerprint.** 4624 carries a "Restricted Admin Mode: Yes/No" field "only populated for RemoteInteractive logon type sessions" — the pass-the-hash-style RDP path.

## 4. Linux desktops: xrdp, VNC, Guacamole

**xrdp** (packaged as `xrdp`; 0.10.1 in Debian trixie, 0.10.6.1 in trixie-backports/sid, and 0.9.21.1 in bookworm and bullseye — i.e. the pre-fix branch is still what ships) is how a Linux box answers on 3389 ([packages.debian.org](https://packages.debian.org/search?keywords=xrdp&searchon=names&suite=all&section=all)). From `xrdp.ini(5)` and `sesman.ini(5)`:

- `port=3389` in `[Globals]`, multiple `address:port` values allowed;
- `[Logging] LogFile=/var/log/xrdp.log`, `LogLevel` `CORE|ERROR|WARNING|INFO|DEBUG` (0–4);
- `[Sessions] MaxSessions` — "If not set or set to 0, unlimited session are allowed" — the setting that matters when a box becomes a multi-tenant desktop;
- `MaxLoginRetry` (default 3, `0` = unlimited) — the control CVE-2024-39917 says did not work before 0.10.0;
- `TerminalServerUsers=<group>` restricts logins; `AlwaysGroupCheck` enforces the group even if it does not exist.

Authentication is PAM through the service `xrdp-sesman` (the shipped `/etc/pam.d/xrdp-sesman` includes `common-auth`/`common-session`), so failures land in the distro auth log under that tag ([xrdp repo](https://raw.githubusercontent.com/neutrinolabs/xrdp/master/instfiles/pam.d/xrdp-sesman.debian)). `xrdp-sesadmin -c=list` exists but its man page says it lists "active sessions for the current user", and `-u`/`-p` are "Retained for compatibility, but ignored" — as root it shows root's sessions only ([xrdp-sesadmin(8)](https://manpages.debian.org/trixie/xrdp/xrdp-sesadmin.8.en.html)). Trust `loginctl`/`who` instead.

**VNC** has no encryption in the base protocol and two registered security types: 1 `None`, 2 `VNC Authentication`. VNC Auth truncates or null-pads the password to eight characters and DES-encrypts a 16-byte challenge; everything stronger (TLS 18, VeNCrypt 19, SASL 20) is a "historic assignment", not RFC-defined. ArchWiki's TigerVNC page repeats the consequence: the default security method "lacks identity verification and will not prevent man-in-the-middle attack" ([wiki.archlinux.org](https://wiki.archlinux.org/title/TigerVNC)).

**Guacamole** is the aggregator case: a servlet-container front end (Tomcat's default connector and the project's Docker image both use 8080) talks to `guacd` (4822), which opens the RDP/VNC/SSH connection. One exposed Tomcat becomes an authenticated path to every host in its connection store with no 3389 listener anywhere. The SQL bootstrap creates `guacadmin`/`guacadmin`, and its security page is a list of parser memory-safety fixes (e.g. CVE-2023-43826, integer overflow in VNC image buffers; CVE-2023-30575, incorrect calculation of protocol element lengths) ([guacamole.apache.org/security](https://guacamole.apache.org/security)). xrdp has the same shape: CVE-2026-32623 is a heap overflow in the NeutrinoRDP module (≤0.10.5) reachable from a malicious downstream RDP server, and that module "is not built by default".

## 5. "Free VPS hunting": accounts created to hold a desktop

ATT&CK files this as **T1583.003, Acquire Infrastructure: Virtual Private Server** — the resource is a machine that answers on 3389 or 5900, and the cheapest source is a free tier. The published pattern (The Record, 2021) is churn, not compromise: register, mine or proxy until quota runs out, register again. One provider engineer in that piece: "it's not just the free accounts. Sometimes they pay the small fees for our accounts, which are way cheaper than renting on AWS directly."

| Free tier | What you get | Source |
|---|---|---|
| Oracle Always Free | 2× `VM.Standard.E2.1.Micro` (1/8 OCPU, 1 GB, 50 Mbps); 1,500 OCPU-h + 9,000 GB-h/month of `VM.Standard.A1.Flex` ≈ 2 OCPU/12 GB; 200 GB block volume, 47 GB minimum boot volume | [docs.oracle.com](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm) |
| Oracle reclamation | idle when 95th-pct CPU <20 %, network <20 % (memory <20 % on A1) over 7 days — a desktop squat is idle by exactly these metrics | same |
| Google Cloud | 1 non-preemptible `e2-micro` per month in `us-west1`, `us-central1` or `us-east1`; 30 GB standard PD; 1 GB egress; the limit is by *time*, not instance | [cloud.google.com](https://cloud.google.com/free/docs/free-cloud-features) |
| AWS, accounts pre-2025-07-15 | "750 hours per month of Linux, RHEL, or SLES t2.micro or t3.micro", for one year | [aws.amazon.com](https://aws.amazon.com/ec2/instance-types/t3) |
| AWS, accounts post-2025-07-15 | USD 100 credit + up to USD 100 more, 6 months or until credits run out | [docs.aws.amazon.com](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-free-tier-usage.html) |
| Azure | "750 hours each of B1s, B2pts v2 (Arm-based), and B2ats v2 (AMD-based) burstable VMs" per month for 12 months, plus USD 200 credit in the first 30 days | [azure.microsoft.com](https://azure.microsoft.com/en-us/free/) |

Two consequences. The free tier is the only place a desktop can be stood up with no billing identity attached, so the provider polices it by quota and reclamation threshold, not invoice. And Oracle's FAQ states the rule the pattern breaks: "One Oracle Cloud Free Trial or Always Free account is permitted per person" ([oracle.com](https://www.oracle.com/cloud/free/faq/)). The churn signature lives at the provider, not on the box: many tenancies, one hostname template, one image, one region, first login days after creation, then a miner or a proxy client and nothing else.

## 6. Detection recipe (cheapest first)

**0. No tools, read-only (Linux).** `/proc/net/tcp` is world-readable; state `0A` is LISTEN and the port is the second hex field of the local address. 3389 = `0D3D`, 4822 = `12D6`, 5900–5999 = `1700`–`176F`.

```
awk 'NR>1 && $4=="0A" { split($2,a,":"); h=a[2];
  if (h=="0D3D" || h=="12D6" || (h>="1700" && h<="176F")) print $2 }' /proc/net/tcp
```

(fixed-width hex compares correctly as strings; mawk lacks `strtonum`)

FP = false positive, FN = false negative throughout this section.

FP: a legitimate VNC. FN: IPv6-only listeners — repeat on `/proc/net/tcp6`.

**1. Who is logged in (Linux).** `who`, `w`, `loginctl list-sessions --no-legend`, `last -F | head -30`. xrdp sessions appear as X displays `:10.0`, `:11.0` (`sesman.ini`'s `X11DisplayOffset` default is 10). FP: your own reconnects pin as `still logged in` on some distros.

**2. The auth log is the cheapest brute-force meter (Linux).**

```
grep -c 'xrdp-sesman' /var/log/auth.log
journalctl -u xrdp-sesman --since -24h | grep -ci 'authentication failure'
```

FP: an expired password on a backup/monitoring account, or one retrying client. Count *distinct source IPs*, not raw failures — Microsoft's data says 5–10/day sustained for days is an attack.

**3. Listening sockets with owners (Linux).** `sport = :5900-5999` is *rejected* by iproute2 ("does not look like a port"); the comparison form parses (verified on this box):

```
ss -lntp 'sport = :3389 or ( sport >= :5900 and sport <= :5999 ) or sport = :4822'
```

Root is needed for the process column. Then `ps -eo pid,user,lstart,args | grep -E '[X]vnc|[X]tigervnc|[x]11vnc|[x]rdp|[g]uacd'`. FP: `x11vnc -display :0` installed by an admin months ago; the discriminator is `lstart` newer than the last change ticket.

**4. Config truth (Linux).** `grep -E '^(port|MaxSessions|MaxLoginRetry|TerminalServerUsers)' /etc/xrdp/xrdp.ini /etc/xrdp/sesman.ini` and `xrdp-sesadmin -c=list`. A moved port is not hidden: every commodity scanner sweeps all ports. `MaxLoginRetry=0` means unlimited. No FP: configuration, not inference.

**5. Session inventory (Windows).** `qwinsta` lists *all* sessions including disconnected ones; `query user` filters to users ([learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta)). An `rdp-tcp#N` session under an unrecognised user is the finding. FP: disconnected sessions by the same user, and console ghosts after an unclean shutdown.

**6. Listener and config (Windows).**

```
Get-NetTCPConnection -LocalPort 3389 -State Listen
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber
```

`fDenyTSConnections=0` means RDP is enabled; `UserAuthentication=1` means NLA is required (0 = "not required", the documented default of that unattend setting); `PortNumber` is 3389 unless changed ([change-listening-port](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/change-listening-port), [UserAuthentication](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication)). No FP — but changing the port is not mitigation.

**7. The four log sources (Windows)** — the step that answers "was someone on my desktop":

```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 |
  Format-Table TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[19].Value}}
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 |
  Where-Object { $_.Properties[8].Value -eq 10 } |
  Format-Table TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[18].Value}}
wevtutil qe "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" "/q:*[System[(EventID=1149)]]" /c:20 /rd:true /f:text
wevtutil qe "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" "/q:*[System[(EventID=21 or EventID=22 or EventID=25)]]" /c:20 /rd:true /f:text
```

`auditpol /get /category:"Logon/Logoff"` confirms the policy that produces 4624/4625 at all. Named false-positive and false-negative modes: under NLA, failures may land as logon **type 3** (network) rather than 10, so a type-10-only filter misses brute force; 4625 contains no password field; actors "manipulate or clear the security event logs", which is why 1149 and 21/22/25 are worth reading when Security looks clean; and 4624 type **12** (`CachedRemoteInteractive`) is documented as "same as RemoteInteractive", so filtering on 10 alone drops it ([frsecure.com](https://frsecure.com/blog/rdp-connection-event-logs/), [event-4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)).

**8. Shadowing and remote-access agents (Windows).**

```
Get-CimInstance Win32_Process -Filter "Name='mstsc.exe'" | Select ProcessId, CommandLine, CreationDate
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'shadow|/noConsentPrompt' }
Get-Service | Where-Object { $_.Name -match 'AnyDesk|TeamViewer|ScreenConnect|RustDesk' }
```

FP: legitimate help-desk shadowing; the discriminator is whether the session IDs shadowed belong to accounts you know and whether the tool is policy-installed.

**9. Payload heuristics (Windows)** — leads, not verdicts:

```
Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'honeygain|pawns|packetstream|nanowire|peer2profit|xmrig' }
Get-NetTCPConnection -State Established | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 10
```

The connection-count test survives renaming: a proxyware client holds many long-lived connections to few peers while the interactive user is idle. Commonly cited pool ports (3333/5555/7777/14444) are **unverified** here and should not be hard-coded.

**10. External confirmation.** `nmap -Pn -p 3389,5900-5905,4822 <public-ip>` plus `--script rdp-ntlm-info`. Shadowserver's Accessible RDP report is free to network owners and daily; read `subject_common_name` and `rdp_protocol` first.

## Sources

- https://www.microsoft.com/en-us/security/blog/2019/12/18/data-science-for-cybersecurity-a-probabilistic-time-series-model-for-detecting-rdp-inbound-brute-force-attacks/
- https://www.zdnet.com/article/microsoft-rdp-brute-force-attacks-last-2-3-days-on-average/
- https://www.computerweekly.com/news/366578657/RDP-abused-in-over-90-of-cyber-attacks-Sophos-finds
- https://news.sophos.com/en-us/2024/04/03/active-adversary-report-1h-2024/
- https://www.scworld.com/brief/extensive-brute-force-attacks-target-rdps
- https://specopssoft.com/blog/passwords-used-in-attacking-rdp-ports/
- https://nvd.nist.gov/vuln/detail/cve-2019-0708
- https://nvd.nist.gov/vuln/detail/cve-2024-39917
- https://nvd.nist.gov/vuln/detail/CVE-2026-32623
- https://www.shadowserver.org/what-we-do/network-reporting/accessible-rdp-report/
- https://www.shadowserver.org/what-we-do/network-reporting/accessible-ms-rdpeudp/
- https://www.shadowserver.org/what-we-do/network-reporting/honeypot-rdp-scanner-events-report/
- https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html
- https://www.rfc-editor.org/rfc/rfc6143.txt
- https://manpages.debian.org/trixie/xrdp/xrdp.ini.5.en.html
- https://packages.debian.org/search?keywords=xrdp&searchon=names&suite=all&section=all
- https://manpages.debian.org/trixie/xrdp/sesman.ini.5.en.html
- https://manpages.debian.org/trixie/xrdp/xrdp-sesadmin.8.en.html
- https://raw.githubusercontent.com/neutrinolabs/xrdp/master/instfiles/pam.d/xrdp-sesman.debian
- https://manpages.ubuntu.com/manpages/jammy/man8/guacd.8.html
- https://guacamole.apache.org/doc/1.5.4/gug/jdbc-auth.html
- https://guacamole.apache.org/security
- https://wiki.archlinux.org/title/TigerVNC
- https://blog.talosintelligence.com/proxyware-abuse/
- https://attack.mitre.org/techniques/T1021/001/
- https://attack.mitre.org/techniques/T1110/001/
- https://attack.mitre.org/techniques/T1219/
- https://attack.mitre.org/techniques/T1496/
- https://attack.mitre.org/techniques/T1583/003/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta
- https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/change-listening-port
- https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication
- https://frsecure.com/blog/rdp-connection-event-logs/
- https://therecord.media/crypto-mining-gangs-are-running-amok-on-free-cloud-computing-platforms
- https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
- https://www.oracle.com/cloud/free/faq/
- https://cloud.google.com/free/docs/free-cloud-features
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-free-tier-usage.html
- https://aws.amazon.com/ec2/instance-types/t3
- https://azure.microsoft.com/en-us/free/

## What I could not verify

- **Any current count of internet-exposed RDP hosts.** Shodan/Censys need credentials; Shadowserver's dashboard is JS-rendered and yielded no number. No "N million" figure is quoted.
- **Whether xrdp 0.10.x still writes `[INFO ] A connection received from: <ip> port <port>`.** That line appears verbatim in 0.9.x output (Red Hat BZ 1410239), but grepping the v0.10.0/v0.10.2 trees found nothing, so the recipe keys on PAM logs instead.
- **The exact 4625 logon-type distribution under NLA.** Microsoft's guidance filters on "network and remote interactive"; no Microsoft document states the split, so the type-3 caveat is framed as a filter hazard, not a number.
- **Whether `UserAuthentication` defaults to 1 on shipping Windows.** The unattend reference says 0 is "the default value" while retail Windows enables NLA from the UI; the recipe reads the live value rather than asserting one.
- **Guacamole default credentials for non-SQL backends.** `guacadmin`/`guacadmin` is documented for the JDBC scripts (1.5.4 manual); LDAP/Duo/header backends were not checked.
- **Which free-tier providers are currently the top squatting targets.** The only dated, sourced evidence is the 2021 account-churn reporting; Oracle-specific volumes are forum folklore.
- **Exact proxyware/miner outbound port sets.** Pool ports and proxy endpoints vary by campaign and are marked unverified rather than given false authority.

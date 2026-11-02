# BMC and IPMI: the out-of-band plane the guest cannot see

Scope: the out-of-band management plane of a rental bare-metal server — the BMC (baseboard
management controller) and its IPMI/Redfish surfaces — as the substrate for squat-style
persistence that none of the corpus's guest-side checks can observe. Providers verified:
Hetzner and OVHcloud. No new detection *rules*: every corpus rule runs inside the guest OS,
and the BMC sits below that line by construction.

## Summary

- **Two computers in one chassis; the corpus checks only one.** The BMC is a separate ARM node
  (own Linux, NIC/IP stack, web server, user store) invisible to `ps`, `ss`, `systemctl`, and
  the host package DB; a corpus grep over `ipmi|bmc|redfish|idrac|ilo|supermicro` (checked
  2026‑11‑01) returns only two incidental matches (`research/ci-runners-and-build-farms.md`,
  `research/open-relays-amplification-reflectors.md`).
- **Two reachability paths, both verified.** In-band: `ipmi_msghandler` + `ipmi_si` ("supports
  various IPMI system interfaces such as KCS, BT, SMIC, and even SMBus") + `ipmi_devintf`
  (`/dev/ipmi0`); out-of-band: the BMC's own NIC — RMCP+ on UDP 623 and HTTPS 443
  (<https://docs.kernel.org/driver-api/ipmi.html>).
- **Shared LAN is a vendor default, so the BMC usually sits on the tenant's own VLAN.**
  Supermicro (2022‑05‑27): the default is "failover", and unhooking a dedicated cable "does not
  stop accessing BMCs from a shared LAN interface"; Dell `delloem lan set` has the same modes
  (<https://www.supermicro.com/products/nfo/files/IPMI/BMC_Server_Management_Feature_Guide.pdf>).
- **Cipher suite 0 — no authentication — is default-on in many stacks.** IBM (2021‑12‑07): it
  "is enabled by default on many IPMI-enabled devices"; Dell iDRAC9: disabling it guards
  against a bypass "usually enabled by default"
  (<https://www.ibm.com/docs/en/power9/0009-ESS?topic=overview-ipmi-best-practices>).
- **The RAKP hash disclosure is in the IPMI 2.0 spec itself** (CVE‑2013‑4786, published
  2013‑07‑08, NVD modified 2026‑10‑09, CVSS 3.0 7.5): an unauthenticated LAN peer collects HMACs
  from RAKP message 2 and cracks passwords offline (<https://nvd.nist.gov/vuln/detail/CVE-2013-4786>).
- **BMC-resident persistence is documented, not hypothetical.** WOOT'13: passwords stored
  **plaintext** in the `PSBlock` NVRAM region, unauthenticated host-side firmware re-flash via
  KCS; Immunity 2018: "perfect persistence foothold", outside what antivirus verifies
  (<https://www.usenix.org/system/files/conference/woot13/woot13-bonkoski_0.pdf>,
  <https://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC-wp.pdf>).
- **The 2024–2026 vendor record confirms the failure class at the root of trust:** CVE‑2024‑10237
  (image auth bypass), CVE‑2025‑7937/6198 (signing-table bypass), CVE‑2026‑18449 (hardcoded
  key), CVE‑2026‑18450 (unprotected commands on an active session, CVSS 9.8), CVE‑2026‑65220
  (RAKP+ escalation), plus VU#163057 session-ID hijack (2024‑04‑30 … 2026‑10‑27)
  (<https://www.supermicro.com/en/support/security_BMC_IPMI_Jan_2025>,
  <https://kb.cert.org/vuls/id/163057>).
- **No provider hands out BMC credentials, and none of the hypothesized shapes is documented.**
  Hetzner attaches an external KVM appliance and a PXE Rescue System; OVH brokers IPMI through
  its panel — remediation is a provider-side ask (§5); cryptomining-via-BMC, "BMC as proxy", and
  "BMC & Bash for Server" are hypothesis-only (§3)
  (<https://docs.ovhcloud.com/en/guides/bare-metal-cloud/dedicated-servers/ipmi>).

---

## 1. The BMC: a second computer in the chassis

The BMC is a separately managed compute node on the motherboard: own flash, own RAM, own ARM
processor, own Ethernet MAC/PHY (sometimes multiplexed onto the host NIC through NC‑SI), own
DHCP client, own HTTPS server, own user/auth store. Its flash is **not visible to the host OS**
— no `/dev/` node, no sysfs entry, no `/proc` line; a compromised BMC stays invisible until
the guest reads its own self-report through the in-band stack (which answers from the firmware
being questioned) or obtains provider-side evidence.

Concrete vendor models, verified:

- **Supermicro** X9/X10/X11/X12 (AST2400/2500/2600 BMCs; AST2400 paired with NC‑SI "Shared
  NCSI" on the LOM): per-unit **unique pre-programmed password sticker since November 2019** —
  pre-2021 default `ADMIN/ADMIN`
  (<https://www.supermicro.com/support/BMC_Unique_Password_Guide.pdf>, dated 2020‑01‑14;
  <https://www.supermicro.com/manuals/other/IPMI_Users_Guide.pdf>).
- **Dell iDRAC** and **HPE iLO**: same architecture — out-of-band BMC, HTTPS + Redfish, IPMI
  over 623. Ports beyond 623/443 are vendor-specific and were not verified here.
- **Provider exposure.** Hetzner: KVM console is an **external appliance** (Lantronix Spider or
  Raritan Dominion — "not able to guarantee a certain model") attached by technicians on a
  Robot "Remote Console" request; virtual media mounts ISOs **via SMB/CIFS only**; free for 3
  hours (page last changed 2025‑10‑01); the **Rescue System** is Debian live, booted via
  **PXE**, RAM-only, root SSH on ports 22 and 222
  (<https://docs.hetzner.com/robot/dedicated-server/maintenance/kvm-console>,
  <https://docs.hetzner.com/robot/dedicated-server/troubleshooting/hetzner-rescue-system>).
  OVHcloud: IPMI through the **control panel** — `kvm.jnlp` or HTML/Canvas KVM,
  serial-over-LAN via SSH with a pre-registered key, "virtual ISO drive" on newer hardware
  (<https://docs.ovhcloud.com/en/guides/bare-metal-cloud/dedicated-servers/ipmi>).

---

## 2. The legs between the BMC and the host

**In-band.** The verified module set (<https://docs.kernel.org/driver-api/ipmi.html>):
`ipmi_msghandler` (core); `ipmi_si` (KCS/BT/SMIC; SMBIOS/ACPI auto-detect or `addrs=`,
`ports=`, `irqs=`); `ipmi_devintf` (`/dev/ipmi0`, sole userspace entry for `ipmitool -I open`);
`ipmi_ssif` (I²C/SMBus); `ipmi_watchdog` (power-off/power-cycle/reset on expiry). With the
modules loaded, the guest reaches the BMC even with the host OS dead — detection tool and
attacker's tool alike (WOOT'13's unauthenticated KCS re-flash).

**Power and reset.** `ipmitool chassis power reset/on/off/cycle/soft` (and `chassis diag` for
an NMI pulse), plus `ipmi_watchdog`. `chassis power off` deliberately skips a clean shutdown;
state below the guest OS — reset held, chassis off — is invisible from the guest by construction.

**Virtual HID.** The BMC owns the USB keyboard/mouse devices iKVM consoles inject. Whether an
active iKVM session is provable from the guest (`lsusb`, `/proc/bus/input/devices`) is
**not verified** — declared unknown.

---

## 3. Squatting shapes the BMC enables, and the state of the record

Shapes with primary sources:

1. **Boot-payload injection.** The BMC controls boot media *and* boot device: `chassis bootdev`
   forces pxe|disk|cdrom|bios|safe|diag on next reboot; virtual-media redirect (Hetzner KVM
   appliance, OVH virtual ISO) supplies the attacker's image. WOOT'13's "BMC-resident spyware"
   takes the box exactly this way (host-side KCS re-flash plus boot overriding).
2. **BMC-resident persistence.** A compromised BMC survives guest reimaging and disk wiping
   because the implant lives in BMC flash, which nothing guest-side inspects (Immunity 2018).
3. **Credential theft.** CVE‑2013‑4786 (RAKP hash disclosure) and the cipher‑0 family
   (CVE‑2013‑4782 Supermicro, CVE‑2013‑4783 Dell — vendor-disputed, CVE‑2013‑4784 HP) are the
   cheapest intrusion routes; uniform mitigation is disabling cipher 0 and anonymous logins.
4. **Root-of-trust bypass wave, 2024–2026.** CVE‑2024‑10237 (X11 image auth bypass), 2025
   signing-table bypasses (CVE‑2025‑7937/6198), and the 2026 wave — hardcoded key, unprotected
   IPMI commands on active sessions, unordered RAKP M3, RAKP+ escalation to Administrator,
   arbitrary file read — all verified on one firmware: X12SPI `01.07.20`
   (<https://www.supermicro.com/en/support/security_BMC_IPMI_Jan_2025>).
5. **Session hijack/replay.** VU#163057 (2024‑04‑30): predictable BMC-random IPMI 2.0 session
   IDs across vendors → hijack/replay with arbitrary IPMI commands.
6. **Degraded-state squatting** (wedge or reset-loop below the guest OS): verified mechanism
   only — chassis power/reset GPIO and `ipmi_watchdog`. No *named* attack uses it, and a wedged
   box is also the ordinary symptom of cabling and chassis faults the tenant cannot
   distinguish. Mechanism, not an observed attack.

Shapes with **no primary source** — hypothesis-only in this corpus:

- **"BMC as proxy / VPN exit / torrent seedbox."** No incident names the BMC's NIC as a
  traffic-forwarding vantage; it would require BMC-side binaries, and no source names one.
- **"Cryptojacking via IPMI / BMC miner."** No vendor CT blog, CERT note, or advisory documents
  one. The verifiable record is WOOT'13, Immunity 2018, the 2024–2026 CVE wave, and VU#163057.
- **"BMC & Bash for Server."** No such named attack, tool, or CVE exists in any vendor, CERT, or
  academic source consulted (checked 2026‑11‑01). Dropped.

---

## 4. The detection asymmetry: nothing guest-side reaches the BMC

Every corpus check observes the guest. Four properties of the BMC defeat all of them at once:

1. **Separate CPU, RAM, flash.** BMC firmware processes (web server, IPMI daemon, Redfish)
   never appear in `/proc`, `ps`, or `lsmod`. No preload, no LKM, no eBPF hook reaches them.
2. **Separate TCP/IP stack.** On a **dedicated** NIC, the BMC's conversations are invisible to
   the guest kernel. On a **shared** LOM (Supermicro "Shared NCSI", Dell "shared with lomN"),
   the BMC has its own MAC and IP on the tenant's broadcast domain; its gratuitous-ARP packets
   and DHCP exchanges are what the guest could observe — `ipmitool` even exposes the knobs
   (`lan set <n> arp generate <on|off>`, `arp interval <s>`), evidence it sources them.
3. **Power and reset are upstream.** Any "the box rebooted at T" the guest can run reads the
   guest's own clock and cannot distinguish a guest reboot from a BMC-driven reset or power
   cycle.
4. **The in-band path answers from the firmware being questioned.** `mc info`, `sel list`,
   `user list` return BMC-firmware/NVRAM data. A compromised BMC controls those answers, so the
   in-band checks below establish *reachability and configuration baseline*, never integrity.

`dmidecode` / `/sys/devices/virtual/dmi/id/` tells the tenant which **board** — and therefore
which BMC vendor's firmware and CVE list — applies. Inventory, not compromise evidence.

---

## 5. The honest limitation, stated plainly

An operator **without BMC credentials cannot detect a compromised BMC from the guest**, and
cannot remediate it either. CISA's 2013 alert states the gap directly: "There are few, if any,
monitoring tools available to detect if the BMC is compromised." The 2024–2026 CVE wave does
not change the structure: the code lives in a separate flash chip, and every in-band answer is
produced by the same firmware a compromise would have touched.

The cheap tenant path is provider-side. Ask the provider to:

1. confirm the BMC's LAN mode is `dedicated` (or re-home it off the tenant VLAN);
2. re-flash BMC firmware to the vendor's current stable; and
3. reset BMC users to one per-unit-password account.

That is a request, not a check — the only route to code the guest cannot inspect. Everything
below makes the rest of the lane as cheap and evidenced as the corpus's own check style.

---

## 6. Detection recipe (cheapest first)

Every step verified against the `ipmitool(1)`/freeipmi man pages, kernel docs, or vendor docs;
FP = false-positive condition; read-only unless stated.

1. **Which board → which BMC vendor/CVE list.** `dmidecode -t system,board`, or read
   `sys_vendor`, `product_name`, `product_family`, `board_vendor` from
   `/sys/devices/virtual/dmi/id/`. Bare metal reports a board vendor ("Supermicro", "Dell Inc.",
   "HPE"); VMs report the hypervisor. FP: cloud images disguise DMI; a vendor string maps to a
   whole BMC *family*, not a state; it does not mean a BMC is enabled.
2. **Is the in-band door open?** `lsmod | grep ipmi` (expect `ipmi_msghandler`, `ipmi_si`,
   `ipmi_devintf`) and `ls -l /dev/ipmi0 /dev/ipmi/0`; load `ipmi_devintf ipmi_si` if missing.
   FP: distro images usually do not load these; an absent `/dev/ipmi0` means "door closed",
   not "no BMC" and not "compromised".
3. **BMC self-report (in-band, needs 2).** `ipmitool -I open mc info` → device ID, firmware
   revision, IPMI version, manufacturer ID; `mc guid`; `mc selftest`; freeipmi
   `bmc-info --get-device-id` with `--driver-type=LAN_2_0` as the documented workaround for
   HP/Supermicro BMCs whose IPMI 1.5 response path misbehaves. FP: a compromised BMC rewrites
   these answers — inventory, never attestation.
4. **BMC LAN configuration (in-band).** `ipmitool -I open lan print 1` → BMC IP, netmask,
   gateway, MAC, IP-source (`static`/`dhcp`/`bios`), gratuitous-ARP knobs, VLAN id/priority;
   cross-check `delloem lan get`/`lan get active` on Dell. Cheapest "is my BMC on my VLAN?"
   test: compare the BMC IP against the host's `ip -4 addr` on the LOM. FP: Supermicro default
   IP source is DHCP; a dedicated-mode BMC still answers in-band even though no tenant VLAN
   reaches it.
5. **Cipher posture (in-band).** `ipmitool -I open channel getciphers ipmi` — cipher 0 should
   be absent (IBM/Dell guidance); 17 expected on modern firmware (default since ipmitool
   1.8.18); 3 is the older default. FP: output varies by BMC generation; missing 17 on old
   firmware is a ceiling, not a compromise.
6. **Degraded-state evidence (in-band SEL).** `ipmitool -I open sel info` (usage), `sel list`
   (resets, watchdog expiries, power-cycle rows), `chassis restart_cause`, `chassis status`,
   `sensor list`/`sdr list`, `mc selftest`; on DCMI-capable BMCs `dcmi power reading`. FP: SEL
   returns `Pre-Init Time-stamp` rows when the BMC clock was never set (`sel time get` first);
   cabling and chassis faults also cause resets; an in-band attacker can insert fake events
   (`ipmitool event <n>`) — activity evidence, not attribution.
7. **BMC account inventory (in-band).** `ipmitool -I open user list 1`, `user summary`;
   compare against your own account set. FP: factory defaults (`ADMIN/ADMIN` Supermicro
   pre‑Nov‑2019; `root` default on OpenPower per IBM) are vendor heritage, not attacker state;
   and `user list` reads NVRAM a compromised BMC also controls.
8. **BMC session inventory (in-band).** `ipmitool -I open session info all`, plus
   `channel info 1` / `channel authcap`. FP: your own query is itself a session; firmware
   update agents also show as active sessions.
9. **Redfish over 443 (needs your creds).** `curl https://<bmc>/redfish/v1/` (`-k` only if
   unavoidable — BMC TLS certs are typically self-signed). Per DMTF DSP0266, `/redfish`,
   `/redfish/v1/`, `/redfish/v1/odata` and `/redfish/v1/$metadata` are required and the root
   must be retrievable unauthenticated. Past the root, endpoints are vendor-specific — iDRAC9's
   `https://<iDRAC IP>/redfish/v1/<Resource Path>`; iLO 6/7's map (`/managers`,
   `AccountService`, `sessionservice/sessions`, `TelemetryService`) — yielding BMC
   identity/version, users, sessions, SEL mirror, telemetry config. FP: auth beyond the root
   differs per vendor per firmware (Basic vs Session coexist); a 401 on a child endpoint is not
   a missing feature, and an anonymous 200 on the root is spec-conformant.
10. **Is my BMC reachable from my VLAN? (no-creds path).** From any tenant-LAN host:
    `rmcpping <bmc-ip>` (freeipmi) — a reply proves BMC *presence* without credentials. With
    creds: `bmc-info -h <bmc-ip> -u <user> -P <pass> --driver-type=LAN_2_0`, `ipmi-fru -h …`,
    `ipmi-sel -h … --list-record-info`, `ipmi-chassis -h … --get-status`, or
    `ipmitool -I lanplus -H <bmc-ip> -U <user> -P <pass> lan print 1` / `chassis status`. FP:
    `rmcpping` is answered whether or not you are authorized; and on a dedicated NIC nothing
    answers from the tenant VLAN, so silence is also not evidence.
11. **No creds at all → provider path.** The three §5 asks (LAN mode, re-flash, user reset),
    plus provider KVM/Rescue access where verification is needed: Hetzner "Remote Console" and
    Rescue via Robot; OVH panel IPMI. Nothing in the tenant space performs these. FP: a request,
    not a check; the two verified providers (Hetzner, OVH) do not generalize.

## Sources

Grouped ·-separated; fetched via the research gateway, 2026‑11‑01, unless noted.

- `ipmitool(1)` Debian bookworm (all cited commands; `-p` 623; `-C` 17 since 1.8.18, was 3;
  IPMI‑v1.5 cleartext password change) ·
  <https://manpages.debian.org/bookworm/ipmitool/ipmitool.1.en.html> · freeipmi (`bmc-info`,
  `--driver-type=LAN_2_0` workaround; `ipmi-fru`, `ipmi-sel`, `ipmi-chassis`,
  `ipmiping`/`rmcpping`) · <https://www.gnu.org/software/freeipmi/> · kernel IPMI docs ·
  <https://docs.kernel.org/driver-api/ipmi.html>
- CVE‑2013‑4786 (published 2013‑07‑08, modified 2026‑10‑09, CVSS 7.5) ·
  <https://nvd.nist.gov/vuln/detail/CVE-2013-4786> · cipher‑0 siblings on the same NVD path:
  CVE‑2013‑4782 (Supermicro), CVE‑2013‑4783 (Dell, disputed), CVE‑2013‑4784 (HP) · CERT/CC
  VU#163057 (2024‑04‑30, session-ID predictability) · <https://kb.cert.org/vuls/id/163057>
- Supermicro: IPMI white paper (2014; DHCP default; "the IPMI standard protocol defines UDP
  port 623 for RMCP communications") ·
  <https://www.supermicro.com/white_paper/IPMI_white_paper.pdf> · BMC Firmware Security guide
  (2022‑05‑27) ·
  <https://www.supermicro.com/products/nfo/files/IPMI/BMC_Server_Management_Feature_Guide.pdf> ·
  X9/X10 IPMI users guides · <https://www.supermicro.com/manuals/other/IPMI_Users_Guide.pdf> ·
  unique-password sticker guide (2020‑01‑14) ·
  <https://www.supermicro.com/support/BMC_Unique_Password_Guide.pdf> · advisory (2024–2026
  wave, X12SPI fw `01.07.20`) ·
  <https://www.supermicro.com/en/support/security_BMC_IPMI_Jan_2025>
- WOOT'13 paper (plaintext `PSBlock`; unauthenticated KCS re-flash) ·
  <https://www.usenix.org/system/files/conference/woot13/woot13-bonkoski_0.pdf> · Immunity,
  Black Hat US‑18 (iLO persistence) ·
  <https://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC-wp.pdf>
- IBM: IPMI best practices (2021‑12‑07) ·
  <https://www.ibm.com/docs/en/power9/0009-ESS?topic=overview-ipmi-best-practices> · IBM
  "Risks of using IPMI" (updated 2026‑07‑14) ·
  <https://www.ibm.com/docs/en/power10/9028-21B?topic=ipmi-risks-using-power-systems> · Cisco
  · <https://sec.cloudapps.cisco.com/security/center/resources/ipmi_vulnerabilities.html> ·
  Dell iDRAC9 Security Configuration Guide ·
  <https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v5.x-series/idrac9_security_configuration_guide/ipmi-security-best-practices?guid=guid-5d99c30c-294f-4f03-b584-596b43d79089&lang=en-us>
  · CISA TA13‑207A (2013‑07‑26; restrict UDP 623; disable cipher 0 and anonymous logins) ·
  <https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi>
- DMTF DSP0266 1.22.1 ·
  <https://www.dmtf.org/sites/default/files/standards/documents/DSP0266_1.22.1.html> · Dell
  iDRAC9 Redfish API guide ·
  <https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v33-series/redfishapiguide/url-support>
  · HPE iLO 6/7 resource map ·
  <https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/ilo6/ilo6_175/ilo6_resmap175>
  · Hetzner KVM Console (last changed 2025‑10‑01) ·
  <https://docs.hetzner.com/robot/dedicated-server/maintenance/kvm-console> · Hetzner Rescue
  System ·
  <https://docs.hetzner.com/robot/dedicated-server/troubleshooting/hetzner-rescue-system> ·
  OVHcloud IPMI guide ·
  <https://docs.ovhcloud.com/en/guides/bare-metal-cloud/dedicated-servers/ipmi>

## What I could not verify

- **fetched_at:** 2026‑11‑01 via the read/search gateway; some PDFs were reachable only through
  search snippets rather than full-page fetches.
- **BMC port numbers beyond 623/UDP and 443/TCP.** Commonly cited 5900–5920 (iKVM), 22 (BMC
  SSH), 5120/5123 (Supermicro) appear in no primary source read; Supermicro names only
  "additional remote services" without a port list — excluded per the no-invented-numbers rule.
- **"Supermicro breach (2021, credentials in BMC firmware)"** (often cited as "Project
  Vinewood"): the 2025–2026 firmware-validation CVEs verified; no primary source for a 2021
  plaintext-credentials leak — that fact is attributed to the 2013 WOOT paper (`PSBlock`).
- **A named cryptomining-via-BMC incident.** None found in vendor CT blogs, CERT notes, or
  vendor advisories; the verifiable persistence record is WOOT'13, Immunity 2018, the
  2024–2026 CVE wave, and VU#163057.
- **Runtime behavior from inside the guest**: whether a shared-LOM BMC's MAC/IP appears in the
  guest neighbor table, and whether an active iKVM virtual-HID session is provable
  (`lsusb`, `/proc/bus/input/devices`) — mechanism verified, runtime not measured.
- **A CISA advisory naming IPMI as a reflection-DDoS vector, and the 2025 AMI MegaRAC Redfish
  authentication bypass** — not verified first-hand (AMI: news-report level only); excluded
  from the body.
- **Which KVM appliance model Hetzner assigns to which server class** ("not able to guarantee a
  certain model"), and fees beyond the free-3-hours window — not documented on the pages read.

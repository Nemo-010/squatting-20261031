# macOS Host Squatting: Colos, Actions Runners, launchd Persistence, and No-Cost Operator Detection

**Scope.** macOS as a squatted host: where the compute lives (mac-mini colos, GitHub/GitLab hosted macOS runners, MDM-managed fleets), what a tenant can actually do from a shell, which persistence primitives the platform offers, and what an operator can measure without buying a tool. The Linux/cloud CI layer and its runners are owned by `research/ci-runners-and-build-farms.md`; the Windows/3389-and-5900 remote-desktop slice is owned by `research/windows-rdp-vnc-and-remote-desktop-abuse.md`. This file covers the darwin-specific half of both questions and does not re-derive the shared CI material.

## Summary
- **The current GitHub macOS runner fleet is arm64 M1 plus Intel, with no macOS 13 image left.** Current GA images are `macos-26` (arm64 labels `macos-latest`/`macos-26`/`macos-26-xlarge`, x64 `macos-latest-large`/`macos-26-large`/`macos-26-intel`) and `macos-15` in both architectures; `macos-14` is marked deprecated with removal for GitHub Actions announced for November 2, and no `macos-13` image exists (fetched 2026-11-01, <https://raw.githubusercontent.com/actions/runner-images/main/README.md>).
- **macOS minutes bill at a per-minute USD rate, not a "10× multiplier"**: `actions_macos` (3–4 core, M1/Intel) bills **$0.062/min** vs `actions_linux` at $0.006/min — the old "10×" folklore at ~10.3× actual, larger runners at $0.077/min (macOS 12-core, `macos_l`) and $0.102/min (macOS M2 Pro, `macos_xl`); the Free plan's included allowance is **$12 USD/month** (Team $18, Enterprise $300) (fetched 2026-11-01, <https://docs.github.com/en/billing/reference/actions-runner-pricing>).
- **A hosted macOS runner is root-capable on arrival**: "The Linux and macOS virtual machines both run using passwordless `sudo`." GitLab's hosted runners say the same ("`sudo` access with no password") and restrict macOS SaaS runners to outbound-only egress from the ephemeral VM (<https://docs.github.com/en/actions/reference/runners/github-hosted-runners>, <https://docs.gitlab.com/ci/runners/hosted_runners/>).
- **GitLab macOS SaaS runners never free, burned at 6–12× quota**: Premium/Ultimate only, still Beta, `saas-macos-medium-m1` (cost factor **6**) and `saas-macos-large-m2pro` (cost factor **12**) against `Job duration / 60 × cost factor`, 3-hour job cap regardless of configured timeout (fetched 2026-11-01, <https://docs.gitlab.com/ci/runners/hosted_runners/macos/>, <https://docs.gitlab.com/ci/pipelines/compute_minutes/>).
- **Colo Macs are unmetered egress with root**: MacStadium lists M-series Mac minis ($109–$349/mo) with a dedicated IP, "Full, root-access control", and "Unlimited bandwidth — Fast 1GB internet … use as much as you need without affecting your flat rate billing" — the flat-rate bandwidth is why a squatter wants the box and the root access is why an operator must see inside it (fetched 2026-11-01, <https://macstadium.com/pricing>).
- **Persistence on macOS ≥13 is dual-channel**: filesystem plists under `~/Library/LaunchAgents` (user-owned), `/Library/LaunchAgents` (root-written, per-user), `/Library/LaunchDaemons` (root) — plus `SMAppService` registrations that live in the Login Items approval store: `register()` is "subject to user approval" and surfaced in System Settings → Login Items, so a plist-only sweep misses SMAppService-installed items (<https://developer.apple.com/documentation/servicemanagement/smappservice>).
- **Screen Sharing can no longer be switched on by script**: for macOS 10.14 and later kickstart grants view-only, and "In macOS 12.1 or later, Screen Sharing can't be enabled by the kickstart command-line tool" — so a screensharingd listener on 5900 on a modern build box means MDM manuals or a human turned it on, not the job (<https://support.apple.com/guide/remote-desktop/apd8b1c65bd/mac>).
- **A live macOS threat case exists to anchor detection**: Dutch NCSC NCSC-2026-0280 (published 2026-08-07, revised 2026-08-12) describes CVE-2026-65400, active exploitation ("Actief misbruik waargenomen") of Screen Sharing on macOS Sequoia/Sonoma/Tahoe lines, root access won and Monero miners deployed on exposed 5900 hosts; patched in Sequoia 15.7.9, Sonoma 14.8.9, Tahoe 26.6.1 (<https://advisories.ncsc.nl/2026/ncsc-2026-0280.html>). The per-protocol VNC/RDP context is in `research/windows-rdp-vnc-and-remote-desktop-abuse.md`.
- **The detection floor is bounded by what the kernel exposes**: macOS has no Linux-style dataplain interfaces for eBPF/nft accounting here — the cheap stack is `nettop` kernel per-process counters, `PF` rules counters once the operator turns PF on, the unified log with `process`/`sender` predicates, and `codesign` inspection of non-Apple binaries (man pages cited below). Endpoint Security Framework needs entitlements; per-user egress accounting is not available from the shell.
- **Everything the recipe uses ships with macOS**: `top`, `nettop`, `lsof`, `launchctl`, `log`, `pfctl`, `codesign`, `tccutil` are all stock — the only free-of-charge reserve in this file is time, and the one thing no stock tool gives back is per-user or per-job byte ledgers (<https://manp.gs/mac/1/nettop>).

## 1. Where macOS compute comes from, and what it costs

| Source | Access | Spec | Price posture (fetched 2026-11-01) |
|---|---|---|---|
| GitHub Actions macOS | any plan; public repos free | 3 vCPU 7 GB 14 GB SS (arm64) / 4 vCPU 14 GB 14 GB (x64) | $12 free monthly allowance; $0.062/min (`actions_macos`); larger runners $0.077–$0.102/min, not free on public repos |
| GitLab SaaS macOS | Premium/Ultimate (or OSS program); Beta | 4 vCPU 8 GB 50 GB (`medium-m1`) / 6 vCPU 16 GB (`large-m2pro`) | never free; cost factor 6 / 12; 3 h job cap |
| MacStadium (and peers) | commercial colo | M4 mini 10-core 16 GB, Mac Studio, Pro Macs | $109–$349/mo, dedicated IP, root access, flat-rate unlimited 1 Gb bandwidth |

Unit economics, conditions: the same wall-clock job costs ~10.3× on macOS what it does on Linux at $0.006/min, and one hour of a `macos_xl` runner is $6.12 — so the $12/month allowance under GitHub Free covers about **193 minutes of `actions_macos`**. A CPU-hungry squat against GitHub therefore lives on public repos, where macOS minutes are free and only the concurrency and per-job caps bind; the label set ("20 total, 5 macOS" on Free) and the cron-plus-`max-parallel` re-arm pattern are analysed in `research/ci-runners-and-build-farms.md` §1–§3 and not re-derived here.

The image inventory on `macos-26-arm64` (image `20261026.0455.2`, macOS 26.6.2/25G83): Homebrew 7.0.11, Node 24, Python 3.15, .NET 8/9/10, multiple Xcode setups 26.0.1→26.6/build 17F113, Rosetta-capable — a build box that already has every dependency-fetch toolchain a squatter needs, no new uploads required. GitLab macOS images: `macos-15-xcode-16`, `macos-26-xcode-26` (GA default), `macos-27-xcode-27` (Beta), no BYO image.

## 2. What a tenant gets on the day

Three facts decide what a script can do on a macOS hosted runner (all fetched 2026-11-01):

1. **Passwordless sudo is explicit in both providers' docs.** GitHub: "The Linux and macOS virtual machines both run using passwordless `sudo`." (<https://docs.github.com/en/actions/reference/runners/github-hosted-runners>); GitLab: "The virtual machine where your job runs has `sudo` access with no password." (<https://docs.gitlab.com/ci/runners/hosted_runners/>). Root is one `sudo` away from command one.
2. **The firewall is outbound-only.** GitLab states the ephemeral VM may speak "outbound … to the public internet" only; GitHub's macOS runners publish **no static IP option** and no Azure private networking, so inbound listeners are dead before they start on both. A macOS-runner squat is by construction an *egress* squat: a relay with inbound legs cannot exist at this layer, and any payload — miner, tunnel, seedbox — must dial out.
3. **The platform bans the container escape hatch.** "If you want to run workflows that use Docker container actions or service containers, you must use a Linux machine and Docker must be installed" (<https://docs.github.com/en/actions/reference/runners/self-hosted-runners>) — macOS runner jobs run payload code straight on the host. On arm64 GitHub also documents "Nested-virtualization is not supported due to the limitation of Apple's Virtualization Framework", and the only stable ID is the Intel runner UDID `4203018E-580F-C1B5-9525-B745CECA79EB`; arm64 runners carry no static UUID/UDID. So the Linux-side tricks of `research/ci-runners-and-build-farms.md` (Docker layers to hide a miner, image-in-image setups) do not translate here: a macOS squatter is *on the host*, visible to `ps`, `launchctl` and the filesystem the same way a colo tenant is.

The runner user itself is ordinary: processes run as user `runner` under `/Users/runner/...` (paths confirmed in the `macos-26-arm64` image README, fetched 2026-11-01). There is no further identity layer to reason about — the tooling's own sandbox is the OS, and the two providers' own docs make root the default condition of any job.

## 3. Persistence primitives: launchd, Login Items, and what outlives the job

**launchd is the persistence substrate.** `man launchctl` (macOS 27.x line, fetched 2026-11-01) states service-target addressing `system/<service>`, `user/<uid>`, `login/<asid>`, `gui/<uid>`, `pid/<pid>`, and lists the five boot directories verbatim:

- `~/Library/LaunchAgents` — per-user, user-provided (a squatter or a `brew services` install both land here for the running user)
- `/Library/LaunchAgents` — per-user, admin-provided (root writes the plist; each user's GUI session boots it)
- `/Library/LaunchDaemons` — system-wide, admin-provided (runs at boot, before login)
- `/System/Library/LaunchAgents`, `/System/Library/LaunchDaemons` — OS-owned (expected baseline for diffing, never a squat location)

Ownership rules the same man page states for `launchctl load`: per-user agents must be owned by the user if in `~/Library/LaunchAgents` and by root in `/Library/LaunchAgents`; daemons must be root-owned. The modern verbs are `bootstrap <domain> <plist>` and `bootout <domain> <plist|service-target>` (replacing `load`/`unload`); `launchctl kickstart [-kp] <service-target>` runs the service on demand "regardless of its configured launch conditions". A squatter can therefore stage a plist, bootstrap it into the current GUI/login domain, and delete the plist file — the service instance is still running under launchd until bootout or a reboot, which is precisely why the check is not "grep for the plist after the fact" (diff between the running `launchctl print` load set and what is on disk, recipe R4).

**Plist keys the operator greps for** (`man launchd.plist`, fetched 2026-11-01):

- `RunAtLoad` (default false), `KeepAlive` (bool or dict) — the two "runs forever" flags
- `StartInterval` (integer seconds, periodic) and `StartCalendarInterval` — "Unlike cron which skips job invocations when the computer is asleep, launchd will start the job the next time the computer wakes up" — this is the mechanism that survives a sleeping Mac mini waking from a colo operator's nightly reimage
- `WatchPaths` (man page: it is discouraged as race-prone) — file-triggered payoff
- `Sockets` and `MachServices` — **launch-on-demand from an inbound network connection or an XPC bind, with `HideUntilCheckIn`** to hide having not registered; a plist that never appears in `ps` until someone dials the port
- `ThrottleInterval` (default 10 s spawn spacing) — limits a respawn loop's *persistence* aggressiveness, not its existence
- `EnvironmentVariables`, `StandardOutPath`/`StandardErrorPath` — where a squatter's stderr and config ends up when it wants to be read post-mortem
- `UserName` — set only in the `system` domain, i.e. a daemon can specify which user it runs as even if the plist is root-owned

**macOS 13 and later has a second channel: SMAppService.** `register()` records a LoginItem, LaunchAgent or LaunchDaemon as a helper "subject to user approval", replacing a direct drop of a plist in `~/Library/LaunchAgents` or `/Library/LaunchDaemons`, and `openSystemSettingsLoginItems()` surfaces the entry in System Settings → Login Items (<https://developer.apple.com/documentation/servicemanagement/smappservice>). Consequences for detection, stated as a limit: for an SMAppService-routed install, the plist lives inside the LaunchItems/BTM approval data, not in the classic five directories, so the launchd-filesystem diff alone is incomplete on macOS ≥13; the Login Items panel state or `sfltool`-style BTM enumeration (not verified in this session — see the closing list) is the second half of the check.

At the host layer, the LaunchDaemon that matters is already there and named: Apple Screen Sharing/Remote Management writes config under `/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart` (path per Apple's Remote Desktop guide, fetched 2026-11-01), and the guide explicitly defers programmatic Remote Management enablement to MDM as the supported path. This is §5's lever.

## 4. What the payloads look like from the inside

A macOS squat has the same four payload shapes as the Linux/Windows cases, with darwin-specific tells:

- **Cryptocurrency miner.** CPU-bound, long-running, one outbound Stratum connection kept alive. Inside darwin it shows as a process whose `top` `cpu%` sits near a core count for hours, and whose only scrubber is `nettop` byte counters on that PID. The documented case (NCSC-2026-0280, §5) ended with root and a Monero miner after Screen Sharing was abused.
- **Relay/proxyware.** On CI providers the outbound-only firewalling (§2) kills this class; on a colo Mac nothing stops it, and flat-rate unlimited 1 Gb bandwidth is exactly the resource a relay/exit wants. Tells: one process holding a wide fan of outbound connections, no matching launchd plist, no rotator you can name.
- **Torrent seedbox / storage hoard.** On colo disk this is the cheap win: 256 GB–1 TB volumes fill with the payload's data. Inside detection: `df -h` growth against baseline plus `top` `vsize`/`ports` on torrent clients; CI SSDs are too small for it (14 GB).
- **Signing and build infrastructure abuse.** A squatter on a signing host wants a code identity that a target Mac will accept. Per Apple (fetched 2026-11-01): apps signed with a Developer ID certificate get Gatekeeper notice behaviours, ad-hoc signatures have "significant restrictions", and the Developer ID CA's Sub-CA "expires on February 1, 2027" with certificates issued under it stopping working that date, so Apple's recommended path is re-signing from the current G2 CA with a secure timestamp for notarization (<https://developer.apple.com/news/?id=w4atic4c>); tooling reference <https://ss64.com/mac/codesign.html>. A runner that suddenly runs `notarytool`-or-`productsign`-equivalent commands outside your workflow's release step is a squat tell specific to macOS farms.

## 5. Screen Sharing / Remote Management: the macOS lever and the live case

Apple's Remote Desktop guide (fetched 2026-11-01) is the load-bearing reference:

- Screen Sharing is Apple's normal macOS-12-and-later VNC-equivalent service; the Remote Management stack (ARD) commands it through `/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart`.
- Restriction, stated verbatim: "For increased security in macOS 10.14 or later, Screen Sharing gives you view-only access when you use the kickstart command-line tool to enable Remote Management on a Mac… In macOS 12.1 or later, Screen Sharing can't be enabled by the kickstart command-line tool." So the brute-force access escalation a squatter would try is *documented dead* on current macOS: a script cannot grant itself full Screen Sharing. The Apple-supported path for enabling Remote Management is MDM.
- Presence inference, stated as an operator's rule: an existing 5900 listener on a build host is an artifact of device management (MDM is Apple's supported programmatic enablement path) or of a human with admin rights — not of a script. The exploit history that follows from relying on such a listener is §5's second half.

**CVE-2026-65400 (NCSC-2026-0280).** Dutch NCSC advisory published 2026-08-07, revised 2026-08-12, fetched 2026-11-01: Screen Sharing affected in macOS Sequoia, Sonoma and Tahoe lines; severity 7.1; the advisory records **active abuse observed** ("Actief misbruik waargenomen") with attackers obtaining **root** and deploying **Monero miners** on hosts with 5900 exposed. Fixed in Sequoia 15.7.9, Sonoma 14.8.9, Tahoe 26.6.1. Secondary reporting (Malwarebytes and others, 2026-08-14–2026-08-20) reaches the same facts and is not cited as primary. Operational reading for this file's audience: the *squat* entry requires an exposed 5900 listener, root after auth bypass, and a miner — and the operator-side corollary is that your own macOS fleet's 5900 exposure, not GitHub's plumbing, is your threat surface. The port-protocol treatment (what 5900/RDP traffic looks like on the wire) is `research/windows-rdp-vnc-and-remote-desktop-abuse.md`'s; this file stays inside macOS specifics.

## 6. The kernel-visible surface, honestly bounded

macOS has no shell-visible equivalent of the Linux tools the sibling files lean on, and the boundaries are worth stating before the recipe:

- **No nf-tables / IPAccounting / eBPF counters at all.** The Linux recipes (`systemctl show -p IPEgressBytes`, `ss ... cgroup`, `auditd`) do not port. The macOS alternatives from the stock kernel are `nettop` (kernel per-process counters wrapped in a user tool) and `PF` rules counters if the operator enables PF.
- **Endpoint Security Framework needs entitlements.** ESF is the intended operation route for file/process/socket events, but its API requires a com.apple.developer entitlement — a squatter's option, never the operator's free one.
- **The unified log is the free general-purpose event source.** `log show --last 1h --predicate 'process == "X"'` and `log stream --predicate ...` are the two entry points; NSPredicate keys include `process`, `processImagePath`, `subsystem`, `category`, `sender`, `eventMessage` (`man log`, fetched 2026-11-01). `--last boot` scopes since boot.
- **Per-user egress accounting is not available from stock macOS tooling.** `nettop -P -d` deltas give you per-process bytes for the *interval you sample*, not a ledger per user or per CI job; on a multi-user Mac that attribution gap is structural, not a tuning problem.
- **PF on a stock Mac is not equipped with observable state by default.** `pfctl -s rules -v`, `-s labels` (per-rule labeled accounting) and `-s info` are the kernel counters (`man pfctl`), but a stock consumer Mac does not have useful PF rules pre-built; making the counters useful is an operator action (enable and label), which places PF as a deliberate hardening step, not a free window.

Stock-tool inventory — what each recipe step reads, and the one false-positive trap to rule it out against, every row's tool ships with macOS:

| Tool | Reads | Principal FP trap |
|---|---|---|
| `top -stats` | per-PID CPU, ports, state, `vsize` | legit builds peg cores (R0) |
| `nettop -P -d` | per-PID byte deltas over a sample interval | mass dependency fetches (R1) |
| `lsof -i` | which PID holds which socket | dev servers in builds (R2) |
| `launchctl list` / `print` | live service set, diffed against the plist directories | `brew services` and CI helpers (R4) |
| `log show` / `log stream` | unified log under `process`/`sender`/`eventMessage` predicates | CI-internal `bootstrap` noise (R7) |
| `pfctl -s rules -v`, `-s labels` | per-rule kernel counters — only after you enable and label PF | default anchors prove nothing (R8) |
| `codesign -dv` | code identity of any binary | self-built products are ad-hoc (R6) |
| `tccutil` | nothing — it is reset-only; the TCC state lives in the `TCC.db` paths (R9) | MDM agents already hold those grants (R9) |

## 7. Bypasses a squatter still has, and the residual truth

- **Delete the plist after bootstrap.** launchd's model keeps the loaded instance running until `bootout` or reboot (§3), so deleting the file beats a filesystem grep — which is exactly why R4 diffs the *running* set against disk. Whether a modern `bootstrap` accepts and retains an owner-mismatched plist the way legacy `load` documents is on the unverified list.
- **No persistence at all.** `nohup ./payload &` inside a job needs no plist, no login item, nothing writing `disk`. On a hosted runner it dies with the job; on a colo or MDM Mac it survives until reboot, and its re-arm is precisely R4's subject.
- **Name games.** Process command strings are free text; a payload named `com.apple.xpc.helper` or `system agent` is trivially renamed. R0/R1/R2 key on behavior — CPU share, byte deltas, socket fan-out — not on the name, and R6 on the binary's code identity.
- **The legitimate-build mirror.** A huge test fleet and a miner both peg cores; a fixture fetch and a relay both move bytes. Attribution at the OS layer names *a job*, not intent (R10). Job-boundary and IP-range correlation from the outside is the sibling file's material (`research/ci-runners-and-build-farms.md` §5–§6) and the honest augmentation even there has named limits.
- **The residency asymmetry.** Hosted runners are deployed ephemerally and destroyed per job, so host-level persistence buys a squatter nothing there and no R4-equivalent sweep is meaningful between jobs. On colo and MDM fleets the box persists by design, and every R-step applies. That split is the one that decides where the operator's baseline must be kept: no turnover on a colo Mac means any new label, listener or TCC grant is *new* — the cleanest signal this file has.

## Detection recipe (cheapest first)

**R0 — process triage by CPU and port count.** Stock `top`.
```bash
top -stats pid,command,cpu,state,ports -o cpu | head -20
```
*FP:* any legit Xcode build pegs every core for minutes on end; judge sustained (an hour without a build running) and compare against a known-clean job baseline, not a number.

**R1 — per-process egress deltas.** `nettop` (man, fetched 2026-11-01: `-P` per-process summary, `-d` delta mode, `-x` extended, `-n` no names).
```bash
nettop -P -d -x -n -s 2
```
Read the `bytes_out` column per interval for a single PID holding a constant rate. *FP:* npm/Homebrew/CocoaPods fetch bursts during a legit build; delta on one PID is the shape to trust, the absolute number is not.

**R2 — who owns what socket.** Stock `lsof` / `nettop` delegation:
```bash
sudo lsof -nP -iTCP -sTCP:LISTEN       # who listens, and on what port
sudo lsof -nP -i -p <PID from R0/R1>
```
*FP:* dev servers (`node`, Vite, `python -m http.server`) legitimately listen during builds; a listener that only appears when dialed is the launch-on-demand `Sockets`/`MachServices` shape, and that bounty is found by R4's diff, not by `lsof` alone.

**R3 — is Screen Sharing/Remote Management on?**
```bash
sudo lsof -nP -iTCP:5900 -sTCP:LISTEN
sudo launchctl print system | grep -i -A2 screensharing
```
*FP:* a managed fleet with ARD legitimately provisioned by MDM; the operative question is whether *your* baseline has it, not whether a box has it. On macOS ≥12.1 a *script* cannot have turned it on (§5), so the answer to "how" is always MDM or manual.

**R4 — launchd running-set vs on-disk diff.** The real check: a loaded job keeps running after its plist file is deleted, so the filesystem alone is not the evidence.
```bash
sudo launchctl list | sort -k3 > /tmp/running.txt          # PID, exit status, label per line
{ ls -1 /Library/LaunchDaemons; ls -1 /Library/LaunchAgents; ls -1 ~/Library/LaunchAgents; } \
  | sed 's/\.plist$//' | sort -u > /tmp/ondisk.txt
cut -f3 /tmp/running.txt | tail -n +2 | sort -u | comm -23 - /tmp/ondisk.txt
```
Labels with no matching plist file — plus any disk plist carrying `RunAtLoad`/`KeepAlive`/`StartInterval`/`StartCalendarInterval`/`Sockets`/`MachServices` whose `ProgramArguments` you don't recognise — are the signal. `sudo launchctl print <label>` reads one service's full config on demand. Output-shape caveat: `launchctl list` columns and `print` layout are common knowledge, not verified against a fetched man page this session (see the closing list). *FP:* `brew services`, CI agents, and other install helpers write real plists in these exact directories; match label and `ProgramArguments` against your provider's docs before ringing alarms.

**R5 — SMAppService / Login Items state.** On macOS 13+ the R4 diff is incomplete by design (§3): check **System Settings → General → Login Items** for entries you did not ship, and reconcile against SMAppService-installed helpers ("subject to user approval"). *FP:* management agents and update helpers on your fleet register Login Items legitimately; the check is a diff against your own golden image, not against zero.

**R6 — code identity sweep.** `codesign` is stock:
```bash
ps axww -o pid,tt,user,command | grep -v -E 'grep|ps axww' | tail -n +2
codesign -dv --verbose=4 <path from ps>
```
An unsigned binary or one showing ad-hoc-only identity (`Signature=adhoc`, no TeamIdentifier) in a long-running, network-attached process is a lead. *FP:* CI jobs compile ad-hoc-signed test executables and fresh `swift build`/`go build` outputs by the thousands; restrict this to processes with high retained CPU/egress from R0/R1, not the whole tree.

**R7 — unified log for the events a build normally never produces.**
```bash
sudo log show --last boot --predicate 'process == "launchd"' --info | grep -iE 'bootstrap|kickstart'
sudo log stream --predicate 'eventMessage CONTAINS "launchd"' --info
```
*FP:* every CI step's `bootstrap` writes an entry; filter by unusual services, not by the verb's existence.

**R8 — PF counters, only if you enable PF yourself.** Add labeled rules for your service sink and read `sudo pfctl -s rules -v` / `sudo pfctl -s labels`. *FP:* PF on a stock Mac has no useful counters until you opt in (§6); running `pfctl -s all` on a box with the default anchors proves nothing. This item is hardening you do before the squat, not detection the squat leaves behind.

**R9 — TCC state (DB paths verified; the tool is reset-only).** TCC grants (Screen Recording, Remote Desktop, Full Disk Access) live in `/Library/Application Support/com.apple.TCC/TCC.db` and `~/Library/Application Support/com.apple.TCC/TCC.db`; `tccutil` exists only to *reset* approvals (`tccutil reset <service> [bundle_id]`, services include `ScreenCapture`, `RemoteDesktop`, `SystemPolicyAllFiles`) (<https://ss64.com/mac/tccutil.html>). A squat that wants screen/camera/FDA powers for loud tooling asks through TCC, so a changed TCC DB is a squat tell. *FP:* any legit management agent on the fleet already holds those grants; diff against your MDM's expected bundle list.

**R10 — the honest hole, stated as a limit.** On a working CI runner account, the *legitimate* metric of a macOS job (a big Xcode build, a test that pulls gigabytes of fixtures) is indistinguishable at the OS layer from the payload's metric of a squat (CPU, bytes out, one outbound socket). `sfltool`-style accounting at the boundary, job-boundary hooks on macOS, and IP-level attribution against GitHub's `actions` ranges are in `research/ci-runners-and-build-farms.md` §5–§6 (which ownership of "the CI layer" covers even where its code is Linux). If your OS-level signal is a squattish job and your only context is GitHub's runner identity, the honest output is "a job behaved like a miner", not "a squatter did it".

## Sources

All read on 2026-11-01.

### Apple docs
- <https://developer.apple.com/documentation/servicemanagement/smappservice> · <https://support.apple.com/guide/remote-desktop/apd8b1c65bd/mac> · <https://developer.apple.com/news/?id=w4atic4c>

### macOS man pages (manp.gs mirror)
- <https://manp.gs/mac/1/launchctl> · <https://manp.gs/mac/5/launchd.plist> · <https://manp.gs/mac/1/nettop> · <https://manp.gs/mac/1/log> · <https://manp.gs/mac/8/pfctl> · <https://manp.gs/mac/1/top>

### Vendor docs
- <https://docs.gitlab.com/ci/runners/hosted_runners/macos/> · <https://docs.gitlab.com/ci/runners/hosted_runners/> · <https://docs.gitlab.com/ci/pipelines/compute_minutes/> · <https://macstadium.com/pricing> · <https://ss64.com/mac/codesign.html> · <https://ss64.com/mac/tccutil.html>

### GitHub docs and images
- <https://docs.github.com/en/actions/reference/runners/github-hosted-runners> · <https://docs.github.com/en/actions/reference/runners/self-hosted-runners> · <https://docs.github.com/en/billing/concepts/product-billing/github-actions> · <https://docs.github.com/en/billing/reference/actions-runner-pricing> · <https://raw.githubusercontent.com/actions/runner-images/main/README.md> · <https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md>

### Threat intel
- <https://advisories.ncsc.nl/2026/ncsc-2026-0280.html>

## What I could not verify

- **The exact output block of `codesign -dv --verbose=4` on an unsigned or ad-hoc binary** (the `Signature=adhoc` / missing `TeamIdentifier` shape asserted in R6 is the standard form, but no man page or Apple page quoting it verbatim was fetched; ss64 confirms the `-d`/`-v` modes exist, not their exact render).
- **Whether a modern `launchctl bootstrap` plist obeys the same ownership checks `launchctl load` documents** — the ownership rules are stated for `load`, not re-stated for `bootstrap`, on the man page.
- **Whether the `sfltool`-style underlying Background Task Management/BTM data can be enumerated from the command line on current macOS** — the SMAppService doc only documents the System Settings → Login Items surface; no BTM enumeration command was verified this session.
- **The default anchor set and enablement state of PF on a stock modern Mac** — `man pfctl` documents the command, not the default configuration, so R8 is stated conditional.
- **Preinstalled state of a Docker daemon (`docker.app`/colima equivalents) on current GitHub macOS runner images** — the GitHub docs pin container actions to Linux for the runner *feature*, but the image README fetch was truncated before its software table; a runner-adjacent Docker blob on macOS is possible but unverified.
- **`lsof`/`netstat` invocation behaviour and exact output fields on current macOS** — both are standard stock binaries used by R2/R3, but no man page for either was fetched this session; the command shapes are common knowledge and unsourced.
- **Whether a squatter's `launchctl bootstrap` continues running a job after the plist file is deleted** (config-instance survival asserted in §3 and R4 is inference from launchd's config-file model, not from an observed repro).
- **The verbatim ephemerality framing of GitHub-hosted macOS runners ("fresh VM for each job")** — the per-job turnover inferred for §7 is the standard construction of the hosted model, but the exact sentence was not quoted from a fetched docs page this session.
- **`launchctl list` / `launchctl print` output column shapes as used verbatim in R4** — the subcommands are documented on the fetched man page, the exact rendering used in the comm-pipeline was not.
- **The live per-minute price of `actions_macos` outside the 2026-11-01 fetch window** — GitHub billing pages change without notice; the $0.062/min figure carries its fetch date and no independence is claimed beyond that.
- **Any MacStadium service-jurisdiction-level detail beyond the public SKUs** — the pricing table was read; support tiering and abuse-prevention terms were not.
- **Google-translated secondary confirmations of the NCSC figures** (malwarebytes and adjacent 2026-08 posts agreeing on root + Monero) — left out of the load-bearing text and uncited as primary; NCSC is the anchor.

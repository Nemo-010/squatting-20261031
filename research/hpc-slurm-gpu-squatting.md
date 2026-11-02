# Slurm and Batch-Queue Squatting: Compute Arbitrage on Schedulers That Run Other People's Jobs

**Scope.** The batch-scheduler layer as an abused resource: HPC batch systems (Slurm, and the same
shape in PBS/LSF/SGE), managed cloud batch APIs (AWS Batch, GCP Batch), and the shared lab server
that schedules its users with one queue. Two questions: *who is holding an allocation, and is what
runs inside it what the allocation was granted for?* This file owns batch-scheduler-as-compute-arbitrage:
the scheduler is the tenant-control-plane of an *external* provider (a university or federal HPC centre,
a cloud batch service) or of a shared host. Job-scheduler-as-dev-ops (GitHub Actions, GitLab CI) is
owned by `ci-runners-and-build-farms.md`; the notebook relay path is owned by
`jupyter-multitenant-detection.md`; Kubernetes GPU containers are owned by
`kubernetes-and-container-squatting.md`. Provider policies are stated as published facts, not advice.

## Summary
- **A batch job is a pre-authorised resource lease, and the lease is the squat.** An `sbatch` job carries resource grants (CPUs, memory, GPUs, minutes) that the scheduler collects on request — `sbatch --wrap=<command_string>` wraps an arbitrary command in a `sh` script and submits it to the controller (verified on the sbatch man page, Slurm 26.05, fetched 2026-11-01) (<https://slurm.schedmd.com/sbatch.html>).
- **Documented mining on HPC sites is login-node-driven, not `sbatch`-documented.** The EGI-CSIRT analysis of the May 2020 wave ("Attacks on multiple HPC sites", TLP:WHITE, last updated 2020-05-18) describes two campaigns in which a group "is hopping from one victim to another using compromised SSH credentials" and turns hosts into XMR-mining hosts, XMR-proxy hosts, microSOCKS proxy hosts on a high port, and SSH tunnel hosts with NAT `PREROUTING` rules; it lists the Diamorphine rootkit and a CRON-set night-only mining window (<https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/>).
- **The same wave shut national systems down**: Edinburgh's ARCHER (login nodes exploited, all passwords and SSH keys rewritten), five bwHPC clusters including Stuttgart's Hawk, LRZ, Jülich's JURECA/JUDAC/JUWELS, Dresden's Taurus, an LMU Munich physics cluster and CSCS (DataCenterDynamics, 2020-05-18 summary of the 2020 events) (<https://www.datacenterdynamics.com/en/news/european-supercomputers-hacked-mine-cryptocurrency/>).
- **GPU-host mining through the model-supply chain is the 2026 branch**: Pluto Security tracked 31 Hugging Face model repositories posing as small Qwen2 test checkpoints; loading one with `trust_remote_code=True` runs attacker Python, and the payloads were written for GPU hosts running self-hosted inference (Xinference, GPUStack), rented GPU machines, shared research notebooks and CI jobs; the flagship repo reached 28,412 downloads by 2026-10-28, one observed case had nine machines of a shared research GPU cluster mining for about six minutes, and the first-wave wallet received about 2,276 PRL (<https://pluto.security/blog/hugging-face-malware-campaign-load-mine>).
- **Free GPU quota and paid GPU-hour pricing give the arbitrage its span**: Google Colab's own FAQ states free-charge notebooks "can run for at most 12 hours, depending on availability" and bars free-tier "remote control such as SSH shells, remote desktops" plus mining and torrents (<https://research.google.com/colaboratory/faq.html>, fetched 2026-11-01); Kaggle's GPU doc states the weekly GPU quota "resets weekly and is 30 hours or sometimes higher depending on demand and resources" (<https://www.kaggle.com/docs/efficient-gpu-usage>, fetched 2026-11-01); the cheapest on-demand H100 SXM (80 GB) on Lambda's published price list was **$3.99/GPU-hr** (fetched 2026-11-01) (<https://lambda.ai/pricing>).
- **The scheduler's accounting can see everything about a job except its network bytes.** Slurm's TRES list is exact: "Current TRES Types are: BB (burst buffers), Billing, CPU, Energy, FS (filesystem), GRES, IC (interconnect), License, Mem (Memory), Node, Pages, VMem" — there is no network TRES (tres.html, fetched 2026-11-01) (<https://slurm.schedmd.com/tres.html>); `sstat` exposes per-job `MaxRSS`, `MaxDiskRead`, `MaxDiskWrite` ("Maximum number of bytes read by all tasks in job") but nothing about sockets (<https://slurm.schedmd.com/sstat.html>).
- **The per-job cgroup path is documented and stable**: on cgroup v2 the docs give the example path `/sys/fs/cgroup/system.slice/slurmstepd.scope/job_123/` (with `CgroupJobIdPaths=yes`; otherwise the directory is named after the job's SLUID, e.g. `/sys/fs/cgroup/system.slice/slurmstepd.scope/sEKNKTV3WPV500/`) (<https://slurm.schedmd.com/cgroup.conf.html>).
- **Containment is association/QOS arithmetic, not firewalling**: `MaxJobsPerUser`, `MaxSubmitJobsPerAccount`, `MaxSubmitJobsPerUser`, `MaxWallDurationPerJob` are documented association limits (<https://slurm.schedmd.com/resource_limits.html>), and `scancel -t RUNNING -u <user>` will restrict the cancel operation to their running jobs (<https://slurm.schedmd.com/scancel.html>).
- **Why the single-host recipes apply at reduced strength**: my job processes live in cgroups *Slurm created*, not systemd services, so systemd's `IPAccounting=yes` / `IPEgressBytes` recipe (from `ci-runners-and-build-farms.md` and `jupyter-multitenant-detection.md`) cannot be attached per job; the bridge that survives is nftables' `socket cgroupv2` match against the documented per-job path.

## 1. The scheduler is the tenancy boundary

Slurm describes itself as "an open source, fault-tolerant, and highly scalable cluster management and job
scheduling system" (<https://slurm.schedmd.com/quickstart.html>). On a batch cluster the unit of tenancy is
the job allocation: `sbatch` submits a script, the scheduler grants CPUs/memory/GRES for a `Timelimit`,
and everything the script spawns runs inside a cgroup the step daemon (`slurmstepd`) created for that
step. The cgroup v2 layout is documented, not inferred: with `CgroupJobIdPaths=yes` the doc shows the
job directory as `/sys/fs/cgroup/system.slice/slurmstepd.scope/job_123/`; without it the directory name
is the job's SLUID (`.../slurmstepd.scope/sEKNKTV3WPV500/`), which "restores the pre-26.05 cgroup/v2
path layout" (<https://slurm.schedmd.com/cgroup.conf.html>). `ConstrainDevices` is a cgroup knob:
`ConstrainDevices=<yes|no>` "constrain[s] the job's allowed devices based on GRES allocated resources"
— that is how GPUs are fenced per job (<https://slurm.schedmd.com/cgroup.conf.html>).

The batch-script artifact on the compute node is verifiable in source: the step daemon stages the
submitted script as a file literally named `slurm_script` under the step's batch directory
(`src/slurmd/slurmstepd/mgr.c`, SchedMD/slurm master, `_batch_script_path()` returns
`xstrdup_printf("%s/%s", step->batchdir, "slurm_script")`) (<https://raw.githubusercontent.com/SchedMD/slurm/master/src/slurmd/slurmstepd/mgr.c>).
A `ps`/`pstree` walk on a compute node therefore reads: `slurmstepd` → batch step → the staged
`slurm_script` interpreter → the workload.

Cloud batch APIs are the same control plane with the provider as operator, and both price the
*scheduler* at zero — the money is in the underlying machines: AWS states "There is no additional
charge for AWS Batch. You pay for AWS resources (e.g. EC2 instances, AWS Lambda functions or AWS
Fargate)" (<https://aws.amazon.com/batch/pricing/>, fetched 2026-11-01); Google states "There is no
additional cost for using Batch. You only incur charges for any billable Google Cloud resources that
are used by Batch jobs" — and its report labels cover GPUs, persistent disks and VMs, not network
bytes (<https://cloud.google.com/batch/pricing>, fetched 2026-11-01). A squat inside a billable batch
job is a squat the victim pays for per VM-hour, with genuinely no cost signal from the batch service.

## 2. Documented incidents, at reporting level

**EGI-CSIRT, "Attacks on multiple HPC sites" (TLP:WHITE, page last updated 2020-05-18 11:00).** Two
incident families, #EGI20200421 and #EGI2020512, both built on compromised SSH credentials. #EGI20200421:
"a malicious group is currently targeting academic data centers for CPU mining purposes"; compromised
hosts were "turned into different roles": XMR mining hosts ("running a hidden XMR binary"), XMR-proxy
hosts, SOCKS proxy hosts ("running a microSOCKS instance on a high port"), tunnel hosts ("configure
NAT PREROUTING"); hiding techniques include the Diamorphine Linux kernel module ("It is not fully
understood how SSH credentials are stolen, although some (but not all) victims have discovered
compromised SSH binaries"), and "at least in one case, the malicious XMR activity is configured (CRON)
to operate only during night times to avoid detection". Victims across Europe, China and North America.
The forensic artifact list for #EGI2020512 includes a suid binary at `/etc/fonts/.fonts` whose payload
is `setgid(0); setuid(0); execl('/bin/bash/', ...)` and a log cleaner that removes entries matching
specific users (<https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/>).
None of this reporting names a scheduler command — the intrusions hopped login nodes. The
application-level shapes (night-only activity windows, relay roles inside a research tenant) are the
transferable part; the exact "`sbatch` with GPU and a miner" job-shape is *not* documented in
threat-intel sources I could reach, and section 3 says so honestly.

**The May 2020 outage wave.** DataCenterDynamics' summary lists ARCHER (University of Edinburgh,
"security exploitation on the ARCHER login nodes", all passwords/SSH keys rewritten), five bwHPC
clusters shut down including Hawk at Stuttgart, a Barcelona system taken offline, LRZ, Jülich's
JURECA/JUDAC/JUWELS, Taurus at TU Dresden, an LMU Munich physics cluster and CSCS, which "detected
malicious activity as well" and shut external access (<https://www.datacenterdynamics.com/en/news/european-supercomputers-hacked-mine-cryptocurrency/>).
ESET's report of the same period cites the EGI-CSIRT analysis: "the bad actor used compromised SSH
credentials to gain access to the systems and use them to mine Monero"
(<https://www.welivesecurity.com/2020/05/18/european-supercomputers-hacked-mine-cryptocurrency/>).

**The 2026 model-hub GPU campaign.** Pluto Security's report documents the head-first branch that
skips login nodes entirely: 31 repositories across seven Hugging Face accounts in two waves, posing
as small Qwen2 test checkpoints, mining via Kryptex into the operator's wallets; targets named are
"GPU hosts running self-hosted inference, especially Xinference and GPUStack, along with rented GPU
machines, shared research notebooks and CI jobs that pull small test models without anyone reading
the code"; "novel" delivery detail: `config.json` `auto_map` triggers `Transformers` to download and
import attacker Python when a user loads the model with `trust_remote_code=True`; removal did not
end the campaign — the second wave arrived "within days of takedown" and a near-identical copy
uploaded 2026-10-25 was still live with a miner and a reverse shell
(<https://pluto.security/blog/hugging-face-malware-campaign-load-mine>). This is the shared-cluster
shape this file cares about: someone else's shared GPU cluster ran the miner for six minutes because
a user loaded a poisoned "test checkpoint". The notebook-facing parts of that story (kernel child
processes, connection files, history DBs) belong to `jupyter-multitenant-detection.md`.

## 3. What the record does not support

I could not find a published threat-intel case study naming a miner submitted *as a Slurm job*
(`sbatch --gres=gpu` + miner, or a miner chained from `srun`) with process-tree and cgroup evidence.
The industry record documents mining *on* managed HPC hosts (EGI), mining *of* login nodes (ARCHER),
and mining *of* shared GPU notebook pools (Pluto 2026). The job-shaped mechanics in this file rest on
verified scheduler behaviour (source, docs) rather than on a published incident report with a
`sbatch` in it. MITRE's T1496 (Resource Hijacking) frame applies either way
(<https://attack.mitre.org/techniques/T1496>).

## 4. What the compute is worth, and why the GPU side is the target

**Free quota buys nothing but buys repeatedly.** Colab's free tier runs at most 12 h
(<https://research.google.com/colaboratory/faq.html>); Kaggle grants a weekly GPU quota of
"30 hours or sometimes higher" (<https://www.kaggle.com/docs/efficient-gpu-usage>); both are account-level
controls: Colab's enforcement is runtime termination and account blocks (its FAQ lists "downloading
torrents or engaging in peer-to-peer file-sharing" and "mining cryptocurrency" as disallowed from all
managed runtimes). These free notebooks — `jupyter-multitenant-detection.md` covers the relay side,
`REPORT.md` §1.5 the inventory — are compute pools for the short term: short-lived, throttled, but free.

**Paid market anchors, published same-day.** Lambda's on-demand price list, fetched 2026-11-01:
H100 SXM 80 GB at $3.99/GPU-hr, A100 80 GB at $2.79, A100 40 GB at $1.99, V100 16 GB at $0.79
(<https://lambda.ai/pricing>). At the H100 price, one month of one GPU runs about $2,900 ≈ $87/day;
a squat worth 24 GPU-hours/day therefore displaces roughly $87/day of paid capacity, on hardware the
victim already runs and cools. Vast.ai's own page makes the arbitrage explicit: "Prices set by supply
and demand across 40+ data centers", with an "Interruptible" tier described as "50%+ cheaper …
Preemptible — may be reclaimed" (<https://vast.ai/pricing/>) — an interruptible GPU market is the
complementary good for stolen capacity, and it is why a low-value buyer exists at all.

**Cluster accounts are the zero-cost tier above free quota.** A student or staff account on a
university or federal HPC system comes without a card, without per-user egress accounting, and —
on the documented EGI record — with SSH keys as the only door. The HPC leaf on the *provider-policy*
side mirrors the free-tier leaf: these sites publish usage policies (Kaggle's AUP bans "server
farming"; `REPORT.md` §1.5 quotes it), but the university scheduler substitutes procedure for policy:
fair-share decay and QOS caps. Fair-share can be configured "to be the dominant factor" in the
multifactor priority (<https://slurm.schedmd.com/priority_multifactor.html>); the association limits
the knobs the administrator may rely on are in the Detection recipe (R9) below.

## 5. What the scheduler itself exposes (admin-facing, per-job)

**`sacct` — the completed- and running-job history.** Verified fields on the man page include `JobID`,
`JobName`, `Partition`, `User` ("the user name of the user who ran the job"), `Timelimit`, `Start`,
`End`, `State` (the page also lists the state codes: `CA CANCELLED`, `CD COMPLETED`, `OOM
OUT_OF_MEMORY`, `PD PENDING`, `R RUNNING`, `S SUSPENDED`, `TO TIMEOUT`), `AllocTres`, `ConsumedEnergy`,
and the aggregation triplet `AveDiskRead`/`AveDiskWrite`/`AveRSS` (`AveDiskRead`: "Average number of bytes read by
all tasks in job") (<https://slurm.schedmd.com/sacct.html>), Note the access limit, verified in the
same page: "If designated, the slurmdbd.conf option PrivateData may further restrict the accounting
data visible to users which are not SlurmUser, root, or a user with AdminLevel=Admin" — a
non-admin's `sacct` may legitimately show less than an admin's.

**`sstat` — per-job step statistics while running.** Verified fields: `MaxRSS` ("the maximum memory
consumption seen by one of the tasks of the step"), `MaxDiskRead` ("Maximum number of bytes read by
all tasks in job"), `MaxDiskReadNode`, `MaxDiskReadTask`, `MaxDiskWrite` and friends
(<https://slurm.schedmd.com/sstat.html>). These are *disk* and *memory* metrics — the word "MaxDiskRead"
does not mean network throughput, and no field on either page reports socket bytes.

**`squeue` — the live queue.** Verified format fields: `%i` job id, `%N` node list, `%u` user name,
`%Z` "The job's working directory", `%D` number of nodes, `%C` number of CPUs, `%m` "Minimum size of
memory (in MiB) requested by the job"; `-t`/`--states=` filters states and `--me` is "Equivalent to
`--user=<my username>`" (<https://slurm.schedmd.com/squeue.html>). `sinfo` reports node-side state:
`%C` there is "Number of CPUs by state in the format allocated/idle/other/total" and `%D` the number
of nodes — node-level utilisation without per-job attribution (<https://slurm.schedmd.com/sinfo.html>).

**What the field lists do not contain.** The TRES page enumerates every accountable resource: "BB
(burst buffers), Billing, CPU, Energy, FS (filesystem), GRES, IC (interconnect), License, Mem, Node,
Pages, VMem" — FS/disk and IC are "primarily there for reporting usage, not limiting access"
(<https://slurm.schedmd.com/tres.html>). No network TRES type exists, so Slurm has no native per-job
egress counter. That is the load-bearing negative for the detection side: everything the corpus
measures as bytes-per-unit (`IPEgressBytes`) has to be rebuilt at the cgroup layer below Slurm.

## 6. Why the host-level corpus recipes do not transplant directly

The corpus recipes that assume "one unit = one tenant" break on a cluster in three places:

1. **No systemd unit per job, so no `IPEgressBytes`.** `IPAccounting=yes` is a systemd *service*
   concept (verified in `ci-runners-and-build-farms.md` §5 against
   <https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html>), and Slurm
   jobs are cgroups under the `slurmstepd.scope` hierarchy, not services the unit manager launched.
   `systemctl show -p IPEgressBytes <job>` has no object to show.
2. **The operator's root ends at the site boundary.** A university or federal HPC admin is not the
   provider's kernel administrator; `HARDENING.md`'s stance that single-host eBPF recipes need root on
   the *serving* host holds — but on a cluster the compute nodes are rootless for users, and
   the "operator" in this dataset is a user of the tenant, not the site ops. Detection that requires
   installing a probe on 400 nodes is out of reach for the corpus buyer.
3. **The measurement is per-node at best.** `sinfo` CPU-state counts and sacct `AveRSS`/`MaxDiskRead`
   trend at job granularity; traffic per job is missing (section 5), so "which of these 40 running
   jobs is the relay" needs a host-side observation the scheduler does not ship.

The bridge that does survive is nftables' `socket cgroupv2` matching (verified for syntax in
`jupyter-multitenant-detection.md` §4 against the nft man page), pointed at the documented per-job
path instead of a unit path: with `CgroupJobIdPaths=yes`, a sweep is
`ls /sys/fs/cgroup/system.slice/slurmstepd.scope/` and a per-job rule is
`socket cgroupv2 level 2 "system.slice/slurmstepd.scope/job_<id>"`. I have not executed this against a
running Slurm cluster (see What I could not verify); the honest shape is "one rule per live job path,
regenerated when the job list changes".

## 7. Known evasion shapes at the scheduler layer

| shape | why the plain check misses it |
|---|---|
| `sbatch --wrap` holding the allocation | the job script is a plain `sh` wrapped around any string — no script file to read, no `#SBATCH` block to scan (verified behaviour: sbatch page) |
| long `Timelimit`, GPU requested, workload starts late | the queue field values are ordinary; nothing distinguishes a miner held for 30 h from a benchmark held for 30 h |
| night-only activity (documented at EGI) | the CRON window defeats any daytime sampling recipe regardless of layer (<https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/>) |
| job-spawned relay (`ssh -R`, `socat`, microSOCKS on a high port) | outbound-only from inside the job cgroup; no listener recipe (`ss -tlnp`) fires (relay shapes documented at EGI, same page) |
| NAT `PREROUTING` on a node | the packet never belongs to a job-local socket for the cgroup match (<https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/>) |
| self-resubmission chain | the job re-`sbatch`es itself from inside its own allocation; the persistence lives in the *queue*, which looks like a normal user submitting daily |
| rootkit hiding the squat (Diamorphine, documented at EGI) | host-side `ps`/`ss` reads are themselves the compromised instrument — `rootkits-that-hide-the-squat.md` owns this layer |
| poisoned dependency inside a legitimate job (2026 HF shape) | the miner is a child of `python` doing the job's own work; the job is real, the dependency is not (<https://pluto.security/blog/hugging-face-malware-campaign-load-mine>) |

## Detection recipe (cheapest first)

Numbers in commands below are verified against the linked man pages (Slurm 26.05 pages fetched 2026-11-01 in all cases).

**R0 — who holds allocations?** On any cluster with `squeue` reachable:
```bash
squeue -h -t R -o "%i|%N|%u|%Z|%D|%C|%m"
```
`%i` job id, `%N` node list (squeue's own default step format reads `%.15i %.8j %.9P %.8u %.9M %N`), `%u` user,
`%Z` working dir, `%D` nodes, `%C` CPUs, `%m` memory-per-node. A user
holding many times their fair share of long-running wide jobs shows here before any forensics.
*FP:* indefinite-queue sweeps of healthy labs share the queue space's size; queue shape alone is not
a verdict.

**R1 — history per user, self-service.** `sacct -S <date> -u <user> -o JobID,JobName,User,Partition,State,Start,End,Timelimit` — fields verified.
*FP:* `PrivateData` can blank users other than yourself; a user's own view is not the admin's view.

**R2 — per-job resource deltas.** `sstat -j <jobid> --format=MaxRSS,MaxDiskRead,MaxDiskWrite` for
running steps; after the fact `sacct -j <jobid> -o AveRSS,AveDiskRead,AveDiskWrite` (both verified).
A CPU-bound compute job with near-zero `MaxRSS` growth and a talking socket is the relay profile.
*FP:* disk-accounting depends on how the cluster's `JobAcctGather` is configured; absent sampling
shows as blanks, which is also what a less-sampled job looks like.

**R3 — walk the job's process tree on one node.** On any node you can reach as the job's owner:
`ps -ef --forest | grep -A8 slurmstepd` and look for ancestry through the staged `slurm_script` file
(name verified in SchedMD/slurm `src/slurmd/slurmstepd/mgr.c`). *FP:* healthy MPI/Spark children
also descend from `slurmstepd`; the discriminator is whether children match the allocation shape
submitted.

**R4 — the job's cgroup path.** `cat /proc/<pid>/cgroup` on an owned job shows the cgroup v2 path;
the documented job directory shape is `/sys/fs/cgroup/system.slice/slurmstepd.scope/<sluid-or-job_123>`
(cgroup.conf doc). With `CgroupJobIdPaths=yes` the enumerator is:
```bash
ls /sys/fs/cgroup/system.slice/slurmstepd.scope/
```
*FP:* the path *form* changed across 26.05 (SLUID-name vs `job_N`), so a hard-coded regex to one form
silently matches nothing on a cluster running the other.

**R5 — egress attribution below the scheduler.** With the `CgroupJobIdPaths=yes` layout, nftables
`socket cgroupv2 level 2 "system.slice/slurmstepd.scope/job_<id>"` can count a job's packets without
a daemon (`jupyter-multitenant-detection.md` §4 pattern). Untested on a live Slurm node here — see
What I could not verify. *FP:* processes that connect *before* joining the cgroup escape the match; pre-26.05 SLUID paths churn every job.

**R6 — non-loopback listeners inside allocations.** On a node where you may run `ss -tlnp` at all
(admin or owner of the socket): the tunnel shapes are outbound-relayed, so this mostly catches
reverse-shell listeners that bind back onto the cluster. *FP:* any real MPI/dev tool that binds
per-node debug ports.

**R7 — content signatures end-to-end.** Stratum first-byte matches (`{"id`: `0x7b226964`) and the
`ss` port classes carry over unchanged from `network-flow-heuristics-proxyjacking.md` and
`ci-runners-and-build-farms.md` R2. R0–R6 are the before-signal on a cluster with no traffic
panels; content checks are the after-signal once a window is known. *FP:* dev ports 3333/5555/7777
are ordinary lab software.

**R8 — the artifacts a job script leaves behind.** Default capture is on: sbatch's own doc states
"By default both standard output and standard error are directed to a file of the name
`slurm-%j.out`" on the first node of the allocation (<https://slurm.schedmd.com/sbatch.html>); then
`~/.bash_history` of the submitting account, the wall-clock state (`sacct -o Start,End`) and the
job's `Timelimit` all trail the abnormal profile. *FP:* legitimate notebooks write `.out` files too.

**R9 — resisting the arithmetic (admin controls).** Documented association/QOS knobs:
`MaxJobsPerUser`, `MaxSubmitJobsPerAccount`/`PerUser` ("running and pending at a given time"),
`MaxWallDurationPerJob` (<https://slurm.schedmd.com/resource_limits.html>); fair-share as the dominant
priority factor (<https://slurm.schedmd.com/priority_multifactor.html>); `scancel` without `--signal`
"will send first a SIGCONT … followed by a SIGTERM, then … SIGKILL" after `KillWait`
(<https://slurm.schedmd.com/scancel.html>), and `scancel -t RUNNING -u <user>` scopes the kill to
their running jobs. Job-step teardown itself is verifiable in Slurm source: at step end the step
daemon signals its process container with SIGKILL and waits for it
(`proctrack_g_signal(step->cont_id, SIGKILL); proctrack_g_wait(...)` in
`src/slurmd/slurmstepd/mgr.c`) — so leftover `nohup` children do not outlive the allocation; what
persists is the *resubmission*, not the process.

## Sources

All fetched or read 2026-11-01 (Pluto Security report published within the previous week of that date).

- Scheduler docs (Slurm 26.05 pages as served by schedmd.com): <https://slurm.schedmd.com/sbatch.html> · <https://slurm.schedmd.com/sacct.html> · <https://slurm.schedmd.com/sstat.html> · <https://slurm.schedmd.com/squeue.html> · <https://slurm.schedmd.com/sinfo.html> · <https://slurm.schedmd.com/scancel.html> · <https://slurm.schedmd.com/cgroup.conf.html> · <https://slurm.schedmd.com/tres.html> · <https://slurm.schedmd.com/resource_limits.html> · <https://slurm.schedmd.com/priority_multifactor.html> · <https://slurm.schedmd.com/quickstart.html>
- Slurm source: <https://raw.githubusercontent.com/SchedMD/slurm/master/src/slurmd/slurmstepd/mgr.c>
- Incidents: <https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/> · <https://www.datacenterdynamics.com/en/news/european-supercomputers-hacked-mine-cryptocurrency/> · <https://www.welivesecurity.com/2020/05/18/european-supercomputers-hacked-mine-cryptocurrency/> · <https://pluto.security/blog/hugging-face-malware-campaign-load-mine> · <https://dailysecurityreview.com/cyber-security/hugging-face-mining-malware-returns-model-hits-28000-downloads>
- Free-tier / pricing / policy: <https://research.google.com/colaboratory/faq.html> · <https://www.kaggle.com/docs/efficient-gpu-usage> · <https://lambda.ai/pricing> · <https://vast.ai/pricing/> · <https://aws.amazon.com/batch/pricing/> · <https://cloud.google.com/batch/pricing>
- Framework: <https://attack.mitre.org/techniques/T1496>

## What I could not verify

- **An `sbatch`-shaped mining incident as documented threat intel.** The EGI-CSIRT record describes miners *on* HPC hosts reached through compromised SSH credentials, not miners submitted *as* jobs; I searched for case studies naming `sbatch`/`srun` payloads with process-tree or cgroup evidence and found none I could reach. If one exists in paywalled CSIRT or campus-IR reporting that never got published, this section would change shape.
- **nftables `socket cgroupv2` counts against a live Slurm per-job cgroup.** The `slurmstepd.scope/job_N` path is documented; the nft syntax is verified in the corpus for *service* paths in `jupyter-multitenant-detection.md`. I did not have a Slurm node with cgroup v2 + `CgroupJobIdPaths=yes` to run a rule against; whether sockets opened inside a job attribute to the job's child cgroup rather than to the `slurmstepd.scope` ancestor is unresolved.
- **Which processes' sockets land in which cgroup when NAT/PREROUTING is set.** The EGI document records tunnel hosts with NAT rules; whether the forwarded traffic shows as a job-socket at all (and therefore whether a `socket cgroupv2` count sees it) is untested. My §7 row assumes the standard result (forwarded packets carry no local socket) — carried over from `HARDENING.md`'s `-m owner cannot see forwarded packets` finding, not re-verified here.
- **Kaggle's exact current GPU hour ceiling beyond "30 hours"**: the doc states "30 hours or sometimes higher depending on demand and resources", without a firm upward bound. Default GPU model availability (T4 vs P100) also varied by page version; the quote is the verified part.
- **Vast.ai live per-hour figures.** The pricing page renders numbers client-side; I verified its tier structure ("Interruptible", "50%+ cheaper", "40+ data centers") but no dated per-GPU price could be quoted first-hand.
- **GCP/AWS batch: whether per-job *network* reporting exists anywhere in their billing surfaces.** GCP's page names GPU/VM/disk labels explicitly and notes some networking charges "do not appear specifically when filtering on Batch labels"; AWS's page shows no per-job network service at all. I did not chase their deeper billing-API docs.
- **LMU Munich, Barcelona and LRZ post-mortems at source.** The DCD summary names them; I did not find archived primary statements from each site (link rot on the 2020 announcements). Affected-system names and dates are from DCD/ESET secondary reporting, verified only at that level.

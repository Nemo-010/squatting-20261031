# Storage you were not given: quota escapes and host-backed paths in container sandboxes

> **First-hand, measured 2026-11-02.** One rented container sandbox, explored from inside with the
> tenant's own credentials. The platform is called **VendorD** here; addresses and identifiers are
> placeholders.
>
> The short version: the sandbox advertises a 10 GB disk, enforces it on `/`, and leaves **2.1 TB
> writable** two directories away because a set of host paths are bind-mounted into the container. The
> quota is real and irrelevant at the same time.

*Scope: Linux containers on a managed sandbox platform (Docker/containerd with hostPath or emptyDir
mounts), observed from a root shell inside the tenant's own container. No host access, no exploit.*

## Summary

- The container's own filesystem is an overlay capped at **10 GB**, and the cap is enforced: a 12 GB
  `fallocate` on `/` fails with `ENOSPC`.
- Seven host paths are bind-mounted read-write and land on a **4 TB XFS volume with 2.1 TB free**:
  `/var/lib/docker`, `/var/lib/kubelet`, `/var/lib/k0s`, `/var/lib/buildkit`,
  `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs`, `/var/lib/rancher/k3s`,
  `/var/lib/rancher/rke2`.
- All seven accept writes. A 2 GiB write to one of them runs at **1.9 GB/s**, and a 20 GiB
  `fallocate` succeeds.
- The path is the least of it: `mount --bind` and `fuse-overlayfs` both work, so the tenant gets a
  4 TB filesystem at a mountpoint of their choosing, and a build can redirect every write there.
- There is **no `io.max`**: the sandbox has a byte quota and no rate ceiling, so filling the node
  volume starves every other sandbox on it.
- The list is not a platform quirk. It is a *template*: any container runtime deployment that mounts
  its data directories into the sandbox, or that uses `emptyDir` for a scratch path, hands over
  whatever volume backs them.
- The container reports the **host's** CPU and memory (`nproc` 48, `free` 193 GiB) while its cgroup
  allows 4 CPU and 4 GiB. A workload that sizes itself from `free` is OOM-killed while believing it
  has room.
- Detection is easy and almost never deployed: compare each mount's capacity with the declared quota,
  and bill per-container volume growth rather than base-image size.

## 1. The measured case

`df -hT` inside the container returns three substantially different storages:

```console
$ df -hT | grep -vE 'tmpfs|devtmpfs'
Filesystem         Type     Size  Used Avail Use% Mounted on
overlay            overlay   10G   53M   10G   1% /
/dev/mapper/mpatha xfs      4.0T  1.9T  2.1T  47% /etc/hosts
/dev/sda1          ext4      48G   18G   30G  38% /usr/local/bin/<agent>
```

Two of those lines are mounted files. The one that matters is the middle line, and `df` only shows it
because it lands on a path that happens to exist. The full picture comes from `/proc/self/mountinfo`,
where every host bind appears with its own target:

```console
$ awk '{print $5" | "$3}' /proc/self/mountinfo | grep -E '^/var'
/var/lib/kubelet | 252:0
/var/lib/k0s | 252:0
/var/lib/buildkit | 252:0
/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs | 252:0
/var/lib/docker | 252:0
/var/lib/rancher/k3s | 252:0
/var/lib/rancher/rke2 | 252:0
```

All seven resolve to the same device (`252:0`, `dev=fc00`), all are the mount root of a 4 TB XFS
filesystem, and all are writable:

```console
$ touch /var/lib/docker/.wtest && echo WRITABLE
WRITABLE

$ fallocate -l 20G /var/lib/docker/.big && ls -lh /var/lib/docker/.big
-rw-r--r-- 1 root root 20G ... /var/lib/docker/.big

$ dd if=/dev/zero of=/var/lib/docker/.cap bs=1M count=2048 conv=fsync
2147483648 bytes copied, 1.11692 s, 1.9 GB/s
```

Meanwhile the quota behaves exactly as advertised:

```console
$ fallocate -l 12G /.overlaytest
fallocate: fallocate failed: No space left on device
```

So the honest statement is not "the quota is broken". It is: **the quota applies to one filesystem
and the platform mounted seven others.**

Each of those directories was empty at first look (`/var/lib/docker/containers` did not exist, so no
other tenant's container metadata is exposed). Whether they are per-sandbox directories on a shared
volume or genuinely shared host paths is not determinable from one sandbox — see the last section.

## 2. From a path to a volume

The measured case reads as though the tenant has to write to a path that looks like a mistake. It does
not. A bind mount, or a FUSE overlay, turns the path into a filesystem with a name of the tenant's
choosing, and nothing inside the sandbox can tell it from a volume the platform sold.

```console
$ mount --bind /var/lib/docker /mnt/storage2 && df -h /mnt/storage2 | tail -1
/dev/mapper/mpatha  4.0T  1.9T  2.1T  47% /mnt/storage2

$ fuse-overlayfs -o lowerdir=/,upperdir=/var/lib/docker/.upper,workdir=/var/lib/docker/.work /mnt/storage
$ mountpoint -q /mnt/storage && echo MOUNTED
MOUNTED
```

Both are `mount(2)` and both need `CAP_SYS_ADMIN`; this sandbox had all 41 capabilities, so both
succeeded on the first attempt. The overlay variant is the more useful of the two, because it presents a
*writable root* over any lower layer, which is what a build or a package install actually wants: the
container's 10 GB `/` stops being the write target at all, and every write that would have filled it
lands in the upper directory on the 4 TB volume instead.

| mount | result here | note |
|---|---|---|
| `mount --bind /var/lib/docker /mnt/x` | works | simplest; no helper binary needed |
| `fuse-overlayfs -o lowerdir=/,upperdir=…,workdir=… /mnt/x` | works | writable overlay, upper layer on the big volume |
| `mount -t fuse …` by hand | refused | needs the `fusermount` helper; the syscall alone is not enough |
| `unshare -Um` then mount | refused | user-namespace mounts denied even though `unshare -U` succeeds |
| `/dev/kvm` | denied | device cgroup, not a capability |

What the tenant ends up with is not "2.1 TB at an odd path" but "a 4 TB filesystem at `/storage`", and
the difference matters for everything downstream: a package manager that refuses to install outside
`/var/lib`, a build that hardcodes `/workspace`, a backup that walks named mountpoints. The declared
quota never enters the conversation.

Two operational details. The mount survives for the container's lifetime — the `fuse-overlayfs` process
was still in `/proc/mounts` twenty minutes later, alongside eight fuse entries — and it dies with the
container, so it is a storage vector and not a persistence one. And the overlay's upper directory is a
plain directory on the bind, so its contents outlive an unmount of the overlay itself.

### 2.1 No IO ceiling behind the quota

```console
$ cat /sys/fs/cgroup/io.max
(empty)
$ cat /sys/fs/cgroup/cgroup.controllers
cpuset cpu io memory hugetlb pids rdma misc dmem
```

The cgroup exposes an `io` controller and sets no limit on it. So the sandbox has a storage ceiling in
*bytes* (10 GB) and no rate ceiling at all on the volume behind the bind. A tenant can fill the node's
shared volume until the node fills, which affects every other sandbox on it, and nothing per-container
stops them.

This is the more serious half of the finding for a platform, and it does not require any abuse at all:
a legitimate build with a large cache does it by accident. The quota protects the tenant from
themselves; it protects nobody else.

## 3. Finding it in ten seconds

The check is a comparison, not a scan: any mount whose capacity is materially larger than the root
filesystem is memory, storage, or both that the platform did not intend to hand out.

```sh
# root quota, in KB
root=$(df -kP / | awk 'NR==2{print $2}')

# every real filesystem, compared against it
awk '$3!="overlay" && $3!="tmpfs" {print $2, $5}' /proc/mounts |
while read -r fstype target; do
	case $fstype in
	proc|sysfs|cgroup*|devpts|mqueue|ramfs|securityfs|debugfs|tracefs|configfs) continue ;;
	esac
	size=$(df -kP "$target" 2>/dev/null | awk 'NR==2{print $2}')
	[ -n "$size" ] || continue
	[ "$size" -gt $((root * 2)) ] && printf '%-8s %-10s %s (%.0fx root)\n' \
		"$(df -hP "$target" | awk 'NR==2{print $2}')" "$fstype" "$target" \
		"$((size / root))"
done
```

`checks/storage-reach.sh` in this repository is exactly that, with the writability test and the
`--max` guard (it refuses to fill anything, it only reports).

## 4. Where platforms leave host paths

The pattern is generic. A sandbox that runs containers on a node, or that gives you a "workspace" with
nested runtime access, will expose some of:

| path | why it exists | what it usually hands over |
|---|---|---|
| `/var/lib/docker` | DinD sidecar, or a runtime socket shim | the node's image and overlay storage |
| `/var/lib/containerd/...` | the same, newer runtime | snapshotter storage, often the largest volume |
| `/var/lib/kubelet` | Kubernetes-in-sandbox (k3s, k0s, RKE2) | emptyDir backing, which is the node volume |
| `/var/lib/buildkit` | builds inside the sandbox | build cache, unbounded by the sandbox quota |
| `/var/lib/rancher/*` | k3s/RKE2 default state dir | whatever the node mounted for it |
| `/etc/hosts`, `/etc/resolv.conf` | almost always file bind-mounts | **the whole filesystem behind them**, per `df` |
| `/usr/local/bin/<agent>` | the platform's own supervisor | the node's boot disk |

Two of these are worth dwelling on. The `/etc/hosts` entry is the cheapest probe in the world: `df
/etc/hosts` routinely reports the node's data volume, because the file is a bind of a file that lives
on it, and `df` answers per filesystem rather than per file. And the agent binary at `/usr/local/bin`
in this case sat on `/dev/sda1` — the node's **boot** disk, 48 GB with 30 GB free, mounted into the
container as a single file.

A squatter does not need any of these to be *empty*. They need one to be writable, and [§1](#1-the-measured-case)
shows they do not need to be shared either.

## 5. What the quota actually binds

Nothing that a careless workload cares about, and everything that a careful one does.

| the quota binds | the quota does not bind |
|---|---|
| the overlay root, which is where a naive `dd` goes | any bind-mounted host path |
| the container image layers | the node volume behind them |
| anything under `/`, `/tmp`, `/var/tmp`, `$HOME`, `/mnt` | `/dev/shm` when it is `shm_size`-capped, and any `tmpfs` the tenant mounts itself with `CAP_SYS_ADMIN` |
| the filesystem the platform bills against | the filesystem the platform actually filled |

The asymmetry is the whole trick. Billing, quota accounting and abuse dashboards in almost every
managed sandbox are keyed to the container's overlay; the node volume is a platform cost centre that
nobody attributes to a tenant. A tenant that writes 2 TB to `/var/lib/docker` shows up as a 10 GB
container with an empty root.

There is a second asymmetry in the same measurement, and it caught this survey out. The container
reports the **host's** resources:

```console
$ nproc; free -m | awk '/^Mem:/{print $2}'
48
193206

$ cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max
400000 100000
4294967296
```

48 cores and 193 GiB reported; 4 cores and 4 GiB allowed. A workload that reads `nproc` and sizes a
thread pool to it, or that sizes a buffer from `free`, will be OOM-killed or throttled while it
believes the machine is mostly idle. For a squatter this is a trap rather than an advantage — but it
is also an information leak: the guest learns the host's size, its device inventory (`/dev` carried
209 entries including `sda`..`sdf`, `dm-0`, `nvme-fabrics`) and, in this case, the node's boot volume
size.

Device *nodes* being visible is not device *access*. Every block device here was denied at `open(2)`
by the device cgroup while `/dev/kmsg`, `/dev/net/tun` and `/dev/fuse` opened normally. That is the
right split, and it is worth stating because the visible inventory reads like a horror story until it
is tested.

## 6. The trick, stated as a play

1. **Read the mount table, not the quota.** `df -h`, then `/proc/self/mountinfo` filtered to non-pseudo
   filesystems. The number you were told is one line out of a dozen.
2. **Prefer a writable bind over a writable tmpfs.** The bind is backed by disk the platform owns and
   does not attribute to you; a tmpfs is charged to your memory cgroup and will OOM you.
2a. **Give it a name.** `mount --bind` the path, or build a `fuse-overlayfs` with its upper layer on
   it, so the storage appears where the workload expects a volume. A build that hardcodes `/workspace`
   or a package manager that refuses to write outside `/var/lib` will not use a path it was not told
   about.
3. **Write to the biggest, and clean up nothing.** Files under `/var/lib/docker` are invisible to
   anything that inspects the image or the overlay, which is what the platform's own tooling reads.
4. **Keep the root filesystem pristine.** An empty `df /` is the difference between a container that
   looks idle and one that looks full.
5. **Expect the node to be shared.** Anything written there may be visible to every other sandbox on
   the same node, so file modes matter even though you are root — see "what I could not verify".

This is the same economics as the rest of this corpus, moved down a layer: the platform pays per node
volume, the tenant is billed per container, and the difference is the margin.

## 7. The other quotas, tested one by one

The storage quota turned out to be the one that binds least. Testing the rest the same way — allocate
until refused, count the cores actually used — gives a table that is worth more than any single finding
in this document:

| resource | advertised to the tenant | enforced? | how it was established |
|---|---|---|---|
| memory | `memory.max` = 4 GiB | **yes** | a page-touching allocator reached 3.5 GiB and was SIGKILLed before 4 |
| cpu | `cpu.max` = `400000 100000` (4 CPUs) | **no** | 16 CPU-bound children finished 2 s of work in 2.00 s — 16 cores effective |
| io | `io.max` | **not set at all** | empty file; no rate ceiling exists to enforce |
| pids | `pids.max` = 16384 | unverified | a runaway fork storm pushed the host's load average past 3000 before the session dropped |
| disk on `/` | 10 GB overlay | **yes** | a 12 GiB `fallocate` fails with `ENOSPC` |
| disk on the bind | nothing was advertised | **n/a** | 2 TiB free and writable |

Two of those are the interesting ones.

**CPU is not charged.** `cpu.max` reads as four CPUs and the scheduler does not apply it: sixteen
CPU-bound children completed two seconds of work each in two seconds of wall time. The tenant is
getting the host's cores, which on this machine meant at least 16 of 48. For a platform selling a
"2 vCPU" tier, that is the whole margin.

**`/proc/loadavg` and `/proc/meminfo` are not namespaced.** They report the *host*: 48 cores, 193 GiB,
and a load average that reached three thousand during a runaway fork storm inside one container. The
first is an information leak — the tenant learns the node's size and, through load, whether neighbours
are busy. The second is a noisy-neighbour problem: one sandbox's fork storm is visible in every other
sandbox's `/proc/loadavg` on the same node, and in the platform's own monitoring.

That last point is also the cheapest detector for resource abuse that does not need per-container
accounting at all: a node whose load average and task count move without any container's own counters
moving is a container whose limits are not binding.

### 7.1 Page cache is charged to the tenant, and it OOMs the writer

Filling the bind mount is not free. A buffered write is charged to the container's `memory.max` as
page cache, so the same 20 GiB that would be trivial on a host is a SIGKILL inside a 4 GiB cgroup:

```console
$ dd if=/dev/zero of=/mnt/storage2/.buf bs=64M count=320 conv=fsync
Killed
$ cat /sys/fs/cgroup/memory.current
4159680512

$ dd if=/dev/zero of=/mnt/storage2/.dir bs=64M count=320 oflag=direct
21474836480 bytes copied, 12.5254 s, 1.7 GB/s
```

The first is killed at the cgroup ceiling; the second, bypassing page cache, completes. Two consequences
worth recording:

- **A tenant who fills the volume with ordinary tooling is killed before they fill it.** `dd`, `cp`,
  `tar` and most language runtimes write buffered. Only `O_DIRECT` or an explicit `posix_fadvise`
  clears the charge, which very little userland does.
- **The kill is not attributed to the storage at all.** It reads as an out-of-memory event in a
  container whose `free` said 189 GiB available, which is the worst possible diagnostic.

For the platform, the same fact is an accidental rate limit: the memory cgroup is doing the job that
`io.max` should be doing, and doing it by killing rather than by throttling.

## 8. Detection

Three checks, cheapest first, and the first one is free because the data already exists.

**Per-container volume growth, not image size.** If the platform exposes node-level disk metrics per
container (cAdvisor's `container_fs_*` covers the overlay; it does not cover a bind mount), the bind is
invisible to it. What is *not* invisible is the volume itself: the node's XFS usage (`1.9T` here) can be
attributed by walking the mount points the runtime created. A per-mount `du` on a schedule is crude but
it is the only thing that sees this.

**Compare each mount's capacity with the declared quota at admission time.** A sandbox that promises
10 GB and mounts a 4 TB filesystem into itself is misconfigured, and the configuration is readable
before the tenant ever logs in:

```sh
for t in $(awk '{print $5}' /proc/self/mountinfo); do
	df -kP "$t" 2>/dev/null | awk -v t="$t" 'NR==2 && $2 > 20971520 {print t, $2}'
done
```

**Bind mounts are visible to the tenant and should be visible to the platform.** Everything in §2
leaves `mountinfo` entries: a container that has mounted a bind over a host path, or started a
`fuse-overlayfs`, says so in `/proc/self/mountinfo` and in its process table. A platform that reads
the mount table of the sandbox it is running has a perfect record of this, and one that does not is
relying on the quota it already knows is bypassable.

**Alert on an empty root and a full node.** In the measured case the container's overlay was `53M` used
after twenty minutes of heavy work, and the node volume moved by gigabytes. That inversion — root flat,
node volume climbing — is the signature, and no per-container byte counter will show it because the
bytes never appear in the container's own filesystem.

## 9. What this does not give you

- **No host escape.** Device nodes existed and were denied; there was no path to the node's
  filesystem outside the mounted directories.
- **No durability.** The sandbox in this case was ephemeral: the host paths are real while the
  container lives and worthless after it is deleted.
- **No cross-tenant read**, at least not visibly: `/var/lib/docker/containers` was absent, so the bind
  was a fresh directory on a shared volume rather than the node's live Docker state.

## 10. What else the tenant can see of the platform

Two surfaces beyond storage, both cheap to enumerate and both worth a line in any sandbox review.

**The supervisor is PID 1 and it listens on localhost.** On the measured sandbox, `/usr/local/bin/<agent>
sleep infinity` held four listening TCP sockets inside the tenant's own namespace — an API-shaped one
returning `404` on every obvious path, an SSH-adjacent one, and two HTTP servers whose titles were
**"Web Terminal"** and **"Screen Recordings"**. The tenant can reach all of them with `curl`.

That is a design choice with two readings. It is convenient: the platform's own tooling is addressable
from inside. It is also a control plane inside the sandbox, and a squatter who wanted to make a host
lie has a natural target that is neither the kernel nor `/proc`. Nothing was done to them here beyond a
`GET /`, and none of them should be reachable from a tenant namespace without authentication the tenant
cannot read.

**The environment names the tenancy.** `VENDORD_*` variables carried the organization id, region,
sandbox id, snapshot name and sandbox user. Those are identifiers rather than credentials, and they are
the join key for everything else: a squatter who wants to be boring should not carry them into a child
process, because they tie a workload to a billing entity across sandbox recreations.

| surface | observed | why it matters |
|---|---|---|
| PID 1 | platform supervisor, not the workload | the tenant's process tree has a platform-owned root |
| listening sockets | 4, all reachable from the tenant | a control plane inside the boundary |
| env | organization, region, sandbox, snapshot ids | cross-sandbox join key for billing and abuse review |
| cron / systemd | neither running | no persistence vector inside the sandbox at all |

## Sources

Measured on a rented container sandbox, 2026-11-02: `df -hT`; `/proc/self/mountinfo`;
`/sys/fs/cgroup/{cpu.max,memory.max,pids.max}`; `nproc`; `free -m`; `dd ... conv=fsync`;
`fallocate`; `stat -c %D`; `open(2)` probes against `/dev/{sda,sdb,dm-0,kvm,mem,port,kmsg,tun,fuse}`.

Documentation: `proc(5)` for `/proc/self/mountinfo` field order; `mount(8)` and
`mount_namespaces(7)`; `df(1)` — "the space available on the *filesystem* containing the file";
the cgroup v2 `memory.max` and `cpu.max` interfaces; the device controller and its eBPF replacement
under cgroup v2, which is what denies `open(2)` on a block device whose node exists;
Docker's `--volume`/`--mount` and Kubernetes `hostPath`/`emptyDir` semantics for where a bind's bytes
actually live.

## What I could not verify

- **Whether the seven paths are shared between sandboxes.** They were empty and writable, consistent
  with either a per-sandbox directory on a shared volume or a shared node path. Settling it needs a
  second sandbox and a marker file — deliberately not done here, because writing outside one's own
  sandbox is the boundary this document is about.
- **Whether the platform bills for node-volume growth at all.** No billing data was available; the
  claim that billing is keyed to the overlay is an inference from how every platform of this shape
  behaves, not from an invoice.
- **Whether the 4 TB figure is per node or per tenancy.** `mpatha` is a multipath device; its mapping
  to a volume is not visible from inside the container.
- **Whether an `emptyDir` with a size limit was in force.** No `sizeLimit` was observable; the 20 GiB
  `fallocate` suggests not, but a lazy allocation and a generous limit are indistinguishable from one
  write.

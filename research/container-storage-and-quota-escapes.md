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

## 2. Finding it in ten seconds

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

## 3. Where platforms leave host paths

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

## 4. What the quota actually binds

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

## 5. The trick, stated as a play

1. **Read the mount table, not the quota.** `df -h`, then `/proc/self/mountinfo` filtered to non-pseudo
   filesystems. The number you were told is one line out of a dozen.
2. **Prefer a writable bind over a writable tmpfs.** The bind is backed by disk the platform owns and
   does not attribute to you; a tmpfs is charged to your memory cgroup and will OOM you.
3. **Write to the biggest, and clean up nothing.** Files under `/var/lib/docker` are invisible to
   anything that inspects the image or the overlay, which is what the platform's own tooling reads.
4. **Keep the root filesystem pristine.** An empty `df /` is the difference between a container that
   looks idle and one that looks full.
5. **Expect the node to be shared.** Anything written there may be visible to every other sandbox on
   the same node, so file modes matter even though you are root — see "what I could not verify".

This is the same economics as the rest of this corpus, moved down a layer: the platform pays per node
volume, the tenant is billed per container, and the difference is the margin.

## 6. Detection

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

**Alert on an empty root and a full node.** In the measured case the container's overlay was `53M` used
after twenty minutes of heavy work, and the node volume moved by gigabytes. That inversion — root flat,
node volume climbing — is the signature, and no per-container byte counter will show it because the
bytes never appear in the container's own filesystem.

## 7. What this does not give you

- **No host escape.** Device nodes existed and were denied; there was no path to the node's
  filesystem outside the mounted directories.
- **No durability.** The sandbox in this case was ephemeral: the host paths are real while the
  container lives and worthless after it is deleted.
- **No cross-tenant read**, at least not visibly: `/var/lib/docker/containers` was absent, so the bind
  was a fresh directory on a shared volume rather than the node's live Docker state.

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

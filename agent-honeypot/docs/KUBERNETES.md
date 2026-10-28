# Deploying on Kubernetes (EKS) with Helm

`deploy/helm/agent-honeypot` runs the reference architecture inside a cluster. On top of the planted decoys and decoy services it adds **Tetragon (eBPF) file watches**: any process in an agent pod that reads a decoy is caught at the kernel, even when it never goes through a wrapped tool. Optionally, Tetragon kills that process.

## Architecture

```
 namespace: ai-agents (untrusted)                       namespace: agent-honeypot (security)
 ┌───────────────────────────────────────────┐          ┌───────────────────────────────────────────────┐
 │ agent pod  label agent-honeypot/agent-id  │  HTTP    │ decoy Deployment (non-root, read-only, no     │
 │  ├ agent container ─ /workspace (decoys) ─┼────────► │  egress)  ◄── ExternalName aliases:           │
 │  └ tool-guard sidecar (AgentGuard,        │          │  decoy, legacy-payroll-db, model-registry     │
 │     /guard hashed registry, read-only)    │          │                                               │
 │                                           │          │ plant Job (hook) ─► EFS: /state  /guard       │
 │ TracingPolicyNamespaced (Tetragon eBPF)   │          │                          /workspaces/<agent>  │
 │  file reads / mmaps of decoy paths        │          │                                               │
 └──────────────────┬────────────────────────┘          │ tetragon-bridge DaemonSet ─► touch alerts     │
                    │ tetragon.log on each node ────────►│                                               │
                    │                                    │ hash-chained evidence (/state/evidence.jsonl) │
                    │◄── quarantine / delete ────────────┤ responder (Role: pods get/list/patch/delete)  │
                    │                                    └──────────────────────┬────────────────────────┘
                    │                                                           │ AHP_ALERT / AHP_RESPONSE logs
                    ▼                                                           ▼
          NetworkPolicy deny-all for                                Fluent Bit → CloudWatch / SIEM
          agent-honeypot/quarantine=true                            (optional: Terraform ingest → S3 Object Lock)
```

| Detection path | Catches | Response |
|---|---|---|
| tool-guard sidecar (AgentGuard) | discover / **use** of decoy secrets through tools | Halts inline, before egress |
| decoy service | **contact** from any pod in the agent namespace | Responder quarantines the pod with that **client IP** |
| Tetragon + bridge | **touch**: `cat`, `open()`, `mmap` of decoy files, bypassing tools | Alert (+ SIGKILL for `enforce: true` decoys when `tetragon.enforce=true`) |

## Prerequisites

1. **EKS ≥ 1.25** (any conformant cluster works with `storage.type=pvc`).
2. **Amazon EFS CSI driver** and an EFS file system with mount targets your nodes can reach on TCP 2049.
3. **Tetragon ≥ 1.1**, export file readable by non-root users:
   ```bash
   helm repo add cilium https://helm.cilium.io && helm repo update
   helm install tetragon cilium/tetragon -n kube-system --set tetragon.exportFilePerm=644
   ```
4. **NetworkPolicy enforcement.** On EKS, enable it in the VPC CNI add-on (`enableNetworkPolicy: "true"`), or use Calico/Cilium.
5. **The image**: push the tag `agent-honeypot-v0.1.0` (`git tag agent-honeypot-v0.1.0 && git push origin agent-honeypot-v0.1.0`); the `agent-honeypot release` workflow publishes `ghcr.io/cybersmeashish/agent-honeypot` (amd64 + arm64) and the chart to `oci://ghcr.io/cybersmeashish/charts`.

## Install

```bash
kubectl create namespace ai-agents
kubectl create namespace agent-honeypot
# hostPath for the Tetragon bridge requires "privileged"; use "baseline" if tetragon.bridge.enabled=false
kubectl label namespace agent-honeypot pod-security.kubernetes.io/enforce=privileged
kubectl label namespace ai-agents pod-security.kubernetes.io/enforce=restricted

helm install agent-honeypot deploy/helm/agent-honeypot -n agent-honeypot \
  -f deploy/helm/examples/values-eks.yaml
# or: helm install agent-honeypot oci://ghcr.io/cybersmeashish/charts/agent-honeypot --version 0.1.0 -n agent-honeypot -f values.yaml
```
The post-install hook plants decoys for every agent in `agents[]` (`kubectl -n agent-honeypot logs job/<name>-plant`).

## Wire your agents

See [`deploy/helm/examples/agent-deployment.yaml`](../deploy/helm/examples/agent-deployment.yaml). Each agent pod needs:

* the label `agent-honeypot/agent-id: <id>` (Tetragon only watches labelled pods; the responder finds pods by it);
* its workspace PVC `<fullname>-ws-<id>` mounted at `/workspace` (`agentWorkspaceMountPath`), running as the agent's `uid`;
* tools run in a sidecar that wraps them with `AgentGuard`, mounting `<fullname>-guard` read-only and using `HoneypotEngine.for_guard("/guard/guard-registry.json", ...)`;
* `automountServiceAccountToken: false`, so agents can't list the objects that would reveal the controls.

Adding an agent: append it to `agents[]` and `helm upgrade`. The hook plants only agents that haven't been planted yet.

## Test

> The first test is a decoy *contact*, so the responder will quarantine `agent-01`.

```bash
# network decoy (contact) -> alert + quarantine
kubectl -n ai-agents exec deploy/agent-01 -c agent -- \
  python -c "import urllib.request; print(urllib.request.urlopen('http://legacy-payroll-db/api/v2/payroll/records').read())"

# file decoy via eBPF (touch) - run against a fresh agent pod
kubectl -n ai-agents exec deploy/agent-02 -c agent -- cat /workspace/.aws/credentials.bak

kubectl -n agent-honeypot logs deploy/agent-honeypot-decoy | grep AHP_ALERT
kubectl -n agent-honeypot logs ds/agent-honeypot-tetragon-bridge | grep AHP_ALERT
kubectl -n agent-honeypot logs deploy/agent-honeypot-responder | grep AHP_RESPONSE
kubectl -n ai-agents get pods -L agent-honeypot/quarantine
kubectl -n agent-honeypot exec deploy/agent-honeypot-decoy -c decoy -- agent-honeypot --state /state report
```

## Kill switch (`responder.mode`)

| Mode | What happens to the pod |
|---|---|
| `quarantine` (default) | All labels except the agent id are removed and `agent-honeypot/quarantine=true` is added. The pod drops out of its ReplicaSet (a clean replacement starts), its Services and app-label NetworkPolicies; the chart's deny-all policy isolates it. It keeps running for memory/process forensics. Delete it once investigated. |
| `delete` | Pod deleted; its controller recreates it. |
| `notify` | Decision logged as `AHP_RESPONSE`, no action. |

Halts on: actions in `haltActions` (default `use`, `contact`), any `cross_agent` trigger, or `severity >= haltMinSeverity`. Plain file `touch` alerts don't halt unless the decoy's severity reaches the threshold (model weights = 5). Decoy contacts are targeted by **TCP client IP**, so a spoofed `X-Agent-Id` header can't get another agent quarantined.

## Tetragon enforcement

`tetragon.enforce=true` renders a SIGKILL selector for decoys with `enforce: true` (by default only the staged model weights). The process that opens them is killed in-kernel before it reads a byte; the bridge still records the event, with `enforced: true`. Start with `enforce=false`, review the alerts, then enable it.

## Ship alerts

All components print `AHP_ALERT {json}` (and the responder `AHP_RESPONSE {json}`). Route container logs with Fluent Bit / CloudWatch Container Insights to your SIEM. To reuse the Terraform pipeline (S3 Object Lock evidence, SNS, Security Hub), send these lines to a CloudWatch log group and add it to the module's `agent_log_group_names`. That Lambda's kill switch acts on ECS tasks only; in Kubernetes the responder plays that role.

## Storage modes

| `storage.type` | Isolation | Requirements |
|---|---|---|
| `efs` (recommended) | Registry + evidence PV only in the release namespace; each agent's PV exposes only `/workspaces/<id>`; guard PV read-only | EFS CSI driver, `storage.efs.fileSystemId` |
| `pvc` | One RWX PVC shared by subPath; isolation relies on pod specs | Any RWX StorageClass; `agentNamespace` must equal the release namespace |

Data PVs/PVCs carry `helm.sh/resource-policy: keep`, so `helm uninstall` doesn't destroy evidence.

## Limitations

* NetworkPolicies are additive. Quarantine works because the responder removes the labels other policies select on. Cluster-wide allow rules (e.g. Calico GlobalNetworkPolicy, Cilium clusterwide policies) can still apply; check them.
* The decoys only cover HTTP on the decoy service. Raw TCP to other ports isn't detected.
* Tetragon watches paths as seen inside the container, so agents must mount their workspace at `agentWorkspaceMountPath`.
* The bridge needs a privileged namespace (hostPath) and reads Tetragon's export file. If Tetragon exports elsewhere, set `tetragon.bridge.exportPath`.
* Guard-sidecar alerts go to logs only (agent pods never mount the shared evidence volume).
* Anyone who can read objects in the agent namespace can spot the aliases, PVCs and policies. Keep agents off the Kubernetes API and consider an innocuous `fullnameOverride`.

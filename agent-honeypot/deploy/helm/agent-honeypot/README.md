# Helm chart: agent-honeypot

Deploys agent-honeypot on Kubernetes (EKS first-class). Full guide: [docs/KUBERNETES.md](../../../docs/KUBERNETES.md).

```bash
helm install agent-honeypot deploy/helm/agent-honeypot -n agent-honeypot \
  --set image.repository=ghcr.io/cybersmeashish/agent-honeypot \
  --set storage.efs.fileSystemId=fs-0123456789abcdef0 \
  --set agentNamespace=ai-agents
```

| Component | Kind | Purpose |
|---|---|---|
| decoy | Deployment + Service, ExternalName aliases in the agent namespace | Fake internal services (`legacy-payroll-db`, `model-registry`, ...) |
| plant | post-install/upgrade Job (+ optional rotation CronJob) | Plants unique decoys per agent, exports the hashed guard registry |
| storage | static EFS PVs/PVCs (or one RWX PVC) | Registry and evidence in the release namespace, one workspace per agent |
| decoys TracingPolicyNamespaced | Tetragon | eBPF watch (optional SIGKILL) on decoy paths inside agent pods |
| tetragon-bridge | DaemonSet | Tetragon events → attributed `touch` alerts |
| responder | Deployment + Role in agent namespace | Kill switch: quarantine / delete agent pods |
| NetworkPolicies | | Decoys reachable only from agents; security pods without egress; deny-all for quarantined pods |

Key values: `agentNamespace`, `agents[]`, `storage.*`, `honeypots[]`, `tetragon.enforce`, `responder.mode`. See `values.yaml`.

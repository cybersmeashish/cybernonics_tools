# Terraform module: agent-honeypot

Deploys the agent-honeypot reference architecture on AWS. See [docs/AWS_DEPLOYMENT.md](../../../../docs/AWS_DEPLOYMENT.md) for the full walkthrough.

| Component | Resources |
|---|---|
| Decoy network | ECS Fargate service (read-only, non-root, all capabilities dropped) behind an internal NLB with client-IP preservation; Route 53 private zone aliases (`decoy.internal`, `legacy-payroll-db.internal`, `model-registry.internal`) |
| Decoy planting | One-shot Fargate planter task; EFS with per-agent workspace access points |
| Isolation | EFS file-system policy: state (registry + evidence) only for decoy/planter roles; workspaces isolated per agent; guard registry read-only for agents; no mounts without an access point; TLS only |
| Evidence | KMS CMK; S3 bucket with Object Lock (GOVERNANCE/COMPLIANCE); EFS backups |
| Detection pipeline | CloudWatch Logs subscription (`AHP_ALERT`) → ingest Lambda → S3 + EventBridge bus |
| Response | Kill-switch Lambda: notify / stop / quarantine ECS task by `ahp:agent-id` tag or private IP; SNS alerts; optional Security Hub findings |

Inputs and outputs are documented in `variables.tf` and `outputs.tf`.

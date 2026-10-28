# Deploying on AWS with Terraform

`deploy/terraform/modules/agent-honeypot` builds the reference architecture as code. `deploy/terraform/examples/complete` adds an isolated VPC (no internet path; VPC endpoints only) so you can stand it up end-to-end.

![architecture](architecture.png)

## What gets created

| Layer | AWS resources | Notes |
|---|---|---|
| Decoy network | ECS Fargate service + internal NLB (client IP preserved) + Route 53 private zone: `decoy.internal`, `legacy-payroll-db.internal`, `model-registry.internal` | Container is non-root, read-only root FS, all Linux capabilities dropped; outbound only to VPC endpoints and EFS |
| Planting | One-shot Fargate planter task (`scripts/plant.sh`) | Fresh tokens per agent, then the agent's workspace is handed to the agent's UID |
| Storage & isolation | EFS (KMS, TLS, backups) with access points `/state`, `/guard`, `/workspaces`, `/workspaces/<agent>` | File-system policy: **state (registry + evidence) is unreachable for every principal except the decoy and planter roles**; each agent can mount only its own workspace; the guard registry is read-only; mounts without an access point are denied |
| Evidence | S3 bucket with **Object Lock** (default GOVERNANCE, 365 days), SSE-KMS, TLS-only, public access blocked | Every alert stored as an immutable object; alerts carry `evidence_seq`/`evidence_hash` that anchor the EFS hash chain |
| Detection pipeline | CloudWatch Logs subscription on `AHP_ALERT` → `ingest` Lambda → S3 + EventBridge bus `agent-honeypot` | Watches the decoy log group plus any `agent_log_group_names` (guard sidecars) |
| Response | `killswitch` Lambda → SNS + ECS StopTask or ENI quarantine + optional Security Hub finding | Acts only on tasks in `agent_cluster_arns` tagged `ahp:agent-id=<agent>` (or owning the contacting private IP) |

```
agent task ──(decoy token)──► NLB ─► decoy service ─┐
guard sidecar ──(AHP_ALERT logs)────────────────────┤
                                                    ▼
                      CloudWatch Logs ─► ingest λ ─► S3 Object Lock (evidence)
                                                 └─► EventBridge ─► killswitch λ ─► SNS / StopTask / quarantine / Security Hub
```

## Prerequisites
* Terraform ≥ 1.5, AWS CLI v2, Docker with `buildx`, Python 3.
* Permissions to create VPC, ECS, EFS, ELB, Route 53, S3, KMS, Lambda, EventBridge, SNS and IAM.

## 1. Deploy

```bash
cd deploy/terraform/examples/complete
cp terraform.tfvars.example terraform.tfvars   # set region, emails, kill_switch_mode
terraform init
terraform apply
```
Confirm the SNS email subscription you receive.

> Using your own VPC? Call the module directly with `vpc_id`, `private_subnet_ids`, `agent_source_security_group_ids`, `agent_cluster_arns` and `agent_log_group_names`. Your private subnets need VPC endpoints for ECR (api + dkr), CloudWatch Logs and S3 (gateway), or a NAT gateway.

## 2. Push the image
```bash
cd ../../../..          # back to the agent-honeypot folder
scripts/push-image.sh deploy/terraform/examples/complete
```
The first `apply` creates the decoy service before the image exists; it reaches steady state once the image is pushed (the script forces a new deployment).

## 3. Plant decoys per agent
```bash
scripts/plant.sh agent-01
scripts/plant.sh agent-02
```
Re-run to rotate decoys. Each run also refreshes `/guard/guard-registry.json` (salted SHA-256 only: no plaintext tokens, no decoy locations).

## 4. Wire your agent tasks

Tag the task, mount the agent's workspace access point, and run tools in a **guard sidecar** so the model-driven container never holds the registry:

```hcl
resource "aws_ecs_task_definition" "agent_01" {
  family                   = "agent-01"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  task_role_arn            = aws_iam_role.agent_01.arn   # also pass it as agents["agent-01"].task_role_arn
  execution_role_arn       = aws_iam_role.agent_exec.arn

  volume {
    name = "workspace"
    efs_volume_configuration {
      file_system_id     = module.agent_honeypot.efs_file_system_id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = module.agent_honeypot.agents["agent-01"].access_point_id
        iam             = "ENABLED"
      }
    }
  }
  volume {
    name = "guard"
    efs_volume_configuration {
      file_system_id     = module.agent_honeypot.efs_file_system_id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = module.agent_honeypot.guard_access_point_id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    { name = "agent", image = "your-agent:latest", essential = true,
      mountPoints = [{ sourceVolume = "workspace", containerPath = "/workspace" }],
      environment = [{ name = "TOOLS_URL", value = "http://localhost:9000" }] },
    { name = "tool-guard", image = "your-tool-executor:latest", essential = true,
      mountPoints = [{ sourceVolume = "workspace", containerPath = "/workspace" },
                     { sourceVolume = "guard", containerPath = "/guard", readOnly = true }],
      environment = [{ name = "AHP_ALERTS_JSON", value = jsonencode([{ type = "json_stdout" }]) }],
      logConfiguration = { logDriver = "awslogs", options = {
        "awslogs-group" = "/ai-agents/tool-guard", "awslogs-region" = "ap-south-1", "awslogs-stream-prefix" = "agent-01" } } }
  ])
}

# run with tags: ahp:agent-id = agent-01  (e.g. propagate_tags = "TASK_DEFINITION" + tags on the task definition)
```

In the tool executor:
```python
from agent_honeypot import HoneypotEngine, AgentGuard
engine = HoneypotEngine.for_guard("/guard/guard-registry.json", "/tmp/ahp-evidence.jsonl")
guard = AgentGuard(engine, agent_id="agent-01")
TOOLS = {name: guard.wrap(fn, name) for name, fn in RAW_TOOLS.items()}
```
Then add `/ai-agents/tool-guard` to `agent_log_group_names` and the agent role to `agents["agent-01"].task_role_arn`, and re-apply.

## 5. Test it
From any task or instance inside the VPC:
```bash
curl -s http://legacy-payroll-db.internal:8080/api/v2/payroll/records
```
Within about a minute you should see the SNS email (`action=contact`, IP-attributed). If the IP belongs to a tagged agent task in `agent_cluster_arns`, it will be stopped or quarantined. Evidence:
```bash
aws s3 ls s3://$(terraform output -raw evidence_bucket)/alerts/ --recursive
```
A token-attributed test: read a decoy from the agent workspace and `curl` the `registry_url` in `research/stage-model-testing/model_weights_v18/config.json`. The alert names `agent-01` even though it came over the network.

## Kill-switch modes
| Mode | Behavior | Use when |
|---|---|---|
| `notify` | SNS (+ Security Hub) only | Initial rollout / tuning false positives |
| `stop` (default) | `ecs:StopTask` on matching tagged tasks | Production; safest containment |
| `quarantine` | Swap task ENIs to a no-traffic SG; task keeps running | You want volatile memory and processes preserved for forensics |

Halt triggers: actions in `halt_actions` (default `use`, `contact`), any `cross_agent` trigger, or `severity >= halt_min_severity`.

## Operations
* **Verdicts / chain check:** run a one-off ops task with the state access point (`agent-honeypot --state /state report`, `... verify`), or review S3 alert objects.
* **Rotation:** re-run `scripts/plant.sh`; vary decoy definitions periodically.
* **Retention:** `evidence_retention_mode = "COMPLIANCE"` makes evidence undeletable by anyone, including root, until retention expires. Test in GOVERNANCE first.
* **Destroy:** the evidence bucket has `force_destroy = false`; objects under retention cannot be deleted, so `terraform destroy` will stop at the bucket by design.

## Cost (rough, verify with the AWS Pricing Calculator)
The module alone (NLB, one ARM64 0.25 vCPU Fargate task, EFS, Lambda, logs) is on the order of **US$25–40/month** at low alert volume. The example's interface endpoints (3 services × 2 AZs) add roughly another US$40–50/month. The NLB and endpoints are the main fixed costs.

## Known limitations
* Only HTTP on the decoy port is instrumented. Raw TCP to other ports (e.g. 5432 on `legacy-payroll-db`) is not detected; use the inline guard (it catches the decoy password when used) or VPC Flow Logs.
* Fargate has no auditd. File-access ("touch") detection in AWS relies on the guard sidecar and on decoy secrets being read (`discover`). On EC2/EKS add `agent-honeypot audit-rules` or Tetragon/Falco.
* A log group can have at most two subscription filters; check `agent_log_group_names` targets.
* The guard is only as good as its placement. If the model-driven container can call tools without going through the sidecar, it bypasses inline detection (the decoy network and token attribution still apply).

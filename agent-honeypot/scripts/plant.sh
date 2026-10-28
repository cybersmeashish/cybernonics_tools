#!/usr/bin/env bash
# Plant fresh decoys for one agent instance via the one-shot Fargate planter task.
#   scripts/plant.sh <agent-id> [terraform-dir]
# Re-run any time to rotate decoys (new tokens; old ones stay in the registry).
set -euo pipefail
AGENT_ID=${1:?usage: scripts/plant.sh <agent-id> [terraform-dir]}
TF_DIR=${2:-deploy/terraform/examples/complete}
out() { terraform -chdir="$TF_DIR" output -raw "$1"; }

REGION=$(out region)
CLUSTER=$(out ecs_cluster_arn)
TASKDEF=$(out planter_task_definition_arn)
SG=$(out planter_security_group_id)
SUBNETS=$(terraform -chdir="$TF_DIR" output -json private_subnet_ids | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)))')
IDS=$(terraform -chdir="$TF_DIR" output -json agents | python3 -c "
import json, sys
agents = json.load(sys.stdin)
if '$AGENT_ID' not in agents:
    sys.exit('unknown agent id $AGENT_ID - add it to the module \"agents\" map and apply')
a = agents['$AGENT_ID']; print(a['uid'], a['gid'])")
read -r AGENT_UID AGENT_GID <<<"$IDS"

OVERRIDES=$(python3 - "$AGENT_ID" "$AGENT_UID" "$AGENT_GID" <<'PY'
import json, sys
agent, uid, gid = sys.argv[1:]
env = [{"name": "AGENT_ID", "value": agent}, {"name": "AGENT_UID", "value": uid}, {"name": "AGENT_GID", "value": gid}]
print(json.dumps({"containerOverrides": [{"name": "planter", "environment": env}]}))
PY
)

TASK=$(aws ecs run-task --region "$REGION" --cluster "$CLUSTER" --task-definition "$TASKDEF" \
  --launch-type FARGATE --overrides "$OVERRIDES" \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG],assignPublicIp=DISABLED}" \
  --query 'tasks[0].taskArn' --output text)
echo "planter task started: $TASK"
aws ecs wait tasks-stopped --region "$REGION" --cluster "$CLUSTER" --tasks "$TASK"
CODE=$(aws ecs describe-tasks --region "$REGION" --cluster "$CLUSTER" --tasks "$TASK" \
  --query 'tasks[0].containers[0].exitCode' --output text)
if [ "$CODE" = "0" ]; then
  echo "decoys planted for $AGENT_ID"
else
  echo "planter failed (exit $CODE) - check CloudWatch log group /agent-honeypot/planter" >&2
  exit 1
fi

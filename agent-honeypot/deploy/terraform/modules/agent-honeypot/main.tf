data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

data "aws_vpc" "this" {
  id = var.vpc_id
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
  tags       = merge({ app = "agent-honeypot" }, var.tags)

  zone_name      = var.private_zone_name
  zone_id        = var.create_private_zone ? aws_route53_zone.private[0].zone_id : var.private_zone_id
  decoy_fqdns    = [for h in var.decoy_hostnames : "${h}.${local.zone_name}"]
  decoy_base_url = "http://${local.decoy_fqdns[0]}:${var.decoy_port}"
  db_host        = contains(var.decoy_hostnames, "legacy-payroll-db") ? "legacy-payroll-db.${local.zone_name}" : local.decoy_fqdns[0]

  agent_cidrs = length(var.agent_source_cidrs) > 0 ? var.agent_source_cidrs : [data.aws_vpc.this.cidr_block]

  # env_file decoys point at the decoy DB hostname unless the definition sets db_host itself
  honeypots = [
    for h in var.honeypots : merge(
      { for k, v in { db_host = local.db_host } : k => v if h.kind == "env_file" },
      h
    )
  ]

  planter_config  = jsonencode({ decoy_base_url = local.decoy_base_url, honeypots = local.honeypots })
  image           = coalesce(var.image, "${aws_ecr_repository.this.repository_url}:latest")
  ahp_alerts_json = jsonencode([{ type = "json_stdout" }])

  # One-shot planter: write config, plant decoys for one agent, hand the
  # workspace to the agent uid, refresh the hashed guard registry.
  planter_script = <<-EOT
    set -eu
    : "$${AGENT_ID:?pass AGENT_ID as a container override (see scripts/plant.sh)}"
    printf '%s' "$AHP_CONFIG_JSON" > /tmp/honeypots.json
    mkdir -p "/workspaces/$AGENT_ID"
    agent-honeypot --state /state plant --config /tmp/honeypots.json --target "/workspaces/$AGENT_ID" --agent-id "$AGENT_ID"
    chown -R "$${AGENT_UID:-1000}:$${AGENT_GID:-1000}" "/workspaces/$AGENT_ID"
    agent-honeypot --state /state export-guard-registry --out /guard/guard-registry.json
    echo "planted decoys for $AGENT_ID"
  EOT
}

check "kill_switch_has_targets" {
  assert {
    condition     = var.kill_switch_mode == "notify" || length(var.agent_cluster_arns) > 0
    error_message = "kill_switch_mode is '${var.kill_switch_mode}' but agent_cluster_arns is empty: the kill switch will only notify."
  }
}

check "zone_configured" {
  assert {
    condition     = var.create_private_zone || var.private_zone_id != null
    error_message = "Set private_zone_id when create_private_zone = false."
  }
}

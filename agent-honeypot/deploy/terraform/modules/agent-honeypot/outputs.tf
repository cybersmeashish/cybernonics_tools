output "decoy_base_url" {
  description = "Base URL baked into planted decoys."
  value       = local.decoy_base_url
}

output "decoy_hostnames" {
  description = "Private DNS names that resolve to the decoy service."
  value       = local.decoy_fqdns
}

output "ecr_repository_url" {
  description = "Push the agent-honeypot image here (scripts/push-image.sh)."
  value       = aws_ecr_repository.this.repository_url
}

output "cpu_architecture" {
  value = var.cpu_architecture
}

output "region" {
  value = local.region
}

output "ecs_cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "decoy_service_name" {
  value = aws_ecs_service.decoy.name
}

output "planter_task_definition_arn" {
  value = aws_ecs_task_definition.planter.arn
}

output "planter_security_group_id" {
  value = aws_security_group.planter.id
}

output "private_subnet_ids" {
  value = var.private_subnet_ids
}

output "efs_file_system_id" {
  value = aws_efs_file_system.this.id
}

output "guard_access_point_id" {
  description = "Mount read-only into guard sidecars at /guard (contains guard-registry.json)."
  value       = aws_efs_access_point.guard.id
}

output "agents" {
  description = "Per-agent workspace access points and POSIX identity."
  value = {
    for k, v in var.agents : k => {
      uid             = v.uid
      gid             = v.gid
      access_point_id = aws_efs_access_point.agent[k].id
    }
  }
}

output "evidence_bucket" {
  description = "S3 Object Lock bucket holding every alert."
  value       = aws_s3_bucket.evidence.id
}

output "event_bus_name" {
  value = aws_cloudwatch_event_bus.this.name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "quarantine_security_group_id" {
  value = aws_security_group.quarantine.id
}

output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

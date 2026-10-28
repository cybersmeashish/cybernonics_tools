resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "decoy" {
  name              = "/${var.name}/decoy"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "planter" {
  name              = "/${var.name}/planter"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = local.tags
}

# ---------------------------------------------------------------- IAM
data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "decoy_task" {
  name               = "${var.name}-decoy-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "decoy_task" {
  statement {
    actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
    resources = [aws_efs_file_system.this.arn]
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.state.arn]
    }
  }
}

resource "aws_iam_role_policy" "decoy_task" {
  name   = "efs-state"
  role   = aws_iam_role.decoy_task.id
  policy = data.aws_iam_policy_document.decoy_task.json
}

resource "aws_iam_role" "planter_task" {
  name               = "${var.name}-planter-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "planter_task" {
  statement {
    actions   = local.efs_client_actions
    resources = [aws_efs_file_system.this.arn]
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.state.arn, aws_efs_access_point.guard.arn, aws_efs_access_point.workspaces_root.arn]
    }
  }
}

resource "aws_iam_role_policy" "planter_task" {
  name   = "efs-plant"
  role   = aws_iam_role.planter_task.id
  policy = data.aws_iam_policy_document.planter_task.json
}

# ------------------------------------------------------ Decoy service
resource "aws_ecs_task_definition" "decoy" {
  family                   = "${var.name}-decoy"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.decoy_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  volume {
    name = "state"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.this.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.state.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([{
    name                   = "decoy"
    image                  = local.image
    essential              = true
    user                   = "10001"
    readonlyRootFilesystem = true
    command                = ["serve", "--host", "0.0.0.0", "--port", tostring(var.decoy_port)]
    portMappings           = [{ containerPort = var.decoy_port, protocol = "tcp" }]
    environment = [
      { name = "AGENT_HONEYPOT_STATE", value = "/state" },
      { name = "AHP_ALERTS_JSON", value = local.ahp_alerts_json },
      { name = "PYTHONDONTWRITEBYTECODE", value = "1" },
      { name = "PYTHONUNBUFFERED", value = "1" },
    ]
    mountPoints     = [{ sourceVolume = "state", containerPath = "/state", readOnly = false }]
    linuxParameters = { capabilities = { drop = ["ALL"] }, initProcessEnabled = true }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.decoy.name
        "awslogs-region"        = local.region
        "awslogs-stream-prefix" = "decoy"
      }
    }
  }])

  tags = local.tags
}

resource "aws_ecs_service" "decoy" {
  name             = "${var.name}-decoy"
  cluster          = aws_ecs_cluster.this.id
  task_definition  = aws_ecs_task_definition.decoy.arn
  desired_count    = var.decoy_desired_count
  launch_type      = "FARGATE"
  platform_version = "LATEST"
  propagate_tags   = "SERVICE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.decoy.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.decoy.arn
    container_name   = "decoy"
    container_port   = var.decoy_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.decoy, aws_efs_mount_target.this, aws_efs_file_system_policy.this]
  tags       = local.tags
}

# ---------------------------------------------- Planter (one-shot task)
resource "aws_ecs_task_definition" "planter" {
  family                   = "${var.name}-planter"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.planter_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  volume {
    name = "state"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.this.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.state.id
        iam             = "ENABLED"
      }
    }
  }

  volume {
    name = "guard"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.this.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.guard.id
        iam             = "ENABLED"
      }
    }
  }

  volume {
    name = "workspaces"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.this.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.workspaces_root.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([{
    name       = "planter"
    image      = local.image
    essential  = true
    user       = "0"
    entryPoint = ["sh", "-c"]
    command    = [local.planter_script]
    environment = [
      { name = "AGENT_HONEYPOT_STATE", value = "/state" },
      { name = "AHP_CONFIG_JSON", value = local.planter_config },
      { name = "AHP_ALERTS_JSON", value = jsonencode([{ type = "console" }]) },
    ]
    mountPoints = [
      { sourceVolume = "state", containerPath = "/state", readOnly = false },
      { sourceVolume = "guard", containerPath = "/guard", readOnly = false },
      { sourceVolume = "workspaces", containerPath = "/workspaces", readOnly = false },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.planter.name
        "awslogs-region"        = local.region
        "awslogs-stream-prefix" = "planter"
      }
    }
  }])

  tags = local.tags
}

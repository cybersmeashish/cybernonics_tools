# Shared EFS with four kinds of access points:
#   /state        registry + evidence      decoy + planter only (uid 10001, 0700)
#   /guard        hashed guard registry     planter writes; agents read-only
#   /workspaces   all agent workspaces      planter only (uid 0 to chown)
#   /workspaces/X one per agent             that agent's task role only
resource "aws_efs_file_system" "this" {
  encrypted        = true
  kms_key_id       = aws_kms_key.this.arn
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"
  tags             = merge(local.tags, { Name = var.name })
}

resource "aws_efs_backup_policy" "this" {
  file_system_id = aws_efs_file_system.this.id
  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_efs_mount_target" "this" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "state" {
  file_system_id = aws_efs_file_system.this.id
  posix_user {
    uid = 10001
    gid = 10001
  }
  root_directory {
    path = "/state"
    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "0700"
    }
  }
  tags = merge(local.tags, { Name = "${var.name}-state" })
}

resource "aws_efs_access_point" "guard" {
  file_system_id = aws_efs_file_system.this.id
  posix_user {
    uid = 10001
    gid = 10001
  }
  root_directory {
    path = "/guard"
    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "0755"
    }
  }
  tags = merge(local.tags, { Name = "${var.name}-guard" })
}

resource "aws_efs_access_point" "workspaces_root" {
  file_system_id = aws_efs_file_system.this.id
  posix_user {
    uid = 0
    gid = 0
  }
  root_directory {
    path = "/workspaces"
    creation_info {
      owner_uid   = 0
      owner_gid   = 0
      permissions = "0755"
    }
  }
  tags = merge(local.tags, { Name = "${var.name}-workspaces-root" })
}

resource "aws_efs_access_point" "agent" {
  for_each       = var.agents
  file_system_id = aws_efs_file_system.this.id
  posix_user {
    uid = each.value.uid
    gid = each.value.gid
  }
  root_directory {
    path = "/workspaces/${each.key}"
    creation_info {
      owner_uid   = each.value.uid
      owner_gid   = each.value.gid
      permissions = "0750"
    }
  }
  tags = merge(local.tags, { Name = "${var.name}-ws-${each.key}", "ahp:agent-id" = each.key })
}

locals {
  efs_client_actions = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"]
  agents_with_roles  = { for k, v in var.agents : k => v if v.task_role_arn != null }
}

data "aws_iam_policy_document" "efs" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["*"]
    resources = [aws_efs_file_system.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyMountsWithoutAccessPoint"
    effect    = "Deny"
    actions   = local.efs_client_actions
    resources = [aws_efs_file_system.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "elasticfilesystem:AccessPointArn"
      values   = ["true"]
    }
  }

  statement {
    sid       = "StateOnlyForSecurityTasks"
    effect    = "Deny"
    actions   = local.efs_client_actions
    resources = [aws_efs_file_system.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.state.arn]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.decoy_task.arn, aws_iam_role.planter_task.arn]
    }
  }

  statement {
    sid       = "WorkspacesRootOnlyForPlanter"
    effect    = "Deny"
    actions   = local.efs_client_actions
    resources = [aws_efs_file_system.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.workspaces_root.arn]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.planter_task.arn]
    }
  }

  statement {
    sid       = "GuardWritableOnlyByPlanter"
    effect    = "Deny"
    actions   = ["elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"]
    resources = [aws_efs_file_system.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.guard.arn]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.planter_task.arn]
    }
  }

  dynamic "statement" {
    for_each = local.agents_with_roles
    content {
      sid       = "Agent${replace(replace(statement.key, "-", ""), ".", "")}Workspace"
      actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
      resources = [aws_efs_file_system.this.arn]
      principals {
        type        = "AWS"
        identifiers = [statement.value.task_role_arn]
      }
      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:AccessPointArn"
        values   = [aws_efs_access_point.agent[statement.key].arn]
      }
    }
  }

  dynamic "statement" {
    for_each = local.agents_with_roles
    content {
      sid       = "Agent${replace(replace(statement.key, "-", ""), ".", "")}GuardReadOnly"
      actions   = ["elasticfilesystem:ClientMount"]
      resources = [aws_efs_file_system.this.arn]
      principals {
        type        = "AWS"
        identifiers = [statement.value.task_role_arn]
      }
      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:AccessPointArn"
        values   = [aws_efs_access_point.guard.arn]
      }
    }
  }

  dynamic "statement" {
    for_each = local.agents_with_roles
    content {
      sid       = "Agent${replace(replace(statement.key, "-", ""), ".", "")}WorkspaceIsolation"
      effect    = "Deny"
      actions   = local.efs_client_actions
      resources = [aws_efs_file_system.this.arn]
      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:AccessPointArn"
        values   = [aws_efs_access_point.agent[statement.key].arn]
      }
      condition {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = [statement.value.task_role_arn]
      }
    }
  }
}

resource "aws_efs_file_system_policy" "this" {
  file_system_id = aws_efs_file_system.this.id
  policy         = data.aws_iam_policy_document.efs.json
}

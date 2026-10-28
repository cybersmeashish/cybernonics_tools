# AHP_ALERT log lines -> ingest Lambda -> S3 Object Lock + EventBridge -> kill switch Lambda -> SNS / ECS / Security Hub
resource "aws_cloudwatch_event_bus" "this" {
  name = var.name
  tags = local.tags
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-alerts"
  kms_master_key_id = aws_kms_key.this.arn
  tags              = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_email_addresses)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.key
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ------------------------------------------------------------ ingest
data "archive_file" "ingest" {
  type        = "zip"
  source_file = "${path.module}/lambda/ingest.py"
  output_path = "${path.module}/.build/ingest.zip"
}

resource "aws_iam_role" "ingest" {
  name               = "${var.name}-ingest"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "ingest_logs" {
  role       = aws_iam_role.ingest.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "ingest" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/alerts/*"]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }
  statement {
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.this.arn]
  }
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "ingest" {
  name   = "ingest"
  role   = aws_iam_role.ingest.id
  policy = data.aws_iam_policy_document.ingest.json
}

resource "aws_cloudwatch_log_group" "ingest" {
  name              = "/aws/lambda/${var.name}-ingest"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_lambda_function" "ingest" {
  function_name    = "${var.name}-ingest"
  role             = aws_iam_role.ingest.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "ingest.handler"
  filename         = data.archive_file.ingest.output_path
  source_code_hash = data.archive_file.ingest.output_base64sha256
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.id
      KMS_KEY_ARN     = aws_kms_key.this.arn
      EVENT_BUS_NAME  = aws_cloudwatch_event_bus.this.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.ingest, aws_iam_role_policy.ingest]
  tags       = local.tags
}

resource "aws_lambda_function_event_invoke_config" "ingest" {
  function_name          = aws_lambda_function.ingest.function_name
  maximum_retry_attempts = 2
  destination_config {
    on_failure {
      destination = aws_sns_topic.alerts.arn
    }
  }
}

locals {
  watched_log_groups = concat([aws_cloudwatch_log_group.decoy.name], var.agent_log_group_names)
}

resource "aws_lambda_permission" "logs" {
  count         = length(local.watched_log_groups)
  statement_id  = "logs-${count.index}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingest.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${local.watched_log_groups[count.index]}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "alerts" {
  count           = length(local.watched_log_groups)
  name            = "${var.name}-alerts"
  log_group_name  = local.watched_log_groups[count.index]
  filter_pattern  = "\"AHP_ALERT\""
  destination_arn = aws_lambda_function.ingest.arn
  depends_on      = [aws_lambda_permission.logs]
}

# ------------------------------------------------------- kill switch
data "archive_file" "killswitch" {
  type        = "zip"
  source_file = "${path.module}/lambda/killswitch.py"
  output_path = "${path.module}/.build/killswitch.zip"
}

resource "aws_iam_role" "killswitch" {
  name               = "${var.name}-killswitch"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "killswitch_logs" {
  role       = aws_iam_role.killswitch.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "killswitch" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }

  dynamic "statement" {
    for_each = length(var.agent_cluster_arns) > 0 ? [1] : []
    content {
      actions   = ["ecs:ListTasks"]
      resources = ["*"]
      condition {
        test     = "ArnEquals"
        variable = "ecs:cluster"
        values   = var.agent_cluster_arns
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.agent_cluster_arns) > 0 ? [1] : []
    content {
      actions   = ["ecs:DescribeTasks", "ecs:StopTask"]
      resources = ["arn:${local.partition}:ecs:${local.region}:${local.account_id}:task/*"]
      condition {
        test     = "ArnEquals"
        variable = "ecs:cluster"
        values   = var.agent_cluster_arns
      }
    }
  }

  dynamic "statement" {
    for_each = var.kill_switch_mode == "quarantine" ? [1] : []
    content {
      actions = ["ec2:ModifyNetworkInterfaceAttribute"]
      resources = [
        "arn:${local.partition}:ec2:${local.region}:${local.account_id}:network-interface/*",
        aws_security_group.quarantine.arn,
      ]
    }
  }

  dynamic "statement" {
    for_each = var.enable_security_hub_findings ? [1] : []
    content {
      actions   = ["securityhub:BatchImportFindings"]
      resources = ["arn:${local.partition}:securityhub:${local.region}:${local.account_id}:product/${local.account_id}/default"]
    }
  }
}

resource "aws_iam_role_policy" "killswitch" {
  name   = "killswitch"
  role   = aws_iam_role.killswitch.id
  policy = data.aws_iam_policy_document.killswitch.json
}

resource "aws_cloudwatch_log_group" "killswitch" {
  name              = "/aws/lambda/${var.name}-killswitch"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_lambda_function" "killswitch" {
  function_name    = "${var.name}-killswitch"
  role             = aws_iam_role.killswitch.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "killswitch.handler"
  filename         = data.archive_file.killswitch.output_path
  source_code_hash = data.archive_file.killswitch.output_base64sha256
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      MODE              = var.kill_switch_mode
      AGENT_CLUSTERS    = join(",", var.agent_cluster_arns)
      AGENT_TAG_KEY     = var.agent_tag_key
      QUARANTINE_SG     = aws_security_group.quarantine.id
      TOPIC_ARN         = aws_sns_topic.alerts.arn
      HALT_ACTIONS      = join(",", var.halt_actions)
      HALT_MIN_SEVERITY = tostring(var.halt_min_severity)
      SECURITY_HUB      = tostring(var.enable_security_hub_findings)
      EVIDENCE_BUCKET   = aws_s3_bucket.evidence.id
    }
  }

  depends_on = [aws_cloudwatch_log_group.killswitch, aws_iam_role_policy.killswitch]
  tags       = local.tags
}

resource "aws_lambda_function_event_invoke_config" "killswitch" {
  function_name          = aws_lambda_function.killswitch.function_name
  maximum_retry_attempts = 2
  destination_config {
    on_failure {
      destination = aws_sns_topic.alerts.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "trigger" {
  name           = "${var.name}-trigger"
  description    = "Every honeypot trigger"
  event_bus_name = aws_cloudwatch_event_bus.this.name
  event_pattern = jsonencode({
    source        = ["agent-honeypot"]
    "detail-type" = ["Honeypot Trigger"]
  })
  tags = local.tags
}

resource "aws_cloudwatch_event_target" "killswitch" {
  rule           = aws_cloudwatch_event_rule.trigger.name
  event_bus_name = aws_cloudwatch_event_bus.this.name
  arn            = aws_lambda_function.killswitch.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }
}

resource "aws_lambda_permission" "events" {
  statement_id  = "eventbridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.trigger.arn
}

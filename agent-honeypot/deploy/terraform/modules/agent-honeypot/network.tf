# NLB in front of the decoy tasks (client IPs preserved for attribution)
resource "aws_security_group" "nlb" {
  name_prefix = "${var.name}-decoy-nlb-"
  description = "agent-honeypot decoy NLB"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-decoy-nlb" })
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "nlb_from_agent_cidrs" {
  count             = length(local.agent_cidrs)
  security_group_id = aws_security_group.nlb.id
  ip_protocol       = "tcp"
  from_port         = var.decoy_port
  to_port           = var.decoy_port
  cidr_ipv4         = local.agent_cidrs[count.index]
  description       = "agents -> decoys"
}

resource "aws_vpc_security_group_ingress_rule" "nlb_from_agent_sgs" {
  count                        = length(var.agent_source_security_group_ids)
  security_group_id            = aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = var.decoy_port
  to_port                      = var.decoy_port
  referenced_security_group_id = var.agent_source_security_group_ids[count.index]
  description                  = "agent tasks -> decoys"
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_decoy" {
  security_group_id            = aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = var.decoy_port
  to_port                      = var.decoy_port
  referenced_security_group_id = aws_security_group.decoy.id
  description                  = "NLB -> decoy tasks"
}

# Decoy tasks: inbound only on the decoy port; outbound only to VPC endpoints and EFS
resource "aws_security_group" "decoy" {
  name_prefix = "${var.name}-decoy-"
  description = "agent-honeypot decoy tasks"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-decoy" })
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "decoy_from_vpc" {
  security_group_id = aws_security_group.decoy.id
  ip_protocol       = "tcp"
  from_port         = var.decoy_port
  to_port           = var.decoy_port
  cidr_ipv4         = data.aws_vpc.this.cidr_block
  description       = "preserved client IPs via NLB + NLB health checks"
}

resource "aws_vpc_security_group_egress_rule" "decoy_https_vpc" {
  security_group_id = aws_security_group.decoy.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = data.aws_vpc.this.cidr_block
  description       = "VPC endpoints (ECR, logs, S3) only"
}

resource "aws_vpc_security_group_egress_rule" "decoy_efs" {
  security_group_id            = aws_security_group.decoy.id
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.efs.id
  description                  = "EFS state"
}

# Planter: no inbound; outbound to VPC endpoints and EFS
resource "aws_security_group" "planter" {
  name_prefix = "${var.name}-planter-"
  description = "agent-honeypot planter tasks"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-planter" })
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_egress_rule" "planter_https_vpc" {
  security_group_id = aws_security_group.planter.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = data.aws_vpc.this.cidr_block
  description       = "VPC endpoints only"
}

resource "aws_vpc_security_group_egress_rule" "planter_efs" {
  security_group_id            = aws_security_group.planter.id
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.efs.id
  description                  = "EFS"
}

# EFS: NFS from decoy, planter and agents
resource "aws_security_group" "efs" {
  name_prefix = "${var.name}-efs-"
  description = "agent-honeypot EFS"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-efs" })
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_decoy" {
  security_group_id            = aws_security_group.efs.id
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.decoy.id
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_planter" {
  security_group_id            = aws_security_group.efs.id
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.planter.id
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_agent_sgs" {
  count                        = length(var.agent_source_security_group_ids)
  security_group_id            = aws_security_group.efs.id
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = var.agent_source_security_group_ids[count.index]
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_agent_cidrs" {
  count             = length(local.agent_cidrs)
  security_group_id = aws_security_group.efs.id
  ip_protocol       = "tcp"
  from_port         = 2049
  to_port           = 2049
  cidr_ipv4         = local.agent_cidrs[count.index]
}

# Quarantine: no rules at all (Terraform removes the default allow-all egress)
resource "aws_security_group" "quarantine" {
  name_prefix = "${var.name}-quarantine-"
  description = "agent-honeypot quarantine - no ingress, no egress"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-quarantine" })
  lifecycle {
    create_before_destroy = true
  }
}

# --------------------------------------------------------------- NLB
resource "aws_lb" "decoy" {
  name                             = substr("${var.name}-decoy", 0, 32)
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = var.private_subnet_ids
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true
  tags                             = local.tags
}

resource "aws_lb_target_group" "decoy" {
  name                 = substr("${var.name}-decoy", 0, 32)
  port                 = var.decoy_port
  protocol             = "TCP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  preserve_client_ip   = "true"
  deregistration_delay = 10

  # TCP checks never send an HTTP request, so they do not create alerts
  health_check {
    protocol = "TCP"
    port     = "traffic-port"
    interval = 30
  }

  tags = local.tags
}

resource "aws_lb_listener" "decoy" {
  load_balancer_arn = aws_lb.decoy.arn
  port              = var.decoy_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.decoy.arn
  }
}

# ------------------------------------------------------- Private DNS
resource "aws_route53_zone" "private" {
  count         = var.create_private_zone ? 1 : 0
  name          = local.zone_name
  comment       = "agent-honeypot decoy names"
  force_destroy = false

  vpc {
    vpc_id = var.vpc_id
  }

  tags = local.tags
}

resource "aws_route53_record" "decoy" {
  for_each = toset(var.decoy_hostnames)
  zone_id  = local.zone_id
  name     = "${each.key}.${local.zone_name}"
  type     = "A"

  alias {
    name                   = aws_lb.decoy.dns_name
    zone_id                = aws_lb.decoy.zone_id
    evaluate_target_health = false
  }
}

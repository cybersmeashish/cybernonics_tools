# Complete example: an isolated VPC (no internet path, VPC endpoints only)
# plus the agent-honeypot module protecting two agent instances.
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { project = "agent-honeypot" }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "agent-honeypot-demo" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "agent-honeypot-private-${count.index}" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "agent-honeypot-private" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "endpoints" {
  name_prefix = "agent-honeypot-endpoints-"
  description = "VPC interface endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(["ecr.api", "ecr.dkr", "logs"])
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# Cluster your agents run in. The kill switch only touches tasks tagged ahp:agent-id.
resource "aws_ecs_cluster" "agents" {
  name = "ai-agents"
}

module "agent_honeypot" {
  source = "../../modules/agent-honeypot"

  vpc_id             = aws_vpc.this.id
  private_subnet_ids = aws_subnet.private[*].id

  agents = {
    "agent-01" = {}
    "agent-02" = {}
  }

  agent_cluster_arns    = [aws_ecs_cluster.agents.arn]
  kill_switch_mode      = var.kill_switch_mode
  alert_email_addresses = var.alert_email_addresses

  depends_on = [aws_vpc_endpoint.interface, aws_vpc_endpoint.s3]
}

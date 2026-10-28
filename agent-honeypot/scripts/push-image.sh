#!/usr/bin/env bash
# Build the agent-honeypot image for the deployment's CPU architecture,
# push it to the module's ECR repository and roll the decoy service.
#   scripts/push-image.sh [terraform-dir] [tag]
set -euo pipefail
TF_DIR=${1:-deploy/terraform/examples/complete}
TAG=${2:-latest}
out() { terraform -chdir="$TF_DIR" output -raw "$1"; }

REPO=$(out ecr_repository_url)
REGION=$(out region)
ARCH=$(out cpu_architecture)
CLUSTER=$(out ecs_cluster_arn)
SERVICE=$(out decoy_service_name)
PLATFORM=$([ "$ARCH" = "ARM64" ] && echo linux/arm64 || echo linux/amd64)
REGISTRY=${REPO%%/*}

aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"
docker buildx build --platform "$PLATFORM" -t "$REPO:$TAG" --push .
aws ecs update-service --region "$REGION" --cluster "$CLUSTER" --service "$SERVICE" --force-new-deployment >/dev/null
echo "pushed $REPO:$TAG ($PLATFORM) and redeployed $SERVICE"

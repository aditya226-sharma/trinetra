#!/usr/bin/env bash
# TriNetra Phase 4 — deploy the GHCR container on a single AWS EC2 host.
#
# Uses the active AWS identity (IAM Identity Center SSO assumed role).
# Provisions:
#   - security group: 8000/tcp + 443/tcp open to the internet
#   - IAM instance role with SSM managed-instance access (no SSH needed)
#   - Amazon Linux 2023 t3.micro running Docker + the trinetra container
#
# Usage: scripts/aws-deploy.sh [aws-region] [stack-name]
set -euo pipefail

REGION="${1:-us-east-1}"
STACK="${2:-trinetra-v1}"
IMAGE="ghcr.io/aditya226-sharma/trinetra:latest"

# --------------------------------------------------------------- identity
IDENTITY="$(aws sts get-caller-identity --output json)"
ACCOUNT="$(python3 -c "import sys,json;print(json.load(sys.stdin)['Account'])" <<<"$IDENTITY")"
echo "==> AWS identity: account ${ACCOUNT} (region ${REGION})"

# ------------------------------------------------------------ secrets
SECRETS_FILE="/tmp/trinetra-deploy/aws-secrets.env"
if [ ! -f "$SECRETS_FILE" ]; then
  ADMIN_PASSWORD="$(openssl rand -hex 16)"
  AGENT_TOKEN="$(openssl rand -hex 24)"
  {
    echo "ADMIN_PASSWORD=${ADMIN_PASSWORD}"
    echo "AGENT_TOKEN=${AGENT_TOKEN}"
  } > "$SECRETS_FILE"
  chmod 600 "$SECRETS_FILE"
  echo "==> generated fresh deployment secrets -> ${SECRETS_FILE}"
fi
# shellcheck disable=SC1090
. "$SECRETS_FILE"
ADMIN_USER="${ADMIN_USER:-admin}"

# --------------------------------------------------------- image check
echo "==> verifying ${IMAGE} is reachable..."
docker manifest inspect "$IMAGE" >/dev/null 2>&1 || \
  { echo "ERROR: image ${IMAGE} not found — run the Deploy workflow first"; exit 1; }

# --------------------------------------------------------- networking
SG_ID="$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters "Name=group-name,Values=${STACK}" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [ -z "$SG_ID" ] || [ "$SG_ID" = "None" ]; then
  SG_ID="$(aws ec2 create-security-group \
    --region "$REGION" \
    --group-name "$STACK" \
    --description "TriNetra dashboard + agent ingestion" \
    --output json | python3 -c "import sys,json;print(json.load(sys.stdin)['GroupId'])")"
  echo "==> created security group ${SG_ID}"
fi
for PORT in 8000 443; do
  if ! aws ec2 describe-security-group-rules --region "$REGION" \
      --filters "Name=group-id,Values=${SG_ID}" --output json \
      | python3 -c "import sys,json;r=[x for x in json.load(sys.stdin)['SecurityGroupRules'] if x['FromPort']==$PORT];sys.exit(0 if r else 1)" 2>/dev/null; then
    aws ec2 authorize-security-group-ingress \
      --region "$REGION" --group-id "$SG_ID" \
      --ip-permissions \
        "IpProtocol=tcp,FromPort=${PORT},ToPort=${PORT},IpRanges=[{CidrIp=0.0.0.0/0,Description=TriNetra}]" >/dev/null
    echo "==> opened ${PORT}/tcp on ${SG_ID}"
  fi
done

# ----------------------------------------------- IAM (SSM instance role)
ROLE_NAME="amazon-ssm-role"
if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
  echo "==> created IAM role ${ROLE_NAME} (SSM managed-instance)"
fi
if ! aws iam get-instance-profile --instance-profile-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-instance-profile --instance-profile-name "$ROLE_NAME" >/dev/null
  for _ in 1 2 3 4 5; do
    aws iam add-role-to-instance-profile --instance-profile-name "$ROLE_NAME" \
      --role-name "$ROLE_NAME" >/dev/null 2>&1 && break
    sleep 2
  done
fi

# --------------------------------------------------------- launch host
SUBNET="$(aws ec2 describe-subnets --region "$REGION" \
  --filters "Name=default-for-az,Values=true" \
  --query 'Subnets[0].SubnetId' --output text)"
AMI="$(aws ssm get-parameters \
  --region "$REGION" \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameters[0].Value' --output text)"

USERDATA=$(cat <<EOF
#!/bin/bash
set -e
dnf -y install docker >/dev/null 2>&1
systemctl enable --now docker
mkdir -p /app
cat > /app/env <<'ENV'
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
AGENT_TOKEN=${AGENT_TOKEN}
TRINETRA_STORE_PATH=/app/data/trinetra.db
TRINETRA_RAW_DIR=/app/data/raw
TRINETRA_RETENTION_DAYS=30
ENV
chmod 600 /app/env
until docker info >/dev/null 2>&1; do sleep 1; done
docker rm -f trinetra >/dev/null 2>&1 || true
docker run -d --restart unless-stopped --name trinetra \
  -p 8000:8000 \
  --env-file /app/env \
  -v trinetra-data:/app/data \
  ghcr.io/aditya226-sharma/trinetra:latest
EOF
)
INSTANCE="$(aws ec2 run-instances \
  --region "$REGION" \
  --image-id "$AMI" \
  --instance-type t3.micro \
  --subnet-id "$SUBNET" \
  --security-group-ids "$SG_ID" \
  --iam-instance-profile Name="$ROLE_NAME" \
  --associate-public-ip-address \
  --user-data "$USERDATA" \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=${STACK}},{Key=Project,Value=trinetra}]" \
  --output json | python3 -c "import sys,json;print(json.load(sys.stdin)['Instances'][0]['InstanceId'])")"
echo "==> launched instance ${INSTANCE} (${AMI})"

echo "==> waiting for public address..."
PUB_IP=""
for _ in {1..60}; do
  PUB_IP="$(aws ec2 describe-instances --region "$REGION" \
    --instance-ids "$INSTANCE" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || true)"
  [ -n "$PUB_IP" ] && [ "$PUB_IP" != "None" ] && break
  sleep 5
done
if [ -z "$PUB_IP" ] || [ "$PUB_IP" = "None" ]; then
  echo "ERROR: no public IP assigned to ${INSTANCE}"; exit 1
fi

echo "==> waiting for container health on ${PUB_IP}..."
for _ in {1..60}; do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://${PUB_IP}:8000/api/health" 2>/dev/null || true)"
  [ "$CODE" = "200" ] && break
  sleep 5
done
if [ "$CODE" != "200" ]; then
  echo "ERROR: health check failed (last code ${CODE}) — debug via SSM:"
  echo "  aws ssm start-session --target ${INSTANCE} --region ${REGION}"
  exit 1
fi

echo
echo "==> TriNetra is LIVE"
echo "    dashboard : http://${PUB_IP}:8000/"
echo "    health    : http://${PUB_IP}:8000/api/health"
echo "    instance  : ${INSTANCE} (region ${REGION}, SSM session for shell)"
echo "    creds     : ${ADMIN_USER} / (see ${SECRETS_FILE})"
echo "    agent url : http://${PUB_IP}:8000/api/ingest-events  (token in ${SECRETS_FILE})"
#!/usr/bin/env bash
#
# Builds the TPM demo, stages it in the stack's bucket, and runs it on the
# instance against the real NitroTPM device over SSM.
#
# The client and server both run on the instance and talk over loopback, so
# nothing needs inbound network access.

set -euo pipefail

STACK_NAME="${STACK_NAME:-httpsig-scratch-nitrotpm}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
TPM_PATH="${TPM_PATH:-/dev/tpmrm0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { echo "$*" >&2; }

# shellcheck disable=SC2016  # the backticks are JMESPath, not shell
read -r INSTANCE BUCKET < <(
  aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" \
    --query '[Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue|[0], Stacks[0].Outputs[?OutputKey==`ArtifactBucket`].OutputValue|[0]]' \
    --output text)
log "Stack ${STACK_NAME}: instance ${INSTANCE}, bucket ${BUCKET}"

log "Building static device-only binaries"
make -C "$REPO_ROOT" tpm_dist >&2

log "Staging binaries in s3://${BUCKET}"
aws s3 cp "${REPO_ROOT}/dist/tpm_server" "s3://${BUCKET}/tpm_server" --region "$REGION" --only-show-errors
aws s3 cp "${REPO_ROOT}/dist/tpm_client" "s3://${BUCKET}/tpm_client" --region "$REGION" --only-show-errors

# The pinned trust file is how a host with any TPM gets a stable identity. Here
# it is built from the endorsement key AWS publishes for this instance, which is
# the same value the reference EK template produces on the instance itself.
log "Pinning the endorsement key AWS publishes for ${INSTANCE}"
EK_PUB=$(aws ec2 get-instance-tpm-ek-pub --region "$REGION" \
  --instance-id "$INSTANCE" --key-type rsa-2048 --key-format tpmt \
  --query KeyValue --output text)
printf '[{"label":"%s","ekPublic":"%s"}]\n' "$INSTANCE" "$EK_PUB" > "${REPO_ROOT}/dist/ek-pinned.json"
aws s3 cp "${REPO_ROOT}/dist/ek-pinned.json" "s3://${BUCKET}/ek-pinned.json" --region "$REGION" --only-show-errors

# A freshly launched instance takes a moment to register with SSM.
log "Waiting for ${INSTANCE} to be reachable by SSM"
for _ in $(seq 1 30); do
  status=$(aws ssm describe-instance-information --region "$REGION" \
    --filters "Key=InstanceIds,Values=${INSTANCE}" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
  [ "$status" = "Online" ] && break
  sleep 10
done
if [ "$status" != "Online" ]; then
  log "ERROR: ${INSTANCE} never came online in SSM"
  exit 1
fi

log "Running the demo on ${INSTANCE} with ${TPM_PATH}"
COMMAND_ID=$(aws ssm send-command --region "$REGION" \
  --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript \
  --comment "httpsig-scratch NitroTPM demo" \
  --parameters "commands=[
    \"set -e\",
    \"cd /root\",
    \"pkill -f tpm_server || true\",
    \"sleep 1\",
    \"aws s3 cp s3://${BUCKET}/tpm_server . --quiet\",
    \"aws s3 cp s3://${BUCKET}/tpm_client . --quiet\",
    \"aws s3 cp s3://${BUCKET}/ek-pinned.json . --quiet\",
    \"chmod +x tpm_server tpm_client\",
    \"ls -l ${TPM_PATH}\",
    \"echo '===== ek-trust=pinned: endorsement key from a file ====='\",
    \"nohup ./tpm_server --ek-trust pinned --ek-file ek-pinned.json > /tmp/tpm_pinned.log 2>&1 &\",
    \"sleep 2\",
    \"./tpm_client --tpm-path ${TPM_PATH}\",
    \"echo '===== unsigned request, expect 401 ====='\",
    \"curl -s -o /dev/null -w '%{http_code}\\n' http://localhost:9092/\",
    \"cat /tmp/tpm_pinned.log\",
    \"pkill -f tpm_server || true\",
    \"sleep 1\",
    \"echo '===== an endorsement key that is not pinned must be refused ====='\",
    \"echo '[{\\\"label\\\":\\\"some-other-machine\\\",\\\"ekPublic\\\":\\\"AAEACwADALIAIA==\\\"}]' > ek-bogus.json\",
    \"nohup ./tpm_server --ek-trust pinned --ek-file ek-bogus.json > /tmp/tpm_bogus.log 2>&1 &\",
    \"sleep 2\",
    \"./tpm_client --tpm-path ${TPM_PATH} || echo 'refused, as expected'\",
    \"pkill -f tpm_server || true\",
    \"sleep 1\",
    \"echo '===== ek-trust=ec2: endorsement key from the control plane ====='\",
    \"nohup ./tpm_server --ek-trust ec2 > /tmp/tpm_ec2.log 2>&1 &\",
    \"sleep 2\",
    \"./tpm_client --tpm-path ${TPM_PATH}\",
    \"cat /tmp/tpm_ec2.log\",
    \"echo '===== a false instance claim must be refused ====='\",
    \"./tpm_client --tpm-path ${TPM_PATH} --claim i-0123456789abcdef0 || echo 'refused, as expected (a claim for another machine)'\",
    \"pkill -f tpm_server || true\"
  ]" \
  --query Command.CommandId --output text)

# Observe completion rather than guessing at a sleep. The waiter exits non-zero
# for a failed command, so the invocation is fetched either way and the output
# is what reports the failure.
aws ssm wait command-executed --region "$REGION" \
  --command-id "$COMMAND_ID" --instance-id "$INSTANCE" || true

aws ssm get-command-invocation --region "$REGION" \
  --command-id "$COMMAND_ID" --instance-id "$INSTANCE" \
  --query 'StandardOutputContent' --output text

STATUS=$(aws ssm get-command-invocation --region "$REGION" \
  --command-id "$COMMAND_ID" --instance-id "$INSTANCE" \
  --query 'Status' --output text)
if [ "$STATUS" != "Success" ]; then
  log "Command ${COMMAND_ID} finished with status ${STATUS}"
  aws ssm get-command-invocation --region "$REGION" \
    --command-id "$COMMAND_ID" --instance-id "$INSTANCE" \
    --query 'StandardErrorContent' --output text >&2
  exit 1
fi
log "Command ${COMMAND_ID} succeeded"

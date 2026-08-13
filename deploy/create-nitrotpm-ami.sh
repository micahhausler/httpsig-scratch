#!/usr/bin/env bash
#
# Registers an arm64 Amazon Linux 2023 AMI with NitroTPM enabled.
#
# Linux has no prebuilt NitroTPM AMI, and NitroTPM cannot be turned on for an
# existing image, so the only way to get one is to register a new AMI over the
# same root snapshot with --tpm-support v2.0. RegisterImage requires a snapshot
# you own, hence the copy.
#
# Neither step has a CloudFormation resource, which is why this is a script and
# the rest of the demo host is deploy/nitrotpm.yaml.
#
# Prints the AMI ID on stdout. Safe to re-run: if an AMI with this name already
# exists, its ID is printed and nothing is created.

set -euo pipefail

AMI_NAME="${AMI_NAME:-al2023-arm64-nitrotpm-httpsig-scratch}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"

log() { echo "$*" >&2; }

existing=$(aws ec2 describe-images --region "$REGION" --owners self \
  --filters "Name=name,Values=${AMI_NAME}" \
  --query 'Images[0].ImageId' --output text)
if [ "$existing" != "None" ] && [ -n "$existing" ]; then
  log "AMI ${AMI_NAME} already exists, reusing it"
  echo "$existing"
  exit 0
fi

# An arm64 AL2023 AMI is already UEFI boot mode, which NitroTPM requires. Its
# other attributes are read here rather than hardcoded so the registered image
# stays a faithful copy.
log "Finding the latest arm64 Amazon Linux 2023 AMI"
read -r SRC_AMI SRC_SNAP ROOT_DEV VOL_SIZE VOL_TYPE BOOT_MODE < <(
  aws ec2 describe-images --region "$REGION" --owners amazon \
    --filters 'Name=name,Values=al2023-ami-2023.*-arm64' 'Name=state,Values=available' \
    --query 'reverse(sort_by(Images,&CreationDate))[0].[ImageId,BlockDeviceMappings[0].Ebs.SnapshotId,RootDeviceName,BlockDeviceMappings[0].Ebs.VolumeSize,BlockDeviceMappings[0].Ebs.VolumeType,BootMode]' \
    --output text)
log "  source AMI ${SRC_AMI}, snapshot ${SRC_SNAP}, boot mode ${BOOT_MODE}"

if [ "$BOOT_MODE" != "uefi" ]; then
  log "ERROR: source AMI boot mode is ${BOOT_MODE}, NitroTPM requires uefi"
  exit 1
fi

log "Copying the root snapshot so we own it"
SNAP=$(aws ec2 copy-snapshot --region "$REGION" \
  --source-region "$REGION" \
  --source-snapshot-id "$SRC_SNAP" \
  --description "AL2023 arm64 root for NitroTPM (${AMI_NAME})" \
  --tag-specifications "ResourceType=snapshot,Tags=[{Key=Name,Value=${AMI_NAME}},{Key=Project,Value=httpsig-scratch}]" \
  --query SnapshotId --output text)
log "  copy is ${SNAP}, waiting for it to complete"
aws ec2 wait snapshot-completed --region "$REGION" --snapshot-ids "$SNAP"

log "Registering ${AMI_NAME} with --tpm-support v2.0"
AMI=$(aws ec2 register-image --region "$REGION" \
  --name "$AMI_NAME" \
  --description "AL2023 arm64 with NitroTPM v2.0, for the httpsig-scratch tpm demo" \
  --architecture arm64 \
  --root-device-name "$ROOT_DEV" \
  --virtualization-type hvm \
  --ena-support \
  --sriov-net-support simple \
  --boot-mode uefi \
  --imds-support v2.0 \
  --tpm-support v2.0 \
  --block-device-mappings "[{\"DeviceName\":\"${ROOT_DEV}\",\"Ebs\":{\"SnapshotId\":\"${SNAP}\",\"VolumeSize\":${VOL_SIZE},\"VolumeType\":\"${VOL_TYPE}\",\"DeleteOnTermination\":true}}]" \
  --query ImageId --output text)

# Confirm the TPM actually stuck, rather than trusting that the flag was accepted
tpm=$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
  --query 'Images[0].TpmSupport' --output text)
if [ "$tpm" != "v2.0" ]; then
  log "ERROR: registered ${AMI} but TpmSupport is '${tpm}'"
  exit 1
fi
log "Registered ${AMI} with TpmSupport ${tpm}"

echo "$AMI"

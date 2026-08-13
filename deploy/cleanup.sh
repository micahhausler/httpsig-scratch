#!/usr/bin/env bash
#
# Deletes everything the NitroTPM demo created: the CloudFormation stack, and
# the AMI and snapshot from create-nitrotpm-ami.sh.
#
# Each deletion is confirmed separately. Pass -y to skip the prompts.

set -euo pipefail

STACK_NAME="${STACK_NAME:-httpsig-scratch-nitrotpm}"
AMI_NAME="${AMI_NAME:-al2023-arm64-nitrotpm-httpsig-scratch}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
ASSUME_YES=false

while getopts "y" opt; do
  case $opt in
    y) ASSUME_YES=true ;;
    *) echo "usage: $0 [-y]" >&2; exit 1 ;;
  esac
done

confirm() {
  if $ASSUME_YES; then
    return 0
  fi
  read -r -p "$1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

echo "Region ${REGION}, account $(aws sts get-caller-identity --query Account --output text)"

# The AMI's snapshot has to be read before the AMI is deregistered, because
# afterwards there is nothing left to derive it from.
AMI=$(aws ec2 describe-images --region "$REGION" --owners self \
  --filters "Name=name,Values=${AMI_NAME}" \
  --query 'Images[0].ImageId' --output text)
SNAP="None"
if [ "$AMI" != "None" ] && [ -n "$AMI" ]; then
  SNAP=$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
    --query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' --output text)
fi

# The bucket must be emptied first: CloudFormation will not delete a bucket
# that still has objects in it, and the whole stack delete would fail.
# shellcheck disable=SC2016  # the backticks are JMESPath, not shell
BUCKET=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`ArtifactBucket`].OutputValue' \
  --output text 2>/dev/null || true)

STACK_STATE=present
aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" >/dev/null 2>&1 || STACK_STATE=absent

# Listed up front because a prompt from read -p is invisible when stdin is not
# a terminal, and this is the last look before things start being deleted.
echo "To delete:"
echo "  stack    ${STACK_NAME} (${STACK_STATE})"
echo "  bucket   ${BUCKET:-none}"
echo "  AMI      ${AMI}"
echo "  snapshot ${SNAP}"

if [ -n "$BUCKET" ] && [ "$BUCKET" != "None" ]; then
  if confirm "Empty bucket ${BUCKET}?"; then
    aws s3 rm "s3://${BUCKET}" --recursive --only-show-errors || true
    echo "  emptied ${BUCKET}"
  fi
fi

if aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" >/dev/null 2>&1; then
  if confirm "Delete stack ${STACK_NAME}, including the instance?"; then
    aws cloudformation delete-stack --region "$REGION" --stack-name "$STACK_NAME"
    echo "  waiting for ${STACK_NAME} to go away"
    aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$STACK_NAME"
    echo "  deleted ${STACK_NAME}"
  fi
else
  echo "No stack named ${STACK_NAME}"
fi

if [ "$AMI" != "None" ] && [ -n "$AMI" ]; then
  if confirm "Deregister AMI ${AMI} (${AMI_NAME})?"; then
    aws ec2 deregister-image --region "$REGION" --image-id "$AMI"
    echo "  deregistered ${AMI}"
  fi
else
  echo "No AMI named ${AMI_NAME}"
fi

# A snapshot cannot be deleted while an AMI still references it, so this comes
# after the deregistration above.
if [ "$SNAP" != "None" ] && [ -n "$SNAP" ]; then
  if confirm "Delete snapshot ${SNAP}?"; then
    aws ec2 delete-snapshot --region "$REGION" --snapshot-id "$SNAP"
    echo "  deleted ${SNAP}"
  fi
else
  echo "No snapshot to delete"
fi

echo "Done"

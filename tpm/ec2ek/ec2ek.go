/*
Package ec2ek resolves endorsement key trust against the EC2 control plane.

This is the anchor that makes a NitroTPM attestation mean something: AWS
publishes the endorsement key of every NitroTPM instance, so a server can ask
it what key a given instance should have, rather than believing whatever the
client presents.

It lives in its own package because it needs the AWS SDK, which nothing else
here does.
*/
package ec2ek

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/micahhausler/httpsig-scratch/tpm"
)

// api is the piece of the EC2 API this needs, so tests do not need AWS.
type api interface {
	GetInstanceTpmEkPub(context.Context, *ec2.GetInstanceTpmEkPubInput, ...func(*ec2.Options)) (*ec2.GetInstanceTpmEkPubOutput, error)
}

// Trust looks up the authoritative endorsement key for the instance a client
// claims to be, and requires the client's key to equal it.
type Trust struct {
	client api
}

var _ tpm.EKTrust = &Trust{}

// New returns a Trust using the ambient AWS configuration. The caller needs
// ec2:GetInstanceTpmEkPub.
//
// The region falls back to IMDS, which has to be asked for: the SDK does not
// consult instance metadata for a region on its own, and a server running on
// the instance it verifies has no other source for one.
func New(ctx context.Context) (*Trust, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithEC2IMDSRegion())
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("no AWS region: set AWS_REGION or run on an instance with IMDS reachable")
	}
	return &Trust{client: ec2.NewFromConfig(cfg)}, nil
}

// Trust resolves claim, an EC2 instance ID, to that instance's published
// endorsement key and compares it with the one presented.
//
// The claim needs no authentication. If a client names an instance that is not
// its own, the comparison either fails outright or the challenge that follows
// is encrypted to that instance's endorsement key, which the client cannot
// open.
func (t *Trust) Trust(ctx context.Context, claim string, ekPublic []byte) (tpm.Identity, error) {
	if claim == "" {
		return tpm.Identity{}, fmt.Errorf("an instance ID is required to look up an endorsement key")
	}

	// The RSA key in TPMT_PUBLIC form is what the reference EK template
	// produces on the instance, so the two are directly comparable.
	out, err := t.client.GetInstanceTpmEkPub(ctx, &ec2.GetInstanceTpmEkPubInput{
		InstanceId: &claim,
		KeyType:    types.EkPubKeyTypeRsa2048,
		KeyFormat:  types.EkPubKeyFormatTpmt,
	})
	if err != nil {
		return tpm.Identity{}, fmt.Errorf("looking up the endorsement key of %s: %w", claim, err)
	}
	if out.KeyValue == nil {
		return tpm.Identity{}, fmt.Errorf("%s has no published endorsement key", claim)
	}

	want, err := base64.StdEncoding.DecodeString(*out.KeyValue)
	if err != nil {
		return tpm.Identity{}, fmt.Errorf("unreadable endorsement key for %s: %w", claim, err)
	}
	if !bytes.Equal(want, ekPublic) {
		return tpm.Identity{}, fmt.Errorf("endorsement key does not match the one published for %s", claim)
	}

	return tpm.Identity{Label: claim, Source: tpm.SourceEC2}, nil
}

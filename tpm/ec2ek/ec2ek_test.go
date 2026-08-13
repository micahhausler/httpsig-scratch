package ec2ek

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/micahhausler/httpsig-scratch/tpm"
)

type fakeAPI struct {
	ekPublic map[string]string // instance ID to base64 TPMT_PUBLIC
	err      error
	gotInput *ec2.GetInstanceTpmEkPubInput
}

func (f *fakeAPI) GetInstanceTpmEkPub(_ context.Context, in *ec2.GetInstanceTpmEkPubInput, _ ...func(*ec2.Options)) (*ec2.GetInstanceTpmEkPubOutput, error) {
	f.gotInput = in
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.ekPublic[*in.InstanceId]
	if !ok {
		return nil, fmt.Errorf("InvalidInstanceID.NotFound: %s", *in.InstanceId)
	}
	return &ec2.GetInstanceTpmEkPubOutput{KeyValue: &v}, nil
}

func TestTrust(t *testing.T) {
	realEK := []byte("the endorsement key of i-real")
	api := &fakeAPI{ekPublic: map[string]string{
		"i-real":  base64.StdEncoding.EncodeToString(realEK),
		"i-other": base64.StdEncoding.EncodeToString([]byte("a different machine's key")),
	}}
	trust := &Trust{client: api}

	t.Run("matching key is trusted as that instance", func(t *testing.T) {
		id, err := trust.Trust(context.Background(), "i-real", realEK)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id.Label != "i-real" || id.Source != tpm.SourceEC2 {
			t.Errorf("got %s/%s, want i-real/%s", id.Label, id.Source, tpm.SourceEC2)
		}
		// the RSA key in TPMT_PUBLIC form is what the reference template
		// produces on the instance, so those are the parameters to ask for
		if api.gotInput.KeyType != "rsa-2048" || api.gotInput.KeyFormat != "tpmt" {
			t.Errorf("asked for %s/%s, want rsa-2048/tpmt", api.gotInput.KeyType, api.gotInput.KeyFormat)
		}
	})

	// Claiming to be an instance whose key you do not hold must fail here,
	// before any challenge is issued.
	t.Run("key from another instance is refused", func(t *testing.T) {
		_, err := trust.Trust(context.Background(), "i-other", realEK)
		if err == nil {
			t.Fatal("a mismatched endorsement key was trusted")
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Errorf("expected a mismatch error, got: %v", err)
		}
	})

	t.Run("unknown instance is refused", func(t *testing.T) {
		if _, err := trust.Trust(context.Background(), "i-missing", realEK); err == nil {
			t.Error("an unknown instance was trusted")
		}
	})

	t.Run("no claim is refused", func(t *testing.T) {
		_, err := trust.Trust(context.Background(), "", realEK)
		if err == nil {
			t.Fatal("an empty claim was accepted")
		}
		if !strings.Contains(err.Error(), "instance ID is required") {
			t.Errorf("expected a missing claim error, got: %v", err)
		}
	})
}

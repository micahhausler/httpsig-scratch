package tpm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// An Identity is the machine an enrollment was traced back to, and the
// mechanism that established it. Source is recorded because the strength of
// the identity is a property of where it came from: an EK matched against the
// EC2 control plane means something a self-asserted name does not.
type Identity struct {
	Label  string `json:"label"`
	Source string `json:"source"`
}

func (i Identity) String() string {
	return fmt.Sprintf("%s (%s)", i.Label, i.Source)
}

// Trust source names, as accepted by the server's --ek-trust flag.
const (
	SourcePinned = "pinned"
	SourceTOFU   = "insecure-tofu"
	SourceEC2    = "ec2"
)

// An EKTrust decides whether an endorsement key presented by a client belongs
// to a machine this server will accept, and what identity it denotes.
//
// claim is the client's own unverified assertion about which machine it is.
// An implementation may use it as a lookup key, but must never treat it as
// established: the only thing that proves the client holds this EK is the
// credential activation that follows, and that is bound to the EK returned
// here, not to the claim.
type EKTrust interface {
	Trust(ctx context.Context, claim string, ekPublic []byte) (Identity, error)
}

// PinnedTrust accepts endorsement keys listed in a file, which is how a host
// with any TPM, including a software one, gets a stable identity without a
// cloud API. On AWS the file is generated from ec2 get-instance-tpm-ek-pub.
type PinnedTrust struct {
	keys []PinnedKey
}

// A PinnedKey is one trusted endorsement key. EKPublic is a base64 TPMT_PUBLIC,
// the same bytes ec2 get-instance-tpm-ek-pub --key-format tpmt returns.
type PinnedKey struct {
	Label    string `json:"label"`
	EKPublic string `json:"ekPublic"`
}

// LoadPinnedTrust reads a JSON array of PinnedKey from path.
func LoadPinnedTrust(path string) (*PinnedTrust, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []PinnedKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s lists no endorsement keys", path)
	}
	for i, k := range keys {
		if k.Label == "" {
			return nil, fmt.Errorf("%s entry %d has no label", path, i)
		}
		if _, err := base64.StdEncoding.DecodeString(k.EKPublic); err != nil {
			return nil, fmt.Errorf("%s entry %q has an unreadable ekPublic: %w", path, k.Label, err)
		}
	}
	return &PinnedTrust{keys: keys}, nil
}

// Trust matches the whole public area, not a digest of it, so a key whose
// attributes differ from the pinned copy does not match.
func (p *PinnedTrust) Trust(_ context.Context, _ string, ekPublic []byte) (Identity, error) {
	for _, k := range p.keys {
		want, err := base64.StdEncoding.DecodeString(k.EKPublic)
		if err != nil {
			continue // rejected at load time
		}
		if bytes.Equal(want, ekPublic) {
			return Identity{Label: k.Label, Source: SourcePinned}, nil
		}
	}
	return Identity{}, fmt.Errorf("endorsement key is not pinned")
}

// TOFUTrust accepts any endorsement key and names it after its own digest. The
// enrollment still proves that the signing key and the attestation key live in
// one TPM, but nothing says which TPM that is, so a software TPM is accepted
// just as readily as hardware. For local testing only, which is why its Source
// says so.
type TOFUTrust struct{}

func (TOFUTrust) Trust(_ context.Context, _ string, ekPublic []byte) (Identity, error) {
	sum := sha256.Sum256(ekPublic)
	return Identity{Label: fmt.Sprintf("ek:%x", sum[:8]), Source: SourceTOFU}, nil
}

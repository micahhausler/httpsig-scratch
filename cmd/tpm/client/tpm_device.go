//go:build !tpmsim

package main

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// simulatorSupported reports whether this binary can run without a TPM device.
const simulatorSupported = false

// openTPM opens a TPM device. This build has no software fallback, so it is
// pure Go and links no C libraries; build with -tags tpmsim for a binary that
// can run an embedded simulator instead.
func openTPM(path string) (transport.TPMCloser, error) {
	if path == "" {
		return nil, fmt.Errorf("--tpm-path is required (this binary was built without simulator support; rebuild with -tags tpmsim for an embedded software TPM)")
	}
	return linuxtpm.Open(path)
}

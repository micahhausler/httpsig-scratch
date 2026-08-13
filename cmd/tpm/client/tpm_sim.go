//go:build tpmsim

package main

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// simulatorSupported reports whether this binary can run without a TPM device.
const simulatorSupported = true

// openTPM opens a TPM device, or an embedded software TPM when no path is
// given. The simulator is the Microsoft reference implementation compiled in
// via cgo, so this build requires openssl headers and links libcrypto.
func openTPM(path string) (transport.TPMCloser, error) {
	if path == "" {
		return simulator.OpenSimulator()
	}
	return linuxtpm.Open(path)
}

SHELL := /usr/bin/env bash

bin/session_server:
	go build -o bin/session_server cmd/session_token/server/main.go

bin/gh_server:
	go build -o bin/gh_server cmd/gh/server/main.go

bin/proxy_server:
	go build -o bin/proxy_server cmd/proxy/server/main.go

bin/kubecon_server:
	go build -o bin/kubecon_server cmd/kubecon/server/main.go

bin/tpm_server:
	go build -o bin/tpm_server ./cmd/tpm/server

.PHONY: build_server
build_server: bin/session_server bin/gh_server bin/kubecon_server bin/proxy_server bin/tpm_server

bin/session_client:
	go build -o bin/session_client cmd/session_token/client/main.go

bin/gh_client:
	go build -o bin/gh_client cmd/gh/client/main.go

bin/proxy_client:
	go build -o bin/proxy_client cmd/proxy/client/main.go

bin/kubecon_client:
	go build -o bin/kubecon_client cmd/kubecon/client/main.go

# the embedded software TPM is cgo and needs openssl headers (openssl-devel).
# built as a package, not a file list, so the build-tagged files are included
bin/tpm_client:
	go build -tags tpmsim -o bin/tpm_client ./cmd/tpm/client

# static device-only binaries for a host with a real TPM, such as a NitroTPM
# instance. No simulator, so no cgo and no libcrypto at runtime.
.PHONY: tpm_dist
tpm_dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/tpm_server ./cmd/tpm/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/tpm_client ./cmd/tpm/client

.PHONY: build_client
build_client: bin/session_client bin/gh_client bin/proxy_client bin/kubecon_client bin/tpm_client

.PHONY: build
build: build_server build_client

.PHONY: all
all: build

.PHONY: clean
clean:
	rm bin/*

.PHONY: test
test:
	go test -cover -timeout 60s -v ./...

#### Keygen

keys:
	mkdir -p keys

keys/aes.key: keys
	openssl rand 32 > keys/aes.key

keys/id_rsa: keys
	ssh-keygen -t rsa -N "" -b 4096 -f keys/id_rsa

keys/id_ecdsa: keys
	ssh-keygen -t ecdsa -N "" -b 256 -f keys/id_ecdsa

keys/hmac.key: keys
	openssl rand -base64 32  > keys/hmac.key

.PHONY: all_keys
all_keys: keys/aes.key keys/id_rsa keys/id_ecdsa keys/hmac.key

.PHONY: clean_keys
clean_keys:
	rm -f keys/*

SERVER_ARGS := --log-level info

### SessionToken

.PHONY: session_server
session_server: bin/session_server keys/aes.key
	./bin/session_server $(SERVER_ARGS) --session-token-encryption-key keys/aes.key | jq

.PHONY: session_client
session_client: bin/session_client keys/id_rsa keys/hmac.key keys/id_ecdsa
	./bin/session_client \
		--key ./keys/id_ecdsa \
		--key-algo ecdsa-p256-sha256
	./bin/session_client \
		--key ./keys/hmac.key \
		--key-algo hmac-sha256
	./bin/session_client \
		--key ./keys/id_rsa \
		--key-algo rsa-pss-sha512

### TPM

# accepts any endorsement key, so it needs no pin file. For the trust path a
# real deployment uses, pin one:
#   ./bin/tpm_client --print-ek > keys/ek.json
#   ./bin/tpm_server --ek-trust pinned --ek-file keys/ek.json
.PHONY: tpm_server
tpm_server: bin/tpm_server
	./bin/tpm_server $(SERVER_ARGS) --ek-trust insecure-tofu | jq .

# uses an embedded software TPM by default; pass a real device with
#   ./bin/tpm_client --tpm-path /dev/tpmrm0
.PHONY: tpm_client
tpm_client: bin/tpm_client
	./bin/tpm_client

### GitHub

.PHONY: gh_server
gh_server: bin/gh_server
	./bin/gh_server $(SERVER_ARGS) --usernames micahhausler | jq .

GH_KEY := ~/.ssh/id_rsa

.PHONY: gh_client
gh_client: bin/gh_client
	echo "Set GH_KEY to the path of your private key registered with GitHub"
	./bin/gh_client --key $(GH_KEY)

### Proxy


mount/server-cert.pem:
	openssl req -x509 \
		-newkey rsa:2048 \
		-keyout mount/server-key.pem \
		-out mount/server-cert.pem \
		-sha256 \
		-days 3650 \
		-nodes \
		-subj "/CN=kubernetes" \
		-addext "subjectAltName=DNS:kubernetes,IP:127.0.0.1"

.PHONY: certs
certs: mount/server-cert.pem

.PHONY: clean-certs
clean-certs:
	rm -f mount/*.pem mount/*.key mount/*.crt

.PHONY: kind
kind:
	kind create cluster --config kind.yaml -v2

# reuse front-proxy-client.crt and front-proxy-client.key, would use unique certs in production
mount/front-proxy-client.crt:
	docker exec -it kind-control-plane cp /etc/kubernetes/pki/front-proxy-client.crt /mount/front-proxy-client.crt
	docker exec -it kind-control-plane cp /etc/kubernetes/pki/front-proxy-client.key /mount/front-proxy-client.key

kubeconfig:
	KUBECONFIG=./kubeconfig kubectl config set-cluster kind-proxy \
		--server=https://127.0.0.1:9091
	KUBECONFIG=./kubeconfig kubectl config set-credentials kind-proxy
	KUBECONFIG=./kubeconfig kubectl config set-context kind-proxy \
		--cluster=kind-proxy \
		--user=kind-proxy
	KUBECONFIG=./kubeconfig kubectl config set current-context kind-proxy
		# 	--embed-certs \
		# --certificate-authority=./mount/server-cert.pem \

.PHONY: proxy
proxy_server: mount/server-cert.pem mount/front-proxy-client.crt bin/proxy_server
	./bin/proxy_server \
		--client-cert mount/front-proxy-client.crt \
		--client-key mount/front-proxy-client.key \
		--backend $$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}') | jq

.PHONY: proxy_client
proxy_client: kubeconfig bin/proxy_client
	./bin/proxy_client \
		-v 99 \
		--key $(GH_KEY) \
		--kubeconfig ./kubeconfig

.PHONY: clean-kind
clean-kind: clean-certs
	kind delete cluster
	rm mount/*.log

.PHONY: tail-api-logs
tail-api-logs:
	docker exec -it kind-control-plane /bin/sh -c 'tail -f /var/log/containers/kube-apiserver-*' | grep signed

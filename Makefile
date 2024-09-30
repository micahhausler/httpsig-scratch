SHELL := /usr/bin/env bash

bin/server:
	go build -o bin/server cmd/server/main.go

bin/gh_server:
	go build -o bin/gh_server cmd/gh_server/main.go

.PHONY: server
server: bin/server bin/gh_server bin/proxy

bin/client:
	go build -o bin/client cmd/client/main.go

bin/gh_client:
	go build -o bin/gh_client cmd/gh_client/main.go

bin/proxy_client:
	go build -o bin/proxy_client cmd/proxy_client/main.go

bin/proxy:
	go build -o bin/proxy cmd/proxy/main.go

.PHONY: client
client: bin/client bin/gh_client bin/proxy_client

.PHONY: build
build: server client

.PHONY: all
all: build

.PHONY: clean
clean:
	rm bin/*

.PHONY: test
test:
	go test -cover -timeout 60s -v ./...

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
kind: certs
	kind create cluster --config kind.yaml -v2

kubeconfig:
	KUBECONFIG=kubeconfig kubectl config set-cluster kind-proxy \
		--embed-certs \
		--certificate-authority=./mount/server-cert.pem \
		--server=https://127.0.0.1:9091
	KUBECONFIG=kubeconfig kubectl config set-credentials kind-proxy
	KUBECONFIG=kubeconfig kubectl config set-context kind-proxy \
		--cluster=kind-proxy \
		--user=kind-proxy
	KUBECONFIG=kubeconfig kubectl config set current-context kind-proxy

.PHONY: proxy
proxy:
	docker exec -it kind-control-plane cp /etc/kubernetes/pki/front-proxy-client.crt /mount/front-proxy-client.crt
	docker exec -it kind-control-plane cp /etc/kubernetes/pki/front-proxy-client.key /mount/front-proxy-client.key
	./bin/proxy \
		--client-cert mount/front-proxy-client.crt \
		--client-key mount/front-proxy-client.key \
		--backend $$(kubectl config view --minify -o json | jq -r .clusters[0].cluster.server) | jq

.PHONY: clean-kind
clean-kind: clean-certs
	kind delete cluster
	rm mount/*.log

.PHONY: tail-logs
tail-logs:
	docker exec -it kind-control-plane /bin/sh -c 'tail -f /var/log/containers/kube-apiserver-*' | grep signed

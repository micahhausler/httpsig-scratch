

bin/server:
	go build -o bin/server cmd/server/main.go

bin/gh_server:
	go build -o bin/gh_server cmd/gh_server/main.go

.PHONY: server
server: bin/server bin/gh_server

bin/client:
	go build -o bin/client cmd/client/main.go

bin/gh_client:
	go build -o bin/gh_client cmd/gh_client/main.go

.PHONY: client
client: bin/client bin/gh_client

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


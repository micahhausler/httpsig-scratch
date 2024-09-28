

bin/server:
	go build -o bin/server server/main.go

.PHONY: server
server: bin/server

bin/client:
	go build -o bin/client client/main.go

.PHONY: client
client: bin/client

.PHONY: build
build: server client

.PHONY: all
all: build

.PHONY: clean
clean:
	rm bin/*

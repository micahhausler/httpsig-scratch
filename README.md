# RFC 9421 scratch project in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/micahhausler/httpsig-scratch.svg)](https://pkg.go.dev/github.com/micahhausler/httpsig-scratch)

I'm starting with https://github.com/common-fate/httpsig but want to also try some other libraries:

* https://github.com/remitly-oss/httpsig-go
* https://github.com/yaronf/httpsign

Tasks:
- [x] Run example client and server
- [x] Get server to support multiple algorithms
- [x] GitHub key database
  - [x] Create KeyDirectory backed by GitHub usernames
  - [x] Integrate KeyDirectory into server
  - [x] Get client signer to sign with SSH RSA or ECDSA Key
- [ ] Impose specific signature base from the server
- [ ] Define a signature input format for the client, including algo.

## Build
```sh
make all
```

## GitHub keys as keyIDs

This package contains an example http server that validates requests based on a set of given user's GitHub usernames. The server will look up the user's public keys (from `https://github.com/username.keys`), and add all the user's key to the in-memory database.

The client can then use one of the corresponding private keys they've registered in GitHub, and sign their request to the server with their SSH ECDSA or RSA key. (`ssh-ed25519` are not yet supported)

```sh
./bin/gh_server --usernames micahhausler
```

```sh
./bin/gh_client -key ~/.ssh/id_rsa
HTTP/1.1 200 OK
Content-Length: 20
Content-Type: text/plain; charset=utf-8
Date: Sun, 29 Sep 2024 02:33:59 GMT

hello, micahhausler!
```

## Simple Server with local keys or HMAC

The simple server has 3 users in its database: `alice` who is identified by a specified ECDSA key, `bob` who uses a pre-shared HMAC secret, and `eve` who uses an RSA keypair.

```sh
# Create test ECDSA keypair id_ecdsa/id_ecdsa.pub
mkdir -p keys/
ssh-keygen -f ./keys/id_ecdsa -t ecdsa -N ""
ssh-keygen -f ./keys/id_rsa -t rsa -b 4096 -N ""
./bin/server --ecdsa-pubkey ./keys/id_ecdsa.pub --rsa-pubkey ./keys/id_rsa.pub
```

In another tab, run the client
```
# Alice uses an ECDSA key
$ ./bin/client --key ./keys/id_ecdsa --key-id alice
2024/09/28 20:20:56 INFO Using ecdsa P256 signer key-id=alice
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: Sun, 29 Sep 2024 01:20:56 GMT

hello, alice!

# Bob uses an hmac pre-shared secret
$ ./bin/client --key-id bob
2024/09/28 20:21:07 INFO Using HMAC SHA-256 signer key-id=bob
HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8
Date: Sun, 29 Sep 2024 01:21:07 GMT

hello, bob!

# eve uses an RSA key
$ ./bin/client --key ./keys/id_rsa --key-id eve
2024/09/28 20:21:16 INFO Using ecdsa P256 signer key-id=eve
HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8
Date: Sun, 29 Sep 2024 01:21:16 GMT

hello, eve!
```

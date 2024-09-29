# RFC 9421 scratch project in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/micahhausler/httpsig-scratch.svg)](https://pkg.go.dev/github.com/micahhausler/httpsig-scratch)

I'm starting with https://github.com/common-fate/httpsig but want to also try some other libraries:

* https://github.com/remitly-oss/httpsig-go
* https://github.com/yaronf/httpsign

Tasks:
- [x] Run example client and server
- [x] Get server to support multiple algorithms
- [ ] GitHub key database
  - [x] Create KeyDirectory backed by GitHub usernames
  - [x] Integrate KeyDirectory into server
  - [ ] Get client signer to sign with SSH RSA or ECDSA Key
- [ ] Impose specific signature base from the server
- [ ] Define a signature input format for the client, including algo.

## Build
```sh
make all
```

## Example

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

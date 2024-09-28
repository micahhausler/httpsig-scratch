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

```
$ ./bin/server
```

In another tab
```
$ ./bin/client
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: Sat, 28 Sep 2024 17:39:47 GMT

hello, alice!
$ ./bin/client -kid micah -alg hmac-sha256
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: Sat, 28 Sep 2024 17:39:56 GMT

hello, micah!
```

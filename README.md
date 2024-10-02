# RFC 9421 scratch project in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/micahhausler/httpsig-scratch.svg)](https://pkg.go.dev/github.com/micahhausler/httpsig-scratch)

## Example 1: GitHub SSH keys as identifiers

This package contains an example http server that validates requests based on a set of given user's GitHub usernames. The server will look up the user's public keys (from `https://github.com/username.keys`), and add all the user's key to the in-memory database.

The client can then use one of the corresponding private keys they've registered in GitHub, and sign their request to the server with their SSH ECDSA or RSA key. (`ssh-ed25519` are not yet supported)

```sh
make gh_server
```

```sh
$ make gh_client GH_KEY=~/.ssh/id_rsa
HTTP/1.1 200 OK
Content-Length: 20
Content-Type: text/plain; charset=utf-8
Date: Sun, 29 Sep 2024 02:33:59 GMT

hello, micahhausler!
```

## Example 2: Server using Session Token concept 

Rather than force the server to keep a database of KeyIDs to users, a scalable 
model for mapping keys to users is to use an encrypted "SessionToken" concept.
In this model, clients pre-register their public key (or HMAC secret) with the
server (or some other service), and the server responds with an encrypted
session token containing both the public key (or HMAC secret) and metadata the 
server can parse to make assertions about the user.  

In this example, the server has a `/session-token` endpoint (currently with no 
auth), that accepts a users's public key and the user specifies their username 
(in a real scenario, you'd have some other form of authentication and the 
server would set the username in the session token). The server uses a 256 bit
symmetric AES key to encrypt (and later decrypt) the session token it crafts. 

The example server has a second endpoint wrapped in a middleware that checks 
for an `x-session-token` header, and adds the encrypted session token to the
request context. When the httpsig `verifier` middleware is later invoked, it 
calls the outer middleware's key directory `GetKey()` method. This `GetKey()` 
method extracts the encrypted session token from the supplied context.Context,
decrypts it, validates that keyID and algoritm included in the signed request
match what is included in the token, and returns a `verifier.Algorithm` which 
the `verifier` middleware can invoke `verifier.Algorithm.Verify()` against, and
ensure the request was properly signed. 

In order to ensure the included encrypted token value is intended for a given
request, the server requries `x-session-token` be included in the client's 
signature base. 

To launch the session token server, run:
```sh
make session_server
```

To launch the client 3 times with different keys, run:
```sh
make session_client
```

Each time, the client will invoke `/session-token` with its signing key and 
then include that encrypted token in a subsequent request

```sh
$ make session_client  
go build -o bin/session_client cmd/session_token/client/main.go
./bin/session_client \
		--key ./keys/id_ecdsa \
		--key-algo ecdsa-p256-sha256
time=2024-10-02T10:26:56.844-05:00 level=INFO msg="Using ecdsa P384 signer" key-algo=ecdsa-p256-sha256 username=alice
time=2024-10-02T10:26:56.844-05:00 level=INFO msg="Creating session token for key" request="&{UserInfo:{Username:alice} KeyID:kid-123 Alg:ecdsa-p256-sha256 PublicKey:-----BEGIN ECDSA PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeMgtCvP9evIaBYhL3cQluU3wPFOl\nBUc1pLHamyG9eMEufGQ8wCbXJ4jt5d88Y/7/b9Q0zAGFUVgYQ86ORyc50A==\n-----END ECDSA PUBLIC KEY-----\n}"
time=2024-10-02T10:26:56.849-05:00 level=INFO msg="Got encrypted session token from server"
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: Wed, 02 Oct 2024 15:26:56 GMT

hello, alice!

./bin/session_client \
		--key ./keys/hmac.key \
		--key-algo hmac-sha256 
time=2024-10-02T10:26:56.864-05:00 level=INFO msg="Using HMAC SHA-256 signer" key-algo=hmac-sha256 username=bob
time=2024-10-02T10:26:56.864-05:00 level=INFO msg="Creating session token for key" request="&{UserInfo:{Username:bob} KeyID:kid-123 Alg:hmac-sha256 PublicKey:eToX3qbmRRnAB/WylWxVLPlOataS/ul37OCiSdhK8oU=\n}"
time=2024-10-02T10:26:56.867-05:00 level=INFO msg="Got encrypted session token from server"
HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8
Date: Wed, 02 Oct 2024 15:26:56 GMT

hello, bob!

./bin/session_client \
		--key ./keys/id_rsa \
		--key-algo rsa-pss-sha512 
time=2024-10-02T10:26:56.879-05:00 level=INFO msg="Using RSAPSS512 signer" key-algo=rsa-pss-sha512 username=charlie
time=2024-10-02T10:26:56.879-05:00 level=INFO msg="Creating session token for key" request="&{UserInfo:{Username:charlie} KeyID:kid-123 Alg:rsa-pss-sha512 PublicKey:-----BEGIN RSA PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAva37Qyfj7StT2hzunifv\nqE9jvy+NLVlWgQo6WRid9p0su4YxDgwu0x1oilOpiayzJYnOqhrtozJ+7+uLBpQf\nndKna0qhzeSCaxLIBf+mj8g21gVTNPP4L6xyW5QOu0vItTsjYD/h2A5qiXU7/O1K\n7k0URIEInjWS4O70GXfjEZUea+nO5+PyXMjRZA8WTyjOb3c4o3BgHPK6LHxi89cb\nfzIdceXEOhT2/1O+233nWyfNyLK5DiRC7MdWXK+7gRigtf3NtMFiuKxzX2eo52G2\nKdQFQWI9k/wim6mlE1PmUtGOrS9nlt0puzeIFHn2McIpLBMKwRg6nmLaqwAHSxc7\n7UqVGCJAce8eVHmZRh3TCu34rCrTuXvnTiXgwpZb3thXKrC6dMobX2/eYZ0ZkAGx\nd2G/JP9+9ZlCur2Z18peYwu7l8IUBCQ7JhXl77AWb6i1BsiNQ3mDdG24enw/BbXc\npeEEA/TedEcXA1KiDPQj4oY3A7gs91dLEshoOMnXcBp6plR/oo6+Z6ZQoQLsCoDl\n5ye9b8BJY4mFCLlgROk2Czph5g0V025/slyrwIOo2pfxxrCJCpXP8GPivdpR2GFK\nlqNRrEr2OQBbvso0PJKe/vifQJVaHtNsCuVIgi8E4Xi15amWD7l1NDpauSbfYRGz\nD63KsjB0LMD97KdrKuz+DH8CAwEAAQ==\n-----END RSA PUBLIC KEY-----\n}"
time=2024-10-02T10:26:56.882-05:00 level=INFO msg="Got encrypted session token from server"
HTTP/1.1 200 OK
Content-Length: 15
Content-Type: text/plain; charset=utf-8
Date: Wed, 02 Oct 2024 15:26:56 GMT

hello, charlie!
```

Passing the session token around via the request context is smelly, and should
probably be refactored so the verifier can directly access the header. 

## Example 3: Kubernetes Signed Request Proxy 

A real world application server that could reap the benefits of message signing
is Kubernetes. Today, there is no support for client authentication methods 
other than token-based or x509. Kubernetes does support a front [authenticating
proxy][k8s-auth-proxy] which can use a custom authenticating method. For this
example, we use that feature. 

The proxy server uses the GitHub signing key lookup for identity, so you'll 
need to run the client on a host that has one of your GitHub private keys.

```sh
# Get the kind cluster up and running
make kind
# Launch the proxy server
make proxy_server
```

And to run 
```sh
# Set GH_KEY to whatever your github signing key is
make proxy_client GH_KEY=~/.ssh/id_rsa 
```

In this example, the client only identifies itself by the keyid in the signed
request, (which is the SHA512 of the serialized public key bytes in SSH wire 
format). The server has pre-fetched the public SSH keys for GitHub users and 
will map the corresponding key to the username.

Kubernetes does not (yet!?) support request signing in clients, so tools like
`kubectl` or wont be able to directly use this. The example client however uses
Kubernetes `client-go` and overrides the Kubernetes client's `http.Client`. 

```sh
$ make proxy_client GH_KEY=~/.ssh/id_ecdsa
./bin/proxy_client \
		-v 99 \
		--key ~/.ssh/id_ecdsa \
		--kubeconfig ./kubeconfig
{"time":"2024-10-02T11:28:29.852923-05:00","level":"DEBUG","source":{"function":"github.com/micahhausler/httpsig-scratch/gh.NewGHSigner","file":"/Users/mhausler/go/src/github.com/micahhausler/httpsig-scratch/gh/signer.go","line":35},"msg":"using ECDSA key"}
I1002 11:28:29.853767   21104 loader.go:395] Config loaded from file:  ./kubeconfig
I1002 11:28:29.854181   21104 main.go:86] Creating self subject review, `kubectl auth whoami`
I1002 11:28:29.854679   21104 request.go:1351] Request Body: {"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1","metadata":{"creationTimestamp":null},"status":{"userInfo":{}}}
I1002 11:28:29.854849   21104 main.go:73] "signing string" string=<
	"@method": POST
	"@target-uri": https://127.0.0.1:9091/apis/authentication.k8s.io/v1/selfsubjectreviews
	"content-type": application/json
	"content-length": 132
	"content-digest": sha-256=:Qvw0kFms9RIhpCFOaD/51GLWanvGkrzQzeZbQRjUqdw=:
	"@signature-params": ("@method" "@target-uri" "content-type" "content-length" "content-digest");keyid="7829c799f966275fa9a01ae111e6dd249522611c8df502fcaed17dca039cf1aeeeb2e3bc95e23f4f3326195a14a55aeadbd75f761c501dbb6cb5a3874756ff88";alg="ecdsa-p256-sha256";tag="foo";nonce="3j6DbggKbhRrgufPds9Kq2igG2DgMBobI-1kZEyEKCQ=";created=1727886509
 >
I1002 11:28:29.870647   21104 request.go:1351] Response Body: {"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1","metadata":{"creationTimestamp":"2024-10-02T16:28:29Z"},"status":{"userInfo":{"username":"micahhausler","groups":["github:users","system:authenticated"]}}}
metadata:
  creationTimestamp: "2024-10-02T16:28:29Z"
status:
  userInfo:
    groups:
    - github:users
    - system:authenticated
    username: micahhausler
```

[k8s-auth-proxy]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#authenticating-proxy

## Notes

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
- [x] Session Token example server
  - [x] alternate endpoint to create a token
  - [x] middleware to embed token in context 
- [x] Kubernetes authenticating proxy
  - [x] Get an example server and client up and running with kind
  - [ ] Figure out how to define the http client's Transport only once: right now its in client and config construction
  - [ ] Impose specific signature base from the server per endpoint (ex: `GET` doesn't need content-type/-length/-digest)
  - [ ] Define a signature input format for the client, including algo that can be read from kubeconfig

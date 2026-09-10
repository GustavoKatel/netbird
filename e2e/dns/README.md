Run the Management-to-client DoH test on a Linux host with Docker:

```sh
go test -tags 'e2e devcert' -v ./e2e/dns -timeout 5m
```

The harness builds the current Management and client sources. The test creates a
nameserver group through the API, reads it back, and checks that the client's
system resolver returns an answer available only from a local HTTPS fixture.
The fixture certificate is explicitly trusted inside the disposable client
container. Containers and their network are removed on completion.

The fixture binds to the host's default Docker bridge address. This test requires
local Docker; remote daemons and Docker Desktop are not supported.

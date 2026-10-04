# relayd — strict HTTP/1.1 GET/POST TCP reverse proxy

A minimal, defensive reverse proxy for a **fixed upstream address**. It is
plain TCP only: no TLS, no `Upgrade`/WebSocket, no `CONNECT` tunneling. Only
`GET` and `POST` over HTTP/1.1 are accepted.

The proxy parses the wire format itself (start line, strict CRLF headers,
`Content-Length` and `Transfer-Encoding: chunked` framing) instead of relying
on a tolerant HTTP stack, so ambiguous requests cannot be interpreted one way
by this proxy and another way by the origin.

## Build / run

```sh
go build -o relayd ./cmd/relayd
./relayd -listen :8080 -upstream 127.0.0.1:9000
# flags: -idle-timeout (default 60s), -dial-timeout (default 10s)
```

## What is enforced

Wire grammar (rejected with `400` and a closed connection):

- bare LF is not a line terminator — only CRLF;
- obs-folded (continuation-line) headers are refused;
- duplicate `Content-Length`, comma lists, leading zeros, or non-decimal values;
- `Content-Length` and `Transfer-Encoding` together (request smuggling shape);
- `Transfer-Encoding` other than exactly `chunked` (no lists, no other codings);
- malformed chunk size / CRLF / trailer, or a body that ends without the
  terminating zero chunk;
- non-HTTP/1.1 requests, non-origin-form targets, bad tokens.

Method policy: anything other than GET/POST gets `501` and the connection
closes. `CONNECT` is parsed in authority-form only so it can be refused with
`501`; it is never tunneled. `Upgrade` offers are treated as ordinary
requests and the header is stripped — the protocol is never switched.

Length policy: each request body is capped at **32 KiB** de-framed.
`Content-Length` over the cap is refused at the head; a chunked body that
crosses the cap is refused as soon as the offending chunk-size is seen.

Forwarding normalization:

- all hop-by-hop fields are removed (`Connection` and the headers it names,
  `Keep-Alive`, `Proxy-Connection`, `Proxy-*`, `TE`, `Trailer(s)`,
  `Transfer-Encoding`, `Content-Length`, `Upgrade`, `Expect`);
- exactly **one** explicit, unambiguous length encoding is generated
  upstream: `Content-Length: N` (GET becomes `0`) for identity requests,
  `Transfer-Encoding: chunked` for chunked requests — never both;
- `Expect: 100-continue` is terminated by the proxy (it sends
  `100 Continue` itself) and never forwarded.

## Failure model (the core invariants)

The body is streamed through a fixed 4 KiB window; a whole request body is
never buffered. As soon as framing breaks, **both** transports are torn down,
they are never reused, and any queued pipelined requests are never sent:

- downstream cancels or its body ends half-way;
- an illegal chunk or an over-limit length is encountered;
- the upstream response head or body is truncated/illegal;
- a write to either side fails.

There is **no upstream retry**: after the first byte of a request is sent,
re-dialing could duplicate an origin side effect. Every request whose bytes
began flowing upstream is journaled with the number of body bytes forwarded
and an `incomplete` (or, for a grammar violation, `rejected`) outcome. Those
forwarded bytes are **not** withdrawn — the origin side effects of whatever
it consumed stand. Pipelined requests are forwarded strictly in order, so
bytes of one request can never be framed into another on the upstream wire.

## Journal

Every request emits lifecycle events:

- `accepted` — head valid, forwarding began;
- `completed` — body sent and full response relayed;
- `incomplete` — forwarding began but the exchange did not finish
  (`forwarded=true`, `forwardedBytes=N`);
- `rejected` — refused (`forwarded` says whether some bytes had already gone
  upstream before a body-framing violation).

`relay.StdLogger` prints them; tests use `relay.MemoryJournal`.

## Tests

```sh
go test ./relay/ -race -count=5
```

The suite contains unit tests for the parser/chunked decoder and real
end-to-end tests over loopback TCP with:

- a self-written raw upstream that re-parses framing and records request
  boundaries and per-body SHA-256 digests;
- clients delivering traffic **byte-by-byte and in random-sized segments**;
- slow trickle slower than the idle timeout (deadline resets on progress);
- duplicate/ambiguous length declarations, folded headers, bad chunks,
  oversize bodies, `CONNECT`, upgrade offers;
- truncated request and response bodies and abrupt downstream cancellation,
  asserting both transports close, queued requests are withheld, upstream
  boundaries/digests are exact, and forwarded partial bytes are journaled.

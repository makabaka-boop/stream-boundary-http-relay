package relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
)

// forwardRequest writes one normalized request head and streams its body to
// upstream. It returns the number of de-framed body bytes already written.
//
// fatal=true means the exchange is unrecoverable: both transports must be torn
// down, no queued request may follow, and ev already carries the terminal
// classification (rejected vs incomplete).
func (s *Server) forwardRequest(h *Head, downBR *bufio.Reader, down net.Conn, up net.Conn, ev *Event) (int64, bool) {
	// Emit end-to-end headers (framing fields stripped), then exactly one
	// unambiguous length encoding of our own.
	if err := writeForwardedRequestHead(up, h); err != nil {
		ev.Kind = EvIncomplete
		ev.Reason = "upstream write head: " + err.Error()
		return 0, true
	}
	markForwarded := func() { ev.Forwarded = true }

	var framing string
	switch h.BodyFraming {
	case FrameNone:
		framing = "Content-Length: 0\r\n"
	case FrameLength:
		framing = fmt.Sprintf("Content-Length: %d\r\n", h.ContentLength)
	case FrameChunked:
		framing = "Transfer-Encoding: chunked\r\n"
	}
	if _, err := io.WriteString(up, framing+"Connection: keep-alive\r\n\r\n"); err != nil {
		ev.Kind = EvIncomplete
		ev.Reason = "upstream write framing: " + err.Error()
		return 0, true
	}

	switch h.BodyFraming {
	case FrameNone:
		return 0, false
	case FrameLength:
		if h.ContentLength == 0 {
			return 0, false
		}
		markForwarded()
		n, err := copyExact(up, downBR, h.ContentLength)
		if err == nil {
			return n, false
		}
		// Source truncated mid-body: our own Content-Length framing to origin
		// is now broken. Never reuse upstream; do not invent a 400 on a wire
		// the peer already abandoned.
		ev.Kind = EvIncomplete
		ev.Reason = "request body truncated: " + err.Error()
		return n, true
	case FrameChunked:
		markForwarded()
		cr := NewChunkedReader(downBR, MaxBody)
		n, err := rechunk(up, cr)
		if err != nil {
			// Illegal chunk, oversize body, or half-open client: upstream got
			// partial chunks with no terminator. Record forwarded bytes; the
			// origin side effects of what it already consumed stand.
			if isProtoErr(err) {
				ev.Kind = EvRejected
			} else {
				ev.Kind = EvIncomplete
			}
			ev.Reason = "chunked request body: " + err.Error()
			// Best effort to tell the client, then tear down regardless.
			if isProtoErr(err) {
				writeStatus(down, 400, "Bad Request")
			}
			return n, true
		}
		if err := writeChunkEnd(up); err != nil {
			ev.Kind = EvIncomplete
			ev.Reason = "upstream write final chunk: " + err.Error()
			return n, true
		}
		return n, false
	}
	return 0, false
}

func isProtoErr(err error) bool {
	var pe *ProtoError
	return errors.As(err, &pe)
}

package relay

import (
	"bufio"
	"fmt"
	"io"
	"net"
)

// relayResponse reads one upstream response and streams it downstream. It
// returns true only when both transports remain framing-consistent and may be
// reused for the next pipelined request.
//
// On a truncated or malformed response, or any downstream write error, it sets
// ev to a terminal kind and returns false: the caller closes both ends and
// never touches queued pipelined requests.
func (s *Server) relayResponse(h *Head, down, up net.Conn, upBR *bufio.Reader, downClose bool, ev *Event) bool {
	var rh *Head
	// Defensively consume and drop any 1xx interim responses (we never
	// advertised Expect upstream, but a tolerant origin may send one anyway).
	for {
		r, err := ReadHead(upBR)
		if err != nil {
			ev.Kind = EvIncomplete
			ev.Reason = "upstream response head: " + err.Error()
			writeStatus(down, 502, "Bad Gateway")
			return false
		}
		if r.StatusCode >= 100 && r.StatusCode < 200 {
			continue
		}
		rh = r
		break
	}

	mode := responseBodyMode(rh)

	// Upstream is reusable only for an HTTP/1.1 persistent connection whose
	// body self-delimits and that did not ask to close.
	upKeep := !rh.WantsClose && mode != bodyClose
	clientClose := downClose || rh.WantsClose || mode == bodyClose

	if err := writeResponseHead(down, rh, mode, clientClose); err != nil {
		ev.Kind = EvIncomplete
		ev.Reason = "downstream write response head: " + err.Error()
		return false
	}

	switch mode {
	case bodyNone:
		// header-only response
	case bodyLength:
		if _, err := copyExact(down, upBR, rh.ContentLength); err != nil {
			ev.Kind = EvIncomplete
			ev.Reason = "upstream response truncated (content-length): " + err.Error()
			return false
		}
	case bodyChunked:
		cr := NewChunkedReader(upBR, 0)
		if _, err := rechunk(down, cr); err != nil {
			ev.Kind = EvIncomplete
			ev.Reason = "upstream response chunked: " + err.Error()
			return false
		}
		if err := writeChunkEnd(down); err != nil {
			ev.Kind = EvIncomplete
			ev.Reason = "downstream write final chunk: " + err.Error()
			return false
		}
	case bodyClose:
		if _, err := drainToClose(down, upBR); err != nil {
			ev.Kind = EvIncomplete
			ev.Reason = "relay close-delimited body: " + err.Error()
			return false
		}
	}

	// Exchange finished. A false result only means the transports must close;
	// the completed event still stands.
	ev.Kind = EvCompleted
	return upKeep && !clientClose
}

type bodyMode int

const (
	bodyNone bodyMode = iota
	bodyLength
	bodyChunked
	bodyClose
)

func responseBodyMode(h *Head) bodyMode {
	if statusNoBody(h.StatusCode) {
		return bodyNone
	}
	switch h.BodyFraming {
	case FrameLength:
		if h.ContentLength == 0 {
			return bodyNone
		}
		return bodyLength
	case FrameChunked:
		return bodyChunked
	default:
		return bodyClose
	}
}

// statusNoBody covers 1xx informational responses and the two header-only codes.
func statusNoBody(code int) bool {
	return (code >= 100 && code < 200) || code == 204 || code == 304
}

func writeResponseHead(w io.Writer, h *Head, mode bodyMode, clientClose bool) error {
	if err := writeForwardedResponseHead(w, h); err != nil {
		return err
	}
	var tail string
	switch mode {
	case bodyLength:
		tail = fmt.Sprintf("Content-Length: %d\r\n", h.ContentLength)
	case bodyChunked:
		tail = "Transfer-Encoding: chunked\r\n"
	}
	if clientClose {
		tail += "Connection: close\r\n"
	} else {
		tail += "Connection: keep-alive\r\n"
	}
	_, err := io.WriteString(w, tail+"\r\n")
	return err
}

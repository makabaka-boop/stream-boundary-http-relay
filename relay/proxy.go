// Package relay implements a strict HTTP/1.1 GET/POST TCP reverse proxy.
//
// It parses start lines and CRLF headers itself, supports request pipelining,
// streams bodies (never buffering a whole one), caps each request body at
// 32KiB, and re-emits exactly one unambiguous length encoding upstream.
// Ambiguous or illegal framing tears both transports down: the connections
// are never reused and queued pipelined requests are never sent.
package relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// Config configures a Server.
type Config struct {
	Listen      string        // downstream listen address, e.g. ":8080"
	Upstream    string        // fixed upstream address, e.g. "127.0.0.1:9000"
	IdleTimeout time.Duration // no-data timeout on either transport (0 = none)
	DialTimeout time.Duration // upstream dial timeout
	Journal     Journal       // lifecycle event sink
}

// Server is the reverse proxy.
type Server struct {
	cfg    Config
	ln     net.Listener
	connID atomic.Uint64
}

// NewServer validates cfg and builds a Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Upstream == "" {
		return nil, errors.New("relay: upstream address required")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":http"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	return &Server{cfg: cfg}, nil
}

// Addr returns the listener address once Serve is running.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Serve accepts connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	s.ln = l
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveConn(c)
	}
}

func (s *Server) record(ev Event) {
	if s.cfg.Journal != nil {
		ev.Time = time.Now()
		s.cfg.Journal.Record(ev)
	}
}

// serveConn serves every pipelined request on one downstream connection with
// at most one upstream connection. All forwarding is serial.
func (s *Server) serveConn(rawDown net.Conn) {
	down := newIdleConn(rawDown, s.cfg.IdleTimeout)
	defer down.Close()
	cid := s.connID.Add(1)
	downBR := bufio.NewReaderSize(down, 16*1024)

	var (
		up      net.Conn
		upBR    *bufio.Reader
		upValid bool // true while the upstream transport is reusable
	)
	closeUp := func() {
		if up != nil {
			_ = up.Close()
		}
		up, upBR, upValid = nil, nil, false
	}
	defer closeUp()

	seq := 0
	downClose := false
	for !downClose {
		h, err := ReadHead(downBR)
		if err != nil {
			var me *MethodError
			switch {
			case errors.As(err, &me):
				s.record(Event{ConnID: cid, Seq: seq + 1, Kind: EvRejected,
					Method: me.Method, Reason: "method not supported"})
				writeStatus(down, 501, "Not Implemented")
				closeUp()
				return
			case isCleanEOF(err):
				return // idle peer closed cleanly between requests
			default:
				s.record(Event{ConnID: cid, Seq: seq + 1, Kind: EvRejected,
					Reason: "request head: " + err.Error()})
				writeStatus(down, 400, "Bad Request")
				closeUp()
				return
			}
		}
		seq++
		ev := Event{ConnID: cid, Seq: seq, Method: h.Method, Target: h.Target, Kind: EvAccepted}
		downClose = h.WantsClose

		// One upstream connection, opened lazily. A failed dial is terminal:
		// retrying a (possibly already received) POST could duplicate effects.
		if !upValid {
			u0, derr := net.DialTimeout("tcp", s.cfg.Upstream, s.cfg.DialTimeout)
			if derr != nil {
				ev.Kind = EvIncomplete
				ev.Reason = "dial upstream: " + derr.Error()
				s.record(ev)
				writeStatus(down, 502, "Bad Gateway")
				return
			}
			u := newIdleConn(u0, s.cfg.IdleTimeout)
			up, upBR, upValid = u, bufio.NewReaderSize(u, 16*1024), true
		}

		if h.Expect100 {
			if _, err := down.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n")); err != nil {
				ev.Kind = EvIncomplete
				ev.Reason = "downstream gone while sending 100-continue"
				s.record(ev)
				closeUp()
				return
			}
		}

		// Forward the head with one explicit length encoding, then stream the
		// body. Any break after the first upstream byte => poisoned upstream.
		n, fatal := s.forwardRequest(h, downBR, down, up, &ev)
		ev.ForwardedBytes = n
		if fatal {
			closeUp()
			s.record(ev)
			return
		}

		ok := s.relayResponse(h, down, up, upBR, downClose, &ev)
		if !ok {
			closeUp()
			s.record(ev)
			return
		}
		if ev.Kind == EvAccepted {
			ev.Kind = EvCompleted
		}
		s.record(ev)
	}
}

func isCleanEOF(err error) bool { return errors.Is(err, io.EOF) }

// writeStatus emits a minimal error response with one explicit length.
func writeStatus(w io.Writer, code int, reason string) {
	body := reason + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %03d %s\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, reason, len(body), body)
}

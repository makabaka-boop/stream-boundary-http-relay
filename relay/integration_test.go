package relay

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- scripted raw upstream -------------------------------------------------

type capturedReq struct {
	connID     int
	seq        int
	method     string
	target     string
	headers    []Header
	body       []byte
	partial    bool // body ended with a framing error / EOF
	bodyDigest string
}

func (c capturedReq) header(name string) (string, bool) {
	return findHeader(c.headers, name)
}

func findHeader(hs []Header, name string) (string, bool) {
	name = strings.ToLower(name)
	for _, h := range hs {
		if strings.ToLower(h.Name) == name {
			return h.Value, true
		}
	}
	return "", false
}

func (h *Head) header(name string) (string, bool) {
	return findHeader(h.Headers, name)
}

// respPlan tells the fake upstream how to answer one request.
type respPlan struct {
	// head is the exact, already-framed head block (must end in \r\n\r\n).
	head string
	// mode: "identity" (write body as-is, CL declared in head),
	// "chunked" (TE declared in head, body encoded here),
	// "close" (write body then close),
	// "truncated" (head declares more than body; write body then close),
	// "badchunk" (valid first chunk, then illegal size line, then close).
	mode string
	body []byte
}

type fakeUpstream struct {
	ln        net.Listener
	responder func(seq int, req capturedReq) respPlan

	mu        sync.Mutex
	reqs      []capturedReq
	conns     atomic.Int64
	closedCh  chan int // connIDs whose request body arrived partial
	anyClose  chan int // connIDs when the handler returns for any reason
	recordedN chan struct{}
}

func newFakeUpstream(t *testing.T, responder func(int, capturedReq) respPlan) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{
		ln: ln, responder: responder,
		closedCh:  make(chan int, 64),
		anyClose:  make(chan int, 64),
		recordedN: make(chan struct{}, 256),
	}
	go u.serve()
	return u
}

func (u *fakeUpstream) serve() {
	for {
		c, err := u.ln.Accept()
		if err != nil {
			return
		}
		u.conns.Add(1)
		go u.handle(c)
	}
}

func (u *fakeUpstream) handle(c net.Conn) {
	cid := int(u.conns.Load())
	defer func() {
		c.Close()
		select {
		case u.anyClose <- cid:
		default:
		}
	}()
	br := bufio.NewReaderSize(c, 4096)
	seq := 0
	for {
		h, err := ReadHead(br)
		if err != nil {
			return
		}
		var body []byte
		partial := false
		switch h.BodyFraming {
		case FrameLength:
			buf := make([]byte, h.ContentLength)
			n, rerr := io.ReadFull(br, buf)
			body = buf[:n]
			partial = rerr != nil
		case FrameChunked:
			cr := NewChunkedReader(br, MaxBody*4)
			b, rerr := io.ReadAll(cr)
			body = b
			partial = rerr != nil
		}
		sum := sha256.Sum256(body)
		cap := capturedReq{
			connID: cid, seq: seq, method: h.Method, target: h.Target,
			headers: append([]Header(nil), h.Headers...), body: body,
			partial: partial, bodyDigest: hex.EncodeToString(sum[:]),
		}
		u.mu.Lock()
		u.reqs = append(u.reqs, cap)
		u.mu.Unlock()
		select {
		case u.recordedN <- struct{}{}:
		default:
		}
		seq++

		if partial {
			// A real origin cannot answer a request whose body never arrived
			// framing-intact; it just closes.
			u.closedCh <- cid
			return
		}

		plan := u.responder(seq-1, cap)
		if _, err := io.WriteString(c, plan.head); err != nil {
			return
		}
		switch plan.mode {
		case "identity", "":
			if _, err := c.Write(plan.body); err != nil {
				return
			}
		case "chunked":
			writeChunks(c, plan.body)
		case "slowchunked":
			writeSlowChunks(c, plan.body, 15*time.Millisecond)
		case "close", "truncated":
			_, _ = c.Write(plan.body)
			return
		case "badchunk":
			io.WriteString(c, fmt.Sprintf("%x\r\n", len(plan.body)))
			c.Write(plan.body)
			io.WriteString(c, "\r\nGARBAGE\r\n")
			return
		}
		if strings.Contains(strings.ToLower(plan.head), "connection: close") {
			return
		}
	}
}

func writeChunks(w io.Writer, body []byte) {
	for len(body) > 0 {
		n := 1 + rand.Intn(1400)
		if n > len(body) {
			n = len(body)
		}
		fmt.Fprintf(w, "%x\r\n", n)
		w.Write(body[:n])
		io.WriteString(w, "\r\n")
		body = body[n:]
	}
	io.WriteString(w, "0\r\n\r\n")
}

func writeSlowChunks(w io.Writer, body []byte, d time.Duration) {
	for len(body) > 0 {
		n := 64
		if n > len(body) {
			n = len(body)
		}
		fmt.Fprintf(w, "%x\r\n", n)
		w.Write(body[:n])
		io.WriteString(w, "\r\n")
		body = body[n:]
		time.Sleep(d)
	}
	io.WriteString(w, "0\r\n\r\n")
}

func (u *fakeUpstream) snapshot() []capturedReq {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]capturedReq, len(u.reqs))
	copy(out, u.reqs)
	return out
}

// waitRecords blocks until at least n requests have been fully captured
// (body framing resolved), or the timeout elapses.
func (u *fakeUpstream) waitRecords(n int, timeout time.Duration) {
	deadline := time.After(timeout)
	for got := 0; got < n; got++ {
		select {
		case <-u.recordedN:
		case <-deadline:
			return
		}
	}
}

func (u *fakeUpstream) close() { u.ln.Close() }

// ---- test harness ----------------------------------------------------------

type testEnv struct {
	t   *testing.T
	up  *fakeUpstream
	srv *Server
	ln  net.Listener
	j   *chanJournal
}

type chanJournal struct{ ch chan Event }

func (c *chanJournal) Record(ev Event) { c.ch <- ev }

func setup(t *testing.T, responder func(int, capturedReq) respPlan, idle time.Duration) *testEnv {
	t.Helper()
	up := newFakeUpstream(t, responder)
	j := &chanJournal{ch: make(chan Event, 256)}
	srv, err := NewServer(Config{
		Upstream:    up.ln.Addr().String(),
		IdleTimeout: idle,
		DialTimeout: 2 * time.Second,
		Journal:     j,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	e := &testEnv{t: t, up: up, srv: srv, ln: ln, j: j}
	t.Cleanup(func() {
		ln.Close()
		up.close()
	})
	return e
}

func (e *testEnv) dial() net.Conn {
	c, err := net.Dial("tcp", e.ln.Addr().String())
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func echoResponder(seq int, req capturedReq) respPlan {
	body := append([]byte("echo:"), req.body...)
	return respPlan{
		head: fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nX-Seq: %d\r\n\r\n", len(body), seq),
		body: body,
		mode: "identity",
	}
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sendSplits writes all of data in pseudo-randomly sized TCP segments.
func sendSplits(t *testing.T, c net.Conn, data []byte, rng *rand.Rand, maxSeg int) {
	t.Helper()
	for len(data) > 0 {
		n := 1 + rng.Intn(maxSeg)
		if n > len(data) {
			n = len(data)
		}
		if _, err := c.Write(data[:n]); err != nil {
			t.Fatalf("client write: %v", err)
		}
		data = data[n:]
	}
}

// readOneResponse parses one downstream response and returns its body.
func readOneResponse(t *testing.T, br *bufio.Reader) (*Head, []byte) {
	t.Helper()
	var h *Head
	for {
		parsed, err := ReadHead(br)
		if err != nil {
			t.Fatalf("client read response head: %v", err)
		}
		if parsed.StatusCode >= 100 && parsed.StatusCode < 200 {
			continue // interim (100-continue)
		}
		h = parsed
		break
	}
	var body []byte
	switch h.BodyFraming {
	case FrameLength:
		body = make([]byte, h.ContentLength)
		if _, err := io.ReadFull(br, body); err != nil {
			t.Fatalf("client read response body: %v", err)
		}
	case FrameChunked:
		b, err := io.ReadAll(NewChunkedReader(br, 0))
		if err != nil {
			t.Fatalf("client dechunk response: %v", err)
		}
		body = b
	case FrameNone:
		if h.WantsClose {
			b, err := io.ReadAll(br)
			if err != nil {
				t.Fatalf("client read close-body: %v", err)
			}
			body = b
		}
	}
	return h, body
}

func waitEvents(t *testing.T, j *chanJournal, want int, timeout time.Duration) []Event {
	t.Helper()
	var out []Event
	deadline := time.After(timeout)
	for len(out) < want {
		select {
		case ev := <-j.ch:
			out = append(out, ev)
		case <-deadline:
			t.Fatalf("timed out waiting for %d events, got %d: %+v", want, len(out), out)
		}
	}
	return out
}

func drainEvents(j *chanJournal, d time.Duration) []Event {
	var out []Event
	deadline := time.After(d)
	for {
		select {
		case ev := <-j.ch:
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
}

// ---- tests -----------------------------------------------------------------

func TestE2E_GetStripsHopHeaders(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()
	req := "GET /a HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Connection: keep-alive, X-Gone\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"TE: trailers\r\n" +
		"Upgrade: websocket\r\n" +
		"X-Gone: secret\r\n" +
		"X-Keep: yes\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	h, body := readOneResponse(t, br)
	if h.StatusCode != 200 || string(body) != "echo:" {
		t.Fatalf("bad response: %d %q", h.StatusCode, body)
	}

	reqs := e.up.snapshot()
	if len(reqs) != 1 {
		t.Fatalf("upstream requests = %d", len(reqs))
	}
	got := reqs[0]
	for _, banned := range []string{"Keep-Alive", "Proxy-Connection", "TE", "Upgrade", "X-Gone"} {
		if _, ok := got.header(banned); ok {
			t.Errorf("hop header leaked upstream: %s", banned)
		}
	}
	// The proxy regenerates Connection itself: it must be the only value and
	// must not carry the client's connection-token "X-Gone".
	if v, ok := got.header("Connection"); !ok || v != "keep-alive" {
		t.Errorf("upstream Connection = %q (%v), want regenerated keep-alive", v, ok)
	}
	if v, ok := got.header("X-Keep"); !ok || v != "yes" {
		t.Errorf("end-to-end header missing: %v", got.headers)
	}
	if v, ok := got.header("Content-Length"); !ok || v != "0" {
		t.Errorf("GET upstream framing not explicit CL:0, got ok=%v v=%q", ok, v)
	}
	if _, ok := got.header("Transfer-Encoding"); ok {
		t.Errorf("GET must not be chunked upstream")
	}
	evs := waitEvents(t, e.j, 1, time.Second)
	if evs[0].Kind != EvAccepted && evs[len(evs)-1].Kind != EvCompleted {
		t.Fatalf("events = %+v", evs)
	}
}

func TestE2E_PostContentLengthByteByByte(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()
	body := bytes.Repeat([]byte("L"), 12345)
	req := []byte(fmt.Sprintf("POST /post/cl HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", len(body)))
	req = append(req, body...)

	// Deliver the entire message one byte at a time.
	for _, b := range req {
		if _, err := c.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	br := bufio.NewReader(c)
	h, got := readOneResponse(t, br)
	if h.StatusCode != 200 || !bytes.Equal(got, append([]byte("echo:"), body...)) {
		t.Fatalf("bad response %d len=%d", h.StatusCode, len(got))
	}
	up := e.up.snapshot()
	if len(up) != 1 || up[0].bodyDigest != digest(body) {
		t.Fatalf("upstream capture wrong: %+v", up)
	}
	if v, _ := up[0].header("Content-Length"); v != fmt.Sprintf("%d", len(body)) {
		t.Fatalf("upstream CL = %q", v)
	}
}

func TestE2E_PostChunkedRandomSplits(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 8; iter++ {
		e := setup(t, echoResponder, 5*time.Second)
		c := e.dial()
		body := make([]byte, 1+rng.Intn(30000))
		rng.Read(body)
		var wire bytes.Buffer
		fmt.Fprintf(&wire, "POST /post/chunk HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
		rest := body
		for len(rest) > 0 {
			n := 1 + rng.Intn(9000)
			if n > len(rest) {
				n = len(rest)
			}
			fmt.Fprintf(&wire, "%x\r\n", n)
			wire.Write(rest[:n])
			wire.WriteString("\r\n")
			rest = rest[n:]
		}
		wire.WriteString("0\r\nDigest-Trailer: ignored\r\n\r\n")

		sendSplits(t, c, wire.Bytes(), rng, 17)
		br := bufio.NewReaderSize(c, 2048)
		h, got := readOneResponse(t, br)
		if h.StatusCode != 200 || !bytes.Equal(got, append([]byte("echo:"), body...)) {
			t.Fatalf("iter %d: bad response %d len=%d want=%d", iter, h.StatusCode, len(got), len(body)+5)
		}
		up := e.up.snapshot()
		if len(up) != 1 {
			t.Fatalf("iter %d: upstream requests = %d", iter, len(up))
		}
		if up[0].bodyDigest != digest(body) {
			t.Fatalf("iter %d: upstream body digest mismatch", iter)
		}
		if te, ok := up[0].header("Transfer-Encoding"); !ok || te != "chunked" {
			t.Fatalf("iter %d: upstream framing = %q ok=%v", iter, te, ok)
		}
		if _, ok := up[0].header("Content-Length"); ok {
			t.Fatalf("iter %d: both length encodings present upstream", iter)
		}
		c.Close()
		e.up.close()
		e.ln.Close()
	}
}

func TestE2E_PipelinedBoundaryAndDigests(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()

	bodyA := bytes.Repeat([]byte("a"), 100)
	bodyB := make([]byte, 5000)
	for i := range bodyB {
		bodyB[i] = byte('A' + i%26)
	}
	msg := []byte(fmt.Sprintf("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(bodyA), bodyA))
	msg = append(msg, []byte(fmt.Sprintf("POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"))...)
	msg = append(msg, []byte(fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(bodyB), bodyB))...)
	msg = append(msg, []byte("GET /c HTTP/1.1\r\nHost: x\r\n\r\n")...)

	rng := rand.New(rand.NewSource(7))
	sendSplits(t, c, msg, rng, 13)

	br := bufio.NewReaderSize(c, 4096)
	for i, want := range []int{len(bodyA) + 5, len(bodyB) + 5, 5} {
		_, body := readOneResponse(t, br)
		if len(body) != want {
			t.Fatalf("response %d body len = %d, want %d", i, len(body), want)
		}
	}

	// Connection reuse: a fourth request on the same downstream conn works.
	io.WriteString(c, "GET /d HTTP/1.1\r\nHost: x\r\n\r\n")
	_, body := readOneResponse(t, br)
	if string(body) != "echo:" {
		t.Fatalf("reuse response = %q", body)
	}

	up := e.up.snapshot()
	if len(up) != 4 {
		t.Fatalf("upstream saw %d requests, want 4", len(up))
	}
	targets := []string{"/a", "/b", "/c", "/d"}
	conns := map[int]bool{}
	for i, r := range up {
		if r.target != targets[i] {
			t.Errorf("upstream order[%d] = %s, want %s", i, r.target, targets[i])
		}
		conns[r.connID] = true
	}
	if up[0].bodyDigest != digest(bodyA) || up[1].bodyDigest != digest(bodyB) {
		t.Fatal("pipelined body digests wrong — bytes crossed request boundaries")
	}
	if len(conns) != 1 {
		t.Fatalf("pipeline used %d upstream connections, want exactly 1", len(conns))
	}
}

func TestE2E_SlowTrickleBothDirections(t *testing.T) {
	up := newFakeUpstream(t, func(seq int, req capturedReq) respPlan {
		return respPlan{
			head: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			body: req.body,
			mode: "slowchunked",
		}
	})
	defer up.close()
	j := &chanJournal{ch: make(chan Event, 16)}
	srv, _ := NewServer(Config{Upstream: up.ln.Addr().String(), IdleTimeout: 200 * time.Millisecond, Journal: j})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()

	body := bytes.Repeat([]byte("s"), 4096)
	fmt.Fprintf(c, "POST /slow HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", len(body))
	// Trickle slower than the idle timeout in bursts; each progress byte must
	// reset the deadline, so the transfer must survive.
	go func() {
		for off := 0; off < len(body); off += 64 {
			end := off + 64
			if end > len(body) {
				end = len(body)
			}
			c.Write(body[off:end])
			time.Sleep(25 * time.Millisecond)
		}
	}()
	br := bufio.NewReader(c)
	h, got := readOneResponse(t, br)
	if h.StatusCode != 200 || digest(got) != digest(body) {
		t.Fatalf("slow transfer failed: code=%d len=%d", h.StatusCode, len(got))
	}
}

func TestE2E_AmbiguousLengthsRejectedBeforeUpstream(t *testing.T) {
	cases := map[string]string{
		"dup-cl":     "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nX",
		"cl-and-te":  "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nX",
		"folded":     "GET /x HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n folded\r\n\r\n",
		"te-list":    "POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
		"oversize":   "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 32769\r\n\r\n" + strings.Repeat("x", 100),
		"cl-list":    "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 1, 1\r\n\r\nX",
		"connect":    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"bad-method": "DELETE /x HTTP/1.1\r\nHost: x\r\n\r\n",
		"http10":     "GET /x HTTP/1.0\r\nHost: x\r\n\r\n",
		"bare-lf":    "GET /x HTTP/1.1\nHost: x\n\n",
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t, echoResponder, 5*time.Second)
			c := e.dial()
			io.WriteString(c, msg)
			br := bufio.NewReader(c)
			h, _ := readOneResponse(t, br)
			want := 400
			if name == "bad-method" || name == "connect" {
				want = 501
			}
			if h.StatusCode != want {
				t.Fatalf("%s: status = %d, want %d", name, h.StatusCode, want)
			}
			// After the error response the transport must be closed.
			buf := make([]byte, 16)
			if n, _ := c.Read(buf); n != 0 {
				t.Fatalf("%s: connection not closed after rejection", name)
			}
			if rs := e.up.snapshot(); len(rs) != 0 {
				t.Fatalf("%s: upstream was contacted: %+v", name, rs)
			}
			c.Close()
		})
	}
}

func TestE2E_RequestBodyTruncatedKillsPipeline(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()

	// req1 complete; req2 declares 100 bytes but the client sends 40 and then
	// half-closes. Under identity framing the body is simply truncated at the
	// transport boundary (the only boundary that exists); the crucial
	// invariants are: exactly two requests reach origin, req2's forwarded
	// byte count is journaled, and the transports are not reused.
	msg := []byte("GET /r1 HTTP/1.1\r\nHost: x\r\n\r\n")
	msg = append(msg, []byte("POST /r2 HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n")...)
	msg = append(msg, bytes.Repeat([]byte("T"), 40)...)
	c.Write(msg)
	tc := c.(*net.TCPConn)
	tc.CloseWrite()

	br := bufio.NewReader(c)
	// req1 response arrives intact...
	h1, b1 := readOneResponse(t, br)
	if h1.StatusCode != 200 || string(b1) != "echo:" {
		t.Fatalf("req1 response wrong: %d %q", h1.StatusCode, b1)
	}
	// ...then the downstream transport closes without a response for req2.
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal(err)
	}
	e.up.waitRecords(2, 3*time.Second)

	up := e.up.snapshot()
	if len(up) != 2 {
		t.Fatalf("upstream saw %d requests, want exactly 2: %+v", len(up), up)
	}
	if up[0].target != "/r1" || up[1].target != "/r2" {
		t.Fatalf("upstream targets wrong: %s %s", up[0].target, up[1].target)
	}
	if !up[1].partial || len(up[1].body) != 40 || string(up[1].body) != strings.Repeat("T", 40) {
		t.Fatalf("truncated body capture: partial=%v len=%d body=%q", up[1].partial, len(up[1].body), up[1].body)
	}

	evs := drainEvents(e.j, time.Second)
	var incomp *Event
	for i := range evs {
		if evs[i].Target == "/r2" && evs[i].Kind == EvIncomplete {
			incomp = &evs[i]
		}
	}
	if incomp == nil || !incomp.Forwarded || incomp.ForwardedBytes != 40 {
		t.Fatalf("expected incomplete event with 40 forwarded bytes: %+v", evs)
	}
}

// With chunked framing the body boundary is self-describing, so a queued
// pipelined request after an illegal/truncated chunk stream must be provably
// withheld rather than swallowed as body or parsed as a new request.
func TestE2E_ChunkedTruncationWithholdsQueued(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()

	msg := []byte("POST /p1 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	msg = append(msg, []byte("5\r\nhello\r\n")...) // one good chunk, no zero chunk
	msg = append(msg, []byte("GET /queued-never-sent HTTP/1.1\r\nHost: x\r\n\r\n")...)
	c.Write(msg)
	tc := c.(*net.TCPConn)
	tc.CloseWrite()

	// Drain until the proxy tears the downstream transport down.
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal(err)
	}
	e.up.waitRecords(1, 3*time.Second)

	up := e.up.snapshot()
	if len(up) != 1 {
		t.Fatalf("upstream saw %d requests, want exactly 1: %+v", len(up), up)
	}
	if up[0].target != "/p1" || string(up[0].body) != "hello" {
		t.Fatalf("upstream capture wrong: %+v", up[0])
	}
	if !up[0].partial {
		t.Fatal("origin must observe the request body as framing-incomplete")
	}
	// The queued request bytes must never appear on the upstream connection.
	for _, r := range up {
		if strings.Contains(string(r.body), "/queued") {
			t.Fatal("queued request bytes crossed into upstream request body")
		}
	}

	evs := drainEvents(e.j, time.Second)
	var found bool
	for _, ev := range evs {
		if ev.Target == "/p1" && ev.Forwarded && ev.ForwardedBytes == 5 &&
			(ev.Kind == EvIncomplete || ev.Kind == EvRejected) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected terminal /p1 event with 5 forwarded bytes: %+v", evs)
	}
}

// A chunked body whose transport simply drops mid-stream is "incomplete"
// (not a grammar rejection); forwarded bytes are journaled and not withdrawn.
func TestE2E_ChunkedDropIsIncomplete(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()

	msg := []byte("POST /drop HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	msg = append(msg, []byte("5\r\nhello\r\n")...) // one good chunk, no zero chunk
	c.Write(msg)
	c.(*net.TCPConn).CloseWrite()

	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal(err)
	}
	e.up.waitRecords(1, 3*time.Second)
	up := e.up.snapshot()
	if len(up) != 1 || up[0].target != "/drop" || string(up[0].body) != "hello" || !up[0].partial {
		t.Fatalf("upstream capture wrong: %+v", up)
	}
	evs := drainEvents(e.j, time.Second)
	var ev *Event
	for i := range evs {
		if evs[i].Target == "/drop" {
			ev = &evs[i]
		}
	}
	if ev == nil || ev.Kind != EvIncomplete || !ev.Forwarded || ev.ForwardedBytes != 5 {
		t.Fatalf("expected incomplete/drop forwarded=5, got %+v", ev)
	}
}

func TestE2E_IllegalChunkKillsPipeline(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()

	msg := []byte("POST /c1 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	msg = append(msg, []byte("5\r\nhello\r\nGZZZ\r\n")...) // illegal size line
	msg = append(msg, []byte("GET /c2-queued HTTP/1.1\r\nHost: x\r\n\r\n")...)
	c.Write(msg)

	br := bufio.NewReader(c)
	h, _ := readOneResponse(t, br)
	if h.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", h.StatusCode)
	}
	io.Copy(io.Discard, c)
	e.up.waitRecords(1, 3*time.Second)

	up := e.up.snapshot()
	if len(up) != 1 || up[0].target != "/c1" || string(up[0].body) != "hello" {
		t.Fatalf("upstream capture wrong: %+v", up)
	}
}

func TestE2E_UpstreamTruncatedResponse(t *testing.T) {
	up := newFakeUpstream(t, func(seq int, req capturedReq) respPlan {
		return respPlan{
			head: "HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: keep-alive\r\n\r\n",
			body: []byte("short"),
			mode: "truncated",
		}
	})
	defer up.close()
	j := &chanJournal{ch: make(chan Event, 16)}
	srv, _ := NewServer(Config{Upstream: up.ln.Addr().String(), IdleTimeout: 5 * time.Second, Journal: j})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()

	// Pipeline a queued second request that must never leave the proxy.
	io.WriteString(c, "POST /t1 HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc"+
		"GET /t2-queued HTTP/1.1\r\nHost: x\r\n\r\n")

	br := bufio.NewReaderSize(c, 4096)
	h, err := ReadHead(br)
	if err != nil {
		t.Fatal(err)
	}
	if cl, _ := h.header("Content-Length"); cl != "500" {
		t.Fatalf("downstream CL = %q", cl)
	}
	got, _ := io.ReadAll(br)
	if string(got) != "short" {
		t.Fatalf("client got %q, expected partial body then EOF", got)
	}

	upReqs := up.snapshot()
	if len(upReqs) != 1 || upReqs[0].target != "/t1" {
		t.Fatalf("queued request leaked upstream after truncated response: %+v", upReqs)
	}
	evs := waitEventsKind(j, EvIncomplete, time.Second)
	if len(evs) == 0 {
		t.Fatal("expected incomplete journal event")
	}
}

func TestE2E_UpstreamBadChunk(t *testing.T) {
	up := newFakeUpstream(t, func(seq int, req capturedReq) respPlan {
		return respPlan{
			head: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			body: []byte("partial-body"),
			mode: "badchunk",
		}
	})
	defer up.close()
	j := &chanJournal{ch: make(chan Event, 16)}
	srv, _ := NewServer(Config{Upstream: up.ln.Addr().String(), IdleTimeout: 5 * time.Second, Journal: j})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	io.WriteString(c, "GET /bc HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	br := bufio.NewReader(c)
	h, err := ReadHead(br)
	if err != nil {
		t.Fatal(err)
	}
	if h.BodyFraming != FrameChunked {
		t.Fatalf("expected chunked downstream framing, got %v", h.BodyFraming)
	}
	if _, err := io.ReadAll(NewChunkedReader(br, 0)); err == nil {
		t.Fatal("expected chunk framing error propagated as closed transport")
	}
	waitEventsKind(j, EvIncomplete, time.Second)
}

func TestE2E_DownstreamCancelMidBody(t *testing.T) {
	up := newFakeUpstream(t, echoResponder)
	defer up.close()
	j := &chanJournal{ch: make(chan Event, 16)}
	srv, _ := NewServer(Config{Upstream: up.ln.Addr().String(), IdleTimeout: 5 * time.Second, Journal: j})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	c, _ := net.Dial("tcp", ln.Addr().String())

	io.WriteString(c, "POST /cancel HTTP/1.1\r\nHost: x\r\nContent-Length: 20000\r\n\r\n")
	rng := rand.New(rand.NewSource(1))
	buf := make([]byte, 3000)
	rng.Read(buf)
	sent := 0
	for sent < len(buf) {
		n := 1 + rng.Intn(200)
		if sent+n > len(buf) {
			n = len(buf) - sent
		}
		c.Write(buf[sent : sent+n])
		sent += n
	}
	// Abrupt client abort (RST-ish full close, not half close) while most of
	// the declared 20000-byte body is still outstanding.
	c.Close()

	select {
	case <-up.anyClose:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream connection was not closed after downstream cancel")
	}
	evs := waitEventsKind(j, EvIncomplete, 3*time.Second)
	var n int64
	for _, ev := range evs {
		if ev.Target == "/cancel" && ev.Forwarded && ev.ForwardedBytes > 0 {
			n = ev.ForwardedBytes
		}
	}
	if n <= 0 || n >= 20000 {
		t.Fatalf("expected partial forwarded bytes recorded, got %d (%+v)", n, evs)
	}
}

func TestE2E_Expect100Continue(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)
	c := e.dial()
	defer c.Close()
	io.WriteString(c, "POST /exp HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
	br := bufio.NewReader(c)

	// Interim response must precede the body.
	h0, err := ReadHead(br)
	if err != nil || h0.StatusCode != 100 {
		t.Fatalf("expected 100 Continue, got %+v err=%v", h0, err)
	}
	c.Write([]byte("hello"))
	h, body := readOneResponse(t, br)
	if h.StatusCode != 200 || string(body) != "echo:hello" {
		t.Fatalf("expect-continue exchange failed: %d %q", h.StatusCode, body)
	}
	up := e.up.snapshot()
	if _, ok := up[0].header("Expect"); ok {
		t.Fatal("Expect header must be stripped before forwarding")
	}
}

func TestE2E_UpstreamCloseDelimited(t *testing.T) {
	up := newFakeUpstream(t, func(seq int, req capturedReq) respPlan {
		return respPlan{
			head: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
			body: []byte("until-eof-body"),
			mode: "close",
		}
	})
	defer up.close()
	j := &chanJournal{ch: make(chan Event, 16)}
	srv, _ := NewServer(Config{Upstream: up.ln.Addr().String(), IdleTimeout: 5 * time.Second, Journal: j})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	io.WriteString(c, "GET /clo HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c)
	h, body := readOneResponse(t, br)
	if h.StatusCode != 200 || string(body) != "until-eof-body" {
		t.Fatalf("close-delimited response wrong: %d %q", h.StatusCode, body)
	}
	if v, _ := h.header("Connection"); !strings.Contains(strings.ToLower(v), "close") {
		t.Fatalf("downstream not told to close: %q", v)
	}
	// Transport must not be reusable: next read gives EOF.
	if n, _ := c.Read(make([]byte, 8)); n != 0 {
		t.Fatal("downstream connection was reused after close-delimited response")
	}
}

func TestE2E_ResponseChunkedDigest(t *testing.T) {
	body := bytes.Repeat([]byte("R"), 20000)
	up := newFakeUpstream(t, func(seq int, req capturedReq) respPlan {
		return respPlan{
			head: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			body: body,
			mode: "chunked",
		}
	})
	defer up.close()
	j := &chanJournal{ch: make(chan Event, 16)}
	srv, _ := NewServer(Config{Upstream: up.ln.Addr().String(), IdleTimeout: 5 * time.Second, Journal: j})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	io.WriteString(c, "GET /rc HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReaderSize(c, 4096)
	h, got := readOneResponse(t, br)
	if h.BodyFraming != FrameChunked || digest(got) != digest(body) {
		t.Fatalf("chunked response wrong: framing=%v len=%d", h.BodyFraming, len(got))
	}
}

func TestE2E_NoUpgradeNoConnect(t *testing.T) {
	e := setup(t, echoResponder, 5*time.Second)

	// An Upgrade offer is just a stripped hop header: the proxy answers as a
	// normal HTTP/1.1 request and must never switch protocols.
	c := e.dial()
	defer c.Close()
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n")
	br := bufio.NewReader(c)
	h, body := readOneResponse(t, br)
	if h.StatusCode != 200 || string(body) != "echo:" {
		t.Fatalf("upgrade offer mishandled: %d %q", h.StatusCode, body)
	}
	if v, _ := h.header("Upgrade"); v != "" {
		t.Fatal("proxy must not negotiate an upgrade")
	}
	up := e.up.snapshot()
	if _, ok := up[0].header("Upgrade"); ok {
		t.Fatal("Upgrade header leaked upstream")
	}
	// Raw bytes after the (answered) request stay on a normal HTTP connection:
	// another ordinary request still works.
	io.WriteString(c, "GET /after HTTP/1.1\r\nHost: t\r\n\r\n")
	_, body2 := readOneResponse(t, br)
	if string(body2) != "echo:" {
		t.Fatalf("post-upgrade-offer request failed: %q", body2)
	}
	c.Close()

	// CONNECT is a refused verb, not tunneled.
	c2 := e.dial()
	defer c2.Close()
	io.WriteString(c2, "CONNECT secret.example:443 HTTP/1.1\r\nHost: secret.example:443\r\n\r\n")
	h2, _ := readOneResponse(t, bufio.NewReader(c2))
	if h2.StatusCode != 501 {
		t.Fatalf("CONNECT status = %d, want 501", h2.StatusCode)
	}
	for _, r := range e.up.snapshot() {
		if strings.Contains(r.target, "secret.example") {
			t.Fatal("CONNECT target reached upstream")
		}
	}
}

// waitEventsKind collects events of a given kind.
func waitEventsKind(j *chanJournal, kind EventKind, timeout time.Duration) []Event {
	var out []Event
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-j.ch:
			if ev.Kind == kind {
				out = append(out, ev)
				return out
			}
		case <-deadline:
			return out
		}
	}
}

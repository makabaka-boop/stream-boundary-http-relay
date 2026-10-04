package httprelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 测试夹具
// ---------------------------------------------------------------------------

type fixture struct {
	t      *testing.T
	origin *testOrigin
	proxy  *Proxy
	ln     net.Listener
	cancel context.CancelFunc
}

func setup(t *testing.T) *fixture {
	t.Helper()
	origin, err := startTestOrigin()
	if err != nil {
		t.Fatalf("start origin: %v", err)
	}
	t.Cleanup(origin.close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy := New(origin.addr())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = proxy.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	return &fixture{t: t, origin: origin, proxy: proxy, ln: ln, cancel: cancel}
}

func (f *fixture) dial() net.Conn {
	f.t.Helper()
	c, err := net.Dial("tcp", f.ln.Addr().String())
	if err != nil {
		f.t.Fatalf("dial proxy: %v", err)
	}
	return c
}

// slowWriter 把报文按“随机分块 + 块间延迟”或“逐字节 + 延迟”送入。
type slowWriter struct {
	c        net.Conn
	rng      *rand.Rand
	byteWise bool
	delay    time.Duration
	maxChunk int // 0 时默认 1..7 字节
}

func (s *slowWriter) writeAll(data []byte) error {
	if s.byteWise {
		for _, b := range data {
			if _, err := s.c.Write([]byte{b}); err != nil {
				return err
			}
			if s.delay > 0 {
				time.Sleep(s.delay)
			}
		}
		return nil
	}
	for len(data) > 0 {
		max := s.maxChunk
		if max <= 0 {
			max = 7
		}
		n := s.rng.Intn(max) + 1 // 故意远小于缓冲
		if n > len(data) {
			n = len(data)
		}
		if _, err := s.c.Write(data[:n]); err != nil {
			return err
		}
		data = data[n:]
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 简易响应读取（测试客户端自用，不依赖 net/http）
// ---------------------------------------------------------------------------

type testResponse struct {
	status string
	code   int
	hdr    map[string]string
	hdrRaw []byte
	body   []byte
	closed bool
}

func readOneResponse(t *testing.T, br *bufio.Reader, assumeClose bool) testResponse {
	t.Helper()
	var hdrRaw bytes.Buffer
	line, err := readClientLine(br)
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	hdrRaw.Write(line)
	hdrRaw.WriteString("\r\n")
	parts := bytes.SplitN(line, []byte{' '}, 3)
	if len(parts) < 2 {
		t.Fatalf("bad status line %q", line)
	}
	code, _ := strconv.Atoi(string(parts[1]))
	resp := testResponse{status: string(line), code: code, hdr: map[string]string{}}
	for {
		h, herr := readClientLine(br)
		if herr != nil {
			t.Fatalf("read header: %v", herr)
		}
		hdrRaw.Write(h)
		hdrRaw.WriteString("\r\n")
		if len(h) == 0 {
			break
		}
		ci := bytes.IndexByte(h, ':')
		if ci < 0 {
			t.Fatalf("bad header %q", h)
		}
		k := strings.ToLower(string(bytes.TrimSpace(h[:ci])))
		v := string(bytes.TrimSpace(h[ci+1:]))
		resp.hdr[k] = v
	}
	resp.hdrRaw = hdrRaw.Bytes()

	if resp.hdr["transfer-encoding"] == "chunked" {
		body, derr := decodeClientChunked(br)
		if derr != nil {
			t.Fatalf("decode chunked: %v", derr)
		}
		resp.body = body
	} else if cl, ok := resp.hdr["content-length"]; ok {
		n, _ := strconv.Atoi(cl)
		resp.body = make([]byte, n)
		if _, err := io.ReadFull(br, resp.body); err != nil {
			t.Fatalf("read body of %d: %v", n, err)
		}
	} else if assumeClose || strings.EqualFold(resp.hdr["connection"], "close") {
		body, err := io.ReadAll(br)
		if err != nil {
			t.Fatalf("read close-delim body: %v", err)
		}
		resp.body = body
		resp.closed = true
	} else {
		resp.body = nil
	}
	return resp
}

func readClientLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		p, err := r.ReadSlice('\n')
		line = append(line, p...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, fmt.Errorf("bare LF in %q", line)
		}
		return line[:len(line)-2], nil
	}
}

func decodeClientChunked(r *bufio.Reader) ([]byte, error) {
	var body bytes.Buffer
	for {
		line, err := readClientLine(r)
		if err != nil {
			return nil, err
		}
		size := line
		if semi := bytes.IndexByte(line, ';'); semi >= 0 {
			size = line[:semi]
		}
		n, err := strconv.ParseUint(string(size), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("chunk size %q: %v", line, err)
		}
		if n == 0 {
			for {
				tl, terr := readClientLine(r)
				if terr != nil {
					return nil, terr
				}
				if len(tl) == 0 {
					return body.Bytes(), nil
				}
			}
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, err
		}
		body.Write(chunk)
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(r, crlf); err != nil {
			return nil, err
		}
	}
}

// readRespOrEOF 用于预期连接已被关闭的场景：尽量读响应头，遇 EOF 则标记。
func readRespOrClosed(t *testing.T, br *bufio.Reader) (testResponse, bool) {
	t.Helper()
	line, err := readClientLine(br)
	if err != nil {
		return testResponse{}, false
	}
	parts := bytes.SplitN(line, []byte{' '}, 3)
	resp := testResponse{status: string(line), hdr: map[string]string{}}
	if len(parts) >= 2 {
		resp.code, _ = strconv.Atoi(string(parts[1]))
	}
	for {
		h, herr := readClientLine(br)
		if herr != nil {
			return resp, true
		}
		if len(h) == 0 {
			break
		}
		ci := bytes.IndexByte(h, ':')
		if ci >= 0 {
			resp.hdr[strings.ToLower(string(bytes.TrimSpace(h[:ci])))] =
				string(bytes.TrimSpace(h[ci+1:]))
		}
	}
	if cl, ok := resp.hdr["content-length"]; ok {
		n, _ := strconv.Atoi(cl)
		resp.body = make([]byte, n)
		_, _ = io.ReadFull(br, resp.body)
	}
	return resp, true
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func chunkedBody(chunks ...[]byte) []byte {
	var b bytes.Buffer
	for _, c := range chunks {
		fmt.Fprintf(&b, "%x\r\n", len(c))
		b.Write(c)
		b.WriteString("\r\n")
	}
	b.WriteString("0\r\n\r\n")
	return b.Bytes()
}

func waitReqs(t *testing.T, f *fixture, n int) []upReq {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := f.origin.requests(); len(got) >= n {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	got := f.origin.requests()
	t.Fatalf("origin saw %d requests, want >= %d", len(got), n)
	return got
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

func TestGETBasic(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "GET /hello HTTP/1.1\r\nHost: example\r\n\r\n")

	br := bufio.NewReader(c)
	resp := readOneResponse(t, br, false)
	if resp.code != 200 {
		t.Fatalf("code=%d, want 200", resp.code)
	}
	if !strings.Contains(string(resp.body), `"path":"/hello"`) {
		t.Fatalf("unexpected body %s", resp.body)
	}
	reqs := waitReqs(t, f, 1)
	if reqs[0].method != "GET" || reqs[0].target != "/hello" {
		t.Fatalf("origin saw %+v", reqs[0])
	}
}

func TestPOSTContentLengthStreaming(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()

	// 正文略大于搬运缓冲，验证流式转发且边界正确。
	body := bytes.Repeat([]byte("ab7Z"), 5000) // 20000 字节 < 32KiB
	req := []byte(fmt.Sprintf("POST /post HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", len(body)))
	sw := &slowWriter{c: c, rng: rand.New(rand.NewSource(1)), delay: 300 * time.Microsecond, maxChunk: 64}
	if err := sw.writeAll(req); err != nil {
		t.Fatal(err)
	}
	if err := sw.writeAll(body); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(c)
	resp := readOneResponse(t, br, false)
	if resp.code != 200 {
		t.Fatalf("code=%d", resp.code)
	}
	reqs := waitReqs(t, f, 1)
	got := reqs[0]
	if got.cl != strconv.Itoa(len(body)) {
		t.Fatalf("upstream CL=%q want %d", got.cl, len(body))
	}
	if !bytes.Equal(got.body, body) || got.bodyHash != shaHex(body) {
		t.Fatalf("body mismatch: got hash %s want %s", got.bodyHash, shaHex(body))
	}
	// 转发后必须是“唯一”的长度编码。
	if got.te != "" {
		t.Fatalf("upstream should not see TE, got %q", got.te)
	}
	if strings.Contains(string(got.headerRx), "Content-Length:") {
		if n := bytes.Count(got.headerRx, []byte("Content-Length:")); n != 1 {
			t.Fatalf("upstream saw %d CL headers, want 1", n)
		}
	}
}

func TestPOSTChunkedBytewise(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()

	chunks := [][]byte{
		bytes.Repeat([]byte("1"), 3000),
		[]byte("hello chunk boundary"),
		bytes.Repeat([]byte{0x00, 0xff}, 4096),
	}
	var expect bytes.Buffer
	wire := []byte("POST /postchunk HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	wire = append(wire, chunkedBody(chunks...)...)
	for _, ch := range chunks {
		expect.Write(ch)
	}

	// 逐字节慢速送入，跨越所有块边界与 CRLF。
	sw := &slowWriter{c: c, byteWise: true, delay: 0}
	if err := sw.writeAll(wire); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(c)
	resp := readOneResponse(t, br, false)
	if resp.code != 200 {
		t.Fatalf("code=%d body=%s", resp.code, resp.body)
	}
	reqs := waitReqs(t, f, 1)
	got := reqs[0]
	// 源站看到的是代理重新生成的规范 chunked。
	if got.te != "chunked" {
		t.Fatalf("upstream TE=%q want chunked", got.te)
	}
	if got.cl != "" {
		t.Fatalf("upstream must not see CL in chunked request, got %q", got.cl)
	}
	if got.bodyHash != shaHex(expect.Bytes()) {
		t.Fatalf("hash mismatch got %s want %s", got.bodyHash, shaHex(expect.Bytes()))
	}
	// 上游收到的原始字节流必须是自洽的规范分帧：验证最后以 0 块结束。
	conns := f.origin.connBytes()
	if len(conns) != 1 || !bytes.HasSuffix(conns[0], []byte("0\r\n\r\n")) {
		t.Fatalf("upstream wire not terminated by last-chunk: %q…", tailOf(conns))
	}
}

func tailOf(conns [][]byte) string {
	if len(conns) == 0 {
		return ""
	}
	b := conns[len(conns)-1]
	if len(b) > 40 {
		b = b[len(b)-40:]
	}
	return string(b)
}

func TestPipeliningNoCrossStream(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()

	b1 := []byte("FIRST-BODY-")
	b2 := bytes.Repeat([]byte("Z"), 32768-5) // 恰好 32763 字节
	b3 := []byte("third")
	pipe := []byte(fmt.Sprintf(
		"POST /r1 HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s",
		len(b1), b1))
	pipe = append(pipe, []byte(fmt.Sprintf(
		"POST /r2 HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", len(b2)))...)
	pipe = append(pipe, b2...)
	pipe = append(pipe, []byte(fmt.Sprintf(
		"POST /r3 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n%s",
		chunkedBody(b3)))...)

	// 随机分块、跨请求边界送入。
	sw := &slowWriter{c: c, rng: rand.New(rand.NewSource(99)), delay: 0}
	if err := sw.writeAll(pipe); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(c)
	r1 := readOneResponse(t, br, false)
	r2 := readOneResponse(t, br, false)
	r3 := readOneResponse(t, br, false)
	for i, r := range []testResponse{r1, r2, r3} {
		if r.code != 200 {
			t.Fatalf("resp %d code=%d", i, r.code)
		}
	}

	reqs := waitReqs(t, f, 3)
	wantBodies := [][]byte{b1, b2, b3}
	wantTargets := []string{"/r1", "/r2", "/r3"}
	for i, want := range wantBodies {
		if reqs[i].target != wantTargets[i] {
			t.Fatalf("req %d target=%q", i, reqs[i].target)
		}
		if reqs[i].bodyHash != shaHex(want) {
			t.Fatalf("req %d body hash mismatch len=%d want=%d",
				i, len(reqs[i].body), len(want))
		}
	}
	// 三条流水线请求必须复用同一条上游 TCP 连接，且字节严格相邻无串入：
	// 源站记录的连接原始字节，按它自解析的三条消息切分后应与发送完全一致。
	conns := f.origin.connBytes()
	if len(conns) != 1 {
		t.Fatalf("upstream conns=%d, want 1 (pipeline must be serialized)", len(conns))
	}
	if !bytes.Contains(conns[0], []byte("POST /r1")) ||
		!bytes.Contains(conns[0], []byte("POST /r2")) ||
		!bytes.Contains(conns[0], []byte("POST /r3")) {
		t.Fatal("upstream wire missing requests")
	}
	// 关键反串流断言：r2 正文里不得混入 r1/r3 的标记字节序列。
	if bytes.Contains(reqs[1].body, []byte("FIRST")) ||
		bytes.Contains(reqs[1].body, []byte("third")) {
		t.Fatal("request boundaries crossed: r2 body contains other request bytes")
	}
	// 连接仍然可复用：再来一条应成功。
	fmt.Fprintf(c, "GET /after-pipe HTTP/1.1\r\nHost: x\r\n\r\n")
	r4 := readOneResponse(t, br, false)
	if r4.code != 200 {
		t.Fatalf("after pipeline code=%d", r4.code)
	}
}

func TestRejectDuplicateCL(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc")
	br := bufio.NewReader(c)
	resp, ok := readRespOrClosed(t, br)
	if ok && resp.code != 400 {
		t.Fatalf("code=%d want 400", resp.code)
	}
	// 连接必须被关闭。
	if err := assertClosed(br); err != nil {
		t.Fatalf("connection not closed after dup CL: %v", err)
	}
	if len(f.origin.requests()) != 0 {
		t.Fatal("origin must not see rejected request")
	}
}

func TestRejectCLAndChunked(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	br := bufio.NewReader(c)
	if resp, ok := readRespOrClosed(t, br); ok && resp.code != 400 {
		t.Fatalf("code=%d want 400", resp.code)
	}
	if err := assertClosed(br); err != nil {
		t.Fatalf("not closed: %v", err)
	}
	if len(f.origin.requests()) != 0 {
		t.Fatal("origin must not see rejected request")
	}
}

func TestRejectFoldedHeader(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "GET /x HTTP/1.1\r\nHost: x\r\nX-Long: part1\r\n folded\r\n\r\n")
	br := bufio.NewReader(c)
	if resp, ok := readRespOrClosed(t, br); ok && resp.code != 400 {
		t.Fatalf("code=%d want 400", resp.code)
	}
	if err := assertClosed(br); err != nil {
		t.Fatalf("not closed: %v", err)
	}
}

func TestRejectIllegalChunk(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	// 块大小写成非法十六进制。
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nx\r\n0\r\n\r\n")
	assertEventuallyClosed(t, c)

	// 流式转发下，chunked 请求的头部在正文解析前已经发出（不能整份缓冲），
	// 因此源站会看到一个未完成请求；但非法分块的任何数据字节都不得到达源站，
	// 且两端连接必须关闭。
	reqs := f.origin.requests()
	if len(reqs) > 1 {
		t.Fatalf("origin saw %d requests, want at most 1 partial", len(reqs))
	}
	if len(reqs) == 1 {
		if len(reqs[0].body) != 0 {
			t.Fatalf("malformed chunk data leaked upstream: %q", reqs[0].body)
		}
		for _, b := range f.origin.connBytes() {
			if bytes.Contains(b, []byte("ZZ")) {
				t.Fatal("illegal chunk-size bytes reached origin")
			}
		}
	}
	evs := f.proxy.IncompleteEvents()
	if len(evs) == 0 || evs[0].Phase != PhaseRequestBody {
		t.Fatalf("want request-body incomplete event, got %+v", evs)
	}
}

func TestRejectIllegalChunkPartial(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	// 第一个块合法（已转发），第二个块大小非法：属于已部分转发的未完成请求。
	wire := []byte("POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	wire = append(wire, []byte("4\r\nabcd\r\n")...)
	wire = append(wire, []byte("gg\r\n")...)
	sw := &slowWriter{c: c, rng: rand.New(rand.NewSource(7)), delay: 0}
	_ = sw.writeAll(wire)
	assertEventuallyClosed(t, c)

	reqs := waitReqs(t, f, 1)
	if reqs[0].bodyHash != shaHex([]byte("abcd")) {
		t.Fatalf("origin partial body=%x", reqs[0].body)
	}
	// 记录为未完成事件。
	evs := f.proxy.IncompleteEvents()
	if len(evs) == 0 || evs[0].Phase != PhaseRequestBody || evs[0].Forwarded == 0 {
		t.Fatalf("want incomplete request-body event with forwarded>0, got %+v", evs)
	}
}

func TestBodyTruncatedMidway(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	// 声明 100 字节，只发 40 就 FIN。
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n")
	c.Write(bytes.Repeat([]byte{'Q'}, 40))
	c.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(f.origin.requests()) >= 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	reqs := f.origin.requests()
	if len(reqs) != 1 {
		t.Fatalf("origin saw %d requests", len(reqs))
	}
	if !bytes.Equal(reqs[0].body, bytes.Repeat([]byte{'Q'}, 40)) {
		t.Fatal("origin must receive the 40 forwarded bytes")
	}
	evs := f.proxy.IncompleteEvents()
	found := false
	for _, ev := range evs {
		if ev.Phase == PhaseRequestBody && ev.Forwarded > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("want incomplete forwarded>0 event, got %+v", evs)
	}
}

func TestBodyTooLargeFixed(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 32769\r\n\r\n")
	br := bufio.NewReader(c)
	if resp, ok := readRespOrClosed(t, br); !ok || resp.code != 413 {
		t.Fatalf("resp=%+v ok=%v, want 413", resp, ok)
	}
	if len(f.origin.requests()) != 0 {
		t.Fatal("oversized request must not reach origin")
	}
}

func TestBodyTooLargeChunked(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	var wire bytes.Buffer
	wire.WriteString("POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	// 40000 字节，分多个块，总量超过 32KiB。
	rest := 40000
	for rest > 0 {
		n := 9000
		if n > rest {
			n = rest
		}
		fmt.Fprintf(&wire, "%x\r\n%s\r\n", n, bytes.Repeat([]byte{'L'}, n))
		rest -= n
	}
	wire.WriteString("0\r\n\r\n")
	sw := &slowWriter{c: c, rng: rand.New(rand.NewSource(3)), delay: 0}
	_ = sw.writeAll(wire.Bytes())
	assertEventuallyClosed(t, c)
	// 上游可能已收到部分正文，事件必须标记未完成（若有连接建立）。
	for _, ev := range f.proxy.IncompleteEvents() {
		if ev.Phase == PhaseRequestBody && !strings.Contains(ev.Err, "32KiB") {
			t.Fatalf("unexpected event err: %v", ev)
		}
	}
}

func TestHopByHopStripped(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	req := "POST /x HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Connection: X-Secret, close\r\n" +
		"X-Secret: nope\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Upgrade: h2c\r\n" +
		"Content-Length: 5\r\n\r\nhello"
	fmt.Fprint(c, req)
	br := bufio.NewReader(c)
	// 请求带 Connection: close，代理应在响应后关闭下游。
	resp := readOneResponse(t, br, true)
	if resp.code != 200 {
		t.Fatalf("code=%d", resp.code)
	}
	reqs := waitReqs(t, f, 1)
	hdr := strings.ToLower(string(reqs[0].headerRx))
	for _, banned := range []string{"x-secret", "keep-alive:", "proxy-connection", "upgrade:", "connection:"} {
		if strings.Contains(hdr, banned) {
			t.Fatalf("hop header leaked upstream: %q in %q", banned, hdr)
		}
	}
	// 但 Content-Length 必须保留且唯一。
	if strings.Count(hdr, "content-length:") != 1 {
		t.Fatalf("want exactly 1 CL upstream, got:\n%s", hdr)
	}
}

func TestResponseTruncatedFixed(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "GET /truncate-fixed HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c)

	// 头部在正文截断前已按上游声明转发（CL:100）。截断发生在正文阶段，
	// 代理无法撤回已发出的长度头，只能原样转发已得字节后关闭连接。
	line, err := readClientLine(br)
	if err != nil || !strings.HasPrefix(string(line), "HTTP/1.1 200") {
		t.Fatalf("status=%q err=%v", line, err)
	}
	for {
		h, herr := readClientLine(br)
		if herr != nil {
			t.Fatalf("header read: %v", herr)
		}
		if len(h) == 0 {
			break
		}
	}
	// 上游声明 100 字节却只发 30 字节就 FIN：下游读 30 字节后得到 EOF，
	// 且连接绝不能被复用。
	body, rerr := io.ReadAll(br)
	if rerr != nil {
		t.Fatalf("reading body: %v", rerr)
	}
	if !bytes.Equal(body, bytes.Repeat([]byte{'T'}, 30)) {
		t.Fatalf("body=%d bytes %q…", len(body), firstN(body, 12))
	}
	if err := assertClosed(br); err != nil {
		t.Fatalf("downstream must be closed: %v", err)
	}
	evs := f.proxy.IncompleteEvents()
	if len(evs) == 0 {
		t.Fatal("want incomplete event for truncated response")
	}
	last := evs[len(evs)-1]
	if last.Phase != PhaseResponseBody {
		t.Fatalf("phase=%s want response-body", last.Phase)
	}
}

func firstN(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func TestResponseTruncatedChunked(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "GET /truncate-chunked HTTP/1.1\r\nHost: x\r\n\r\n")
	assertEventuallyClosed(t, c)
	evs := f.proxy.IncompleteEvents()
	if len(evs) == 0 || evs[len(evs)-1].Phase != PhaseResponseBody {
		t.Fatalf("want response-body incomplete, got %+v", evs)
	}
}

func TestUpstreamMalformedHeadCloses(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "GET /badhead HTTP/1.1\r\nHost: x\r\n\r\n")
	assertEventuallyClosed(t, c)
	evs := f.proxy.IncompleteEvents()
	found := false
	for _, ev := range evs {
		if ev.Phase == PhaseResponseHeaders {
			found = true
		}
	}
	if !found {
		t.Fatalf("want response-headers event, got %+v", evs)
	}
}

func TestDownstreamCancellation(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "GET /slow-chunked HTTP/1.1\r\nHost: x\r\n\r\n")

	// 后台持续排空，确认响应已经开始流动；随后主动关闭（取消）。
	drained := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		var total int
		for {
			n, err := c.Read(buf)
			total += n
			if total >= 64*1024 {
				close(drained)
				return
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("never received enough streaming response to cancel")
	}
	_ = c.Close() // 下游取消

	// 代理写下游会失败，必须记录未完成事件并作废两端。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range f.proxy.IncompleteEvents() {
			if ev.Phase == PhaseResponseBody || ev.Phase == PhaseDownstreamWrite {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("want incomplete event after cancel, got %+v", f.proxy.IncompleteEvents())
}

func TestQueuedRequestNotForwardedAfterFailure(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()

	// 两条完整、合法的流水线请求。第一条的上游响应会被截断，
	// 第二条已（可能）进入代理的读缓冲，但绝不能被转发。
	pipe := []byte("GET /truncate-fixed HTTP/1.1\r\nHost: x\r\n\r\n")
	pipe = append(pipe, []byte("GET /second-queued HTTP/1.1\r\nHost: x\r\n\r\n")...)
	c.Write(pipe)

	br := bufio.NewReader(c)
	// 读到第一条的截断响应（30 字节后 EOF）。
	line, err := readClientLine(br)
	if err != nil || !strings.HasPrefix(string(line), "HTTP/1.1 200") {
		t.Fatalf("status=%q err=%v", line, err)
	}
	for {
		h, herr := readClientLine(br)
		if herr != nil {
			t.Fatalf("header: %v", herr)
		}
		if len(h) == 0 {
			break
		}
	}
	rest, _ := io.ReadAll(br)
	if len(rest) != 30 {
		t.Fatalf("first resp body=%d want 30", len(rest))
	}
	if err := assertClosed(br); err != nil {
		t.Fatalf("conn must close after truncation: %v", err)
	}

	// 源站必须只看到第一条请求。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(f.origin.requests()) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, r := range f.origin.requests() {
		if strings.Contains(r.target, "second") {
			t.Fatal("queued request was forwarded after failure!")
		}
	}
	if n := len(f.origin.requests()); n != 1 {
		t.Fatalf("origin saw %d requests, want exactly 1", n)
	}
	for _, b := range f.origin.connBytes() {
		if bytes.Contains(b, []byte("second-queued")) {
			t.Fatal("queued request bytes leaked onto upstream connection")
		}
	}
}

func TestCloseDelimitedResponse(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	body := []byte("close-delimited-body!!")
	fmt.Fprintf(c, "POST /close-delim HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", len(body))
	c.Write(body)
	br := bufio.NewReader(c)
	resp := readOneResponse(t, br, true)
	if resp.code != 200 || !bytes.Equal(resp.body, body) {
		t.Fatalf("code=%d body=%q want %q", resp.code, resp.body, body)
	}
	if err := assertClosed(br); err != nil {
		t.Fatalf("close-delim must close conn: %v", err)
	}
}

func TestSlowlorisHeaders(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	// 起始行与每个头部逐字节慢速送入（远大于一次 read 往返的颗粒度），
	// 验证代理按 CRLF 增量拼行而不会误判或越界解析正文。
	wire := []byte("POST /slow-headers HTTP/1.1\r\nHost: slow\r\nContent-Length: 11\r\n\r\nhello-world")
	sw := &slowWriter{c: c, byteWise: true, delay: 2 * time.Millisecond}
	if err := sw.writeAll(wire); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp := readOneResponse(t, br, false)
	if resp.code != 200 {
		t.Fatalf("code=%d", resp.code)
	}
	reqs := waitReqs(t, f, 1)
	if reqs[0].bodyHash != shaHex([]byte("hello-world")) {
		t.Fatalf("body=%q", reqs[0].body)
	}
}

func TestExpect100Continue(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	body := []byte("expect-body")
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n", len(body))
	br := bufio.NewReader(c)
	// 必须先收到 100。
	line, err := readClientLine(br)
	if err != nil || string(line) != "HTTP/1.1 100 Continue" {
		t.Fatalf("want 100 Continue, got %q err=%v", line, err)
	}
	// 吃掉 100 的空行。
	empty, err := readClientLine(br)
	if err != nil || len(empty) != 0 {
		t.Fatalf("want empty line after 100, got %q", empty)
	}
	c.Write(body)
	resp := readOneResponse(t, br, false)
	if resp.code != 200 {
		t.Fatalf("code=%d", resp.code)
	}
	reqs := waitReqs(t, f, 1)
	if reqs[0].bodyHash != shaHex(body) {
		t.Fatal("body mismatch after expect/continue")
	}
	if strings.Contains(strings.ToLower(string(reqs[0].headerRx)), "expect:") {
		t.Fatal("Expect must be stripped before forwarding")
	}
}

func TestContentLengthZeroMadeExplicit(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "POST /zero HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
	br := bufio.NewReader(c)
	if r := readOneResponse(t, br, false); r.code != 200 {
		t.Fatalf("code=%d", r.code)
	}
	reqs := waitReqs(t, f, 1)
	hdr := strings.ToLower(string(reqs[0].headerRx))
	if strings.Count(hdr, "content-length:") != 1 || !strings.Contains(hdr, "content-length: 0") {
		t.Fatalf("upstream must see exactly one CL:0, got:\n%s", hdr)
	}
}

func TestConfusingLengthsRejected(t *testing.T) {
	cases := []string{
		"Content-Length: +3",
		"Content-Length: 0x3",
		"Content-Length: 3, 3",
		"Content-Length : 3", // 冒号前空格：字段名非法
		"Content-Length: 3\nContent-Length:3",
	}
	for _, h := range cases {
		f := setup(t)
		c := f.dial()
		fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\n%s\r\n\r\nabc", h)
		br := bufio.NewReader(c)
		if resp, ok := readRespOrClosed(t, br); ok && resp.code != 400 {
			t.Fatalf("%q -> code=%d want 400", h, resp.code)
		}
		assertClosed(br)
		c.Close()
		if n := len(f.origin.requests()); n != 0 {
			t.Fatalf("%q: origin saw %d requests", h, n)
		}
	}
}

// TestLegalOWSAroundLength：值两侧的 OWS 是合法的，代理必须规范化后转发。
func TestLegalOWSAroundLength(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length:\t5 \r\n\r\nhello")
	br := bufio.NewReader(c)
	if r := readOneResponse(t, br, false); r.code != 200 {
		t.Fatalf("code=%d", r.code)
	}
	reqs := waitReqs(t, f, 1)
	if reqs[0].cl != "5" || reqs[0].bodyHash != shaHex([]byte("hello")) {
		t.Fatalf("normalized CL=%q body=%q", reqs[0].cl, reqs[0].body)
	}
	hdr := string(reqs[0].headerRx)
	if strings.Count(hdr, "Content-Length:") != 1 || !strings.Contains(hdr, "Content-Length: 5\r\n") {
		t.Fatalf("upstream must get canonical CL, got:\n%s", hdr)
	}
}

func TestMethodRestriction(t *testing.T) {
	f := setup(t)
	for _, m := range []string{"PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "get"} {
		c := f.dial()
		fmt.Fprintf(c, "%s /x HTTP/1.1\r\nHost: x\r\n\r\n", m)
		br := bufio.NewReader(c)
		if resp, ok := readRespOrClosed(t, br); ok && resp.code != 400 {
			t.Fatalf("method %s code=%d want 400", m, resp.code)
		}
		assertClosed(br)
		c.Close()
	}
	if len(f.origin.requests()) != 0 {
		t.Fatal("forbidden methods must not reach origin")
	}
}

func TestConnectionReuseAfterChunked(t *testing.T) {
	f := setup(t)
	c := f.dial()
	defer c.Close()
	br := bufio.NewReader(c)
	for i := 0; i < 3; i++ {
		body := []byte(fmt.Sprintf("body-%d-", i) + strings.Repeat("x", 100+i))
		req := []byte("POST /multi HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
		req = append(req, chunkedBody(body)...)
		c.Write(req)
		resp := readOneResponse(t, br, false)
		if resp.code != 200 {
			t.Fatalf("iter %d code=%d", i, resp.code)
		}
	}
	reqs := waitReqs(t, f, 3)
	for i := range reqs {
		want := []byte(fmt.Sprintf("body-%d-%s", i, strings.Repeat("x", 100+i)))
		if reqs[i].bodyHash != shaHex(want) {
			t.Fatalf("iter %d hash mismatch", i)
		}
	}
	conns := f.origin.connBytes()
	if len(conns) != 1 {
		t.Fatalf("chunked keep-alive opened %d upstream conns, want 1", len(conns))
	}
}

// ---------------------------------------------------------------------------
// 辅助断言
// ---------------------------------------------------------------------------

func assertClosed(br *bufio.Reader) error {
	buf := make([]byte, 16)
	// 排空缓冲后应当 EOF。
	done := make(chan error, 1)
	go func() {
		_, err := br.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			return fmt.Errorf("still readable")
		}
		return nil
	case <-time.After(3 * time.Second):
		return fmt.Errorf("connection not closed within timeout")
	}
}

func assertEventuallyClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, err := c.Read(buf)
		if err != nil {
			return
		}
	}
}

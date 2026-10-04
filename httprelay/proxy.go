// Package httprelay 实现一个仅支持 HTTP/1.1 GET、POST 的 TCP 反向代理。
//
// 设计要点：
//   - 起始行、CRLF 头部、Content-Length 与 chunked 分帧全部自行解析，
//     不依赖 net/http 的服务端解析（避免它代为宽容折叠头、重复长度等）。
//   - 每接受一条下游 TCP 连接就绑定一条独占的上游 TCP 连接；合法的流水线
//     请求严格按序转发。任何一端一旦出错（下游取消、半途断开、上游截断
//     响应等），两端连接立即作废关闭，排队请求一律不再转发。
//   - 请求正文以固定小缓冲流式搬运，绝不整份缓冲；单请求正文硬上限
//     32 KiB，超限即中止并记录未完成事件。
//   - 转发时剔除逐跳头与 Connection 点名头，且重新生成唯一、明确的长度
//     编码：Content-Length 与 Transfer-Encoding 至多出现一种，由代理
//     自己用规范数值/规范分块写出。
//   - 已经向上游写出部分字节后发生的中止记录为“未完成”，代理不会、也
//     无法承诺撤回源站可能已经产生的副作用。
package httprelay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MaxBody 是单请求正文的硬上限（字节），32 KiB。
	MaxBody = 32 * 1024
	// MaxHeaderBlock 限制单个消息的头部块大小（起始行+头部）。
	MaxHeaderBlock = 1 << 20
	// readChunk 是正文搬运使用的固定小缓冲，保证不整份缓冲正文。
	readChunk = 4096
	// idleTimeout 是两端在等待下一帧数据时的空闲超时。
	idleTimeout = 20 * time.Second
)

// frame 表示一条消息的正文分帧方式。
type frame int

const (
	frameNone    frame = iota // 无正文
	frameLength               // Content-Length: N
	frameChunked              // Transfer-Encoding: chunked
	frameClose                // 响应专用：读到对端关闭为止
)

// 解析阶段返回的哨兵错误，便于映射状态码与决定是否还能回错误响应。
var (
	errBadRequest   = errors.New("httprelay: malformed request")
	errBadResponse  = errors.New("httprelay: malformed upstream response")
	errHeaderTooBig = errors.New("httprelay: header block too large")
	errBodyTooLarge = errors.New("httprelay: request body exceeds 32KiB")
	errTruncated    = errors.New("httprelay: message body truncated")
	errBadChunk     = errors.New("httprelay: malformed chunk")
)

// field 保留头部字段的原始大小写与到达顺序。
type field struct {
	name  string
	value []byte
}

// msgHead 是请求/响应解析后的统一头部表示。
type msgHead struct {
	method     string
	target     string
	status     string // 响应状态行 "200 OK"
	statusCode int
	fields     []field
	contentLen int64 // -1 表示未声明
	chunked    bool
	wantClose  bool
	hosts      [][]byte
	hasExpect  bool
	expectBad  bool
	connTokens map[string]bool
}

func newHead() *msgHead {
	return &msgHead{contentLen: -1, connTokens: map[string]bool{}}
}

// ---------------------------------------------------------------------------
// 低层行/块读取
// ---------------------------------------------------------------------------

var lineBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 256); return &b },
}

// readLineCRLF 读取一条以 CRLF 结尾的行，返回不含 CRLF 的内容。
// 单独的 LF（或被裸 LF 折叠的头部）一律视为非法。
func readLineCRLF(r *bufio.Reader, headerBytes *int) ([]byte, error) {
	bp := lineBufPool.Get().(*[]byte)
	line := (*bp)[:0]
	defer func() { *bp = line; lineBufPool.Put(bp) }()

	for {
		p, err := r.ReadSlice('\n')
		*headerBytes += len(p)
		if *headerBytes > MaxHeaderBlock {
			return nil, errHeaderTooBig
		}
		line = append(line, p...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			// 读到 EOF 且缓冲里还有不带 CRLF 的残余字节，属于截断。
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, errBadRequest
		}
		out := make([]byte, len(line)-2)
		copy(out, line[:len(line)-2])
		return out, nil
	}
}

// readResponseLine 同上，但上游响应的畸形错误用 errBadResponse 标记。
func readResponseLine(r *bufio.Reader, headerBytes *int) ([]byte, error) {
	out, err := readLineCRLF(r, headerBytes)
	if errors.Is(err, errBadRequest) {
		return nil, errBadResponse
	}
	return out, err
}

// ---------------------------------------------------------------------------
// 头部解析
// ---------------------------------------------------------------------------

func isTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

func isOWS(c byte) bool { return c == ' ' || c == '\t' }

// trimOWS 去掉字段值两侧的空格/制表符。
func trimOWS(b []byte) []byte {
	for len(b) > 0 && isOWS(b[0]) {
		b = b[1:]
	}
	for len(b) > 0 && isOWS(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

func lowerEqual(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != s[i] {
			return false
		}
	}
	return true
}

func asciiToLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// parseFields 解析 CRLF 头部块（空行之后的部分已由调用方去掉）。
// 折叠头（首字节为空格/制表符）、畸形字段一律拒绝。
func (h *msgHead) parseFields(lines [][]byte) error {
	for _, raw := range lines {
		// 折叠头：RFC 7230 已废弃，本代理直接拒绝。
		if len(raw) > 0 && isOWS(raw[0]) {
			return errBadRequest
		}
		colon := bytes.IndexByte(raw, ':')
		if colon <= 0 {
			return errBadRequest
		}
		name := raw[:colon]
		for _, c := range name {
			if !isTokenByte(c) {
				return errBadRequest
			}
		}
		// 冒号前不允许空白（防止 "Content-Length : 3" 之类混淆）。
		// 冒号已在上面定位，name 中不可能有空白；值侧只做 OWS 裁剪。
		val := trimOWS(raw[colon+1:])
		v := make([]byte, len(val))
		copy(v, val)

		lname := strings.ToLower(string(name))
		switch lname {
		case "content-length":
			// 重复 Content-Length：即使数值相同也拒绝（拒绝解析歧义）。
			if h.contentLen != -1 {
				return errBadRequest
			}
			n, err := parseCL(v)
			if err != nil {
				return err
			}
			h.contentLen = n
		case "transfer-encoding":
			// 仅支持恰好为 "chunked"；重复 TE 头、TE 列表、其它编码全部拒绝。
			if h.chunked || !lowerEqual(v, "chunked") {
				return errBadRequest
			}
			h.chunked = true
		case "connection":
			for _, tok := range splitTokens(asciiToLower(v)) {
				if tok == "close" {
					h.wantClose = true
				} else if tok == "keep-alive" {
					// HTTP/1.1 默认 keep-alive，无需特殊处理。
				} else {
					h.connTokens[tok] = true
				}
			}
		case "host":
			h.hosts = append(h.hosts, v)
		case "expect":
			h.hasExpect = true
			if !lowerEqual(v, "100-continue") {
				h.expectBad = true
			}
		}
		h.fields = append(h.fields, field{name: string(name), value: v})
	}
	return nil
}

func splitTokens(b []byte) []string {
	var out []string
	for len(b) > 0 {
		for len(b) > 0 && (b[0] == ',' || b[0] == ' ' || b[0] == '\t') {
			b = b[1:]
		}
		i := 0
		for i < len(b) && b[i] != ',' {
			i++
		}
		tok := trimOWS(b[:i])
		if len(tok) > 0 {
			out = append(out, string(tok))
		}
		b = b[i:]
	}
	return out
}

// parseCL 严格解析十进制 Content-Length：只允许 1*DIGIT，拒绝前后空白、
// 加号、多个数字段等混淆写法。
func parseCL(v []byte) (int64, error) {
	if len(v) == 0 {
		return 0, errBadRequest
	}
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, errBadRequest
		}
		n = n*10 + int64(c-'0')
		if n > 1<<50 {
			return 0, errBadRequest
		}
	}
	return n, nil
}

// readRequestHead 从下游读取并解析一条请求的起始行与头部。
// 连接干净结束（无任何字节）返回 io.EOF；头部半截返回 io.ErrUnexpectedEOF。
func readRequestHead(r *bufio.Reader) (*msgHead, error) {
	used := 0
	start, err := readLineCRLF(r, &used)
	if err != nil {
		return nil, err
	}
	parts := bytes.Split(start, []byte{' '})
	if len(parts) != 3 {
		return nil, errBadRequest
	}
	method := string(parts[0])
	if method != "GET" && method != "POST" {
		return nil, errBadRequest
	}
	target := parts[1]
	// 仅支持 origin-form：必须以 "/" 开头且不得含空格（Split 已保证）。
	if len(target) == 0 || target[0] != '/' {
		return nil, errBadRequest
	}
	if string(parts[2]) != "HTTP/1.1" {
		return nil, errBadRequest
	}

	h := newHead()
	h.method = method
	h.target = string(target)
	var lines [][]byte
	for {
		line, err := readLineCRLF(r, &used)
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			break
		}
		lines = append(lines, line)
	}
	if err := h.parseFields(lines); err != nil {
		return nil, err
	}
	// 同时出现两种长度声明：直接拒绝（RFC 7230 3.3.3 的硬拒绝策略）。
	if h.chunked && h.contentLen != -1 {
		return nil, errBadRequest
	}
	// 定长正文超过 32 KiB：在触碰上游之前拒绝，绝不转发。
	// （chunked 的上限在解码过程中强制，因为总长度无法事先得知。）
	if h.contentLen > MaxBody {
		return nil, statusError{413, errBodyTooLarge}
	}
	// Host 必须唯一（HTTP/1.1 要求 Host；重复 Host 可能造成路由混淆）。
	if len(h.hosts) != 1 {
		return nil, errBadRequest
	}
	if h.expectBad {
		return nil, statusError{417, errBadRequest}
	}
	return h, nil
}

// readResponseHead 读取上游一条最终响应（自动跳过 1xx 中间响应）。
func readResponseHead(r *bufio.Reader) (*msgHead, error) {
	used := 0
	for interim := 0; ; interim++ {
		if interim > 10 {
			return nil, errBadResponse
		}
		start, err := readResponseLine(r, &used)
		if err != nil {
			return nil, err
		}
		h := newHead()
		var lines [][]byte
		for {
			line, err := readResponseLine(r, &used)
			if err != nil {
				return nil, err
			}
			if len(line) == 0 {
				break
			}
			lines = append(lines, line)
		}
		// 上游响应同样不接受折叠头、重复 CL、CL+chunked。
		if err := h.parseFieldsStrict(lines); err != nil {
			return nil, err
		}
		// 状态行：HTTP/1.1 SP 3位数字 SP 原因短语（原因短语可空）。
		sp1 := bytes.IndexByte(start, ' ')
		if sp1 < 0 || string(start[:sp1]) != "HTTP/1.1" {
			return nil, errBadResponse
		}
		rest := start[sp1+1:]
		sp2 := bytes.IndexByte(rest, ' ')
		var codeB, reason []byte
		if sp2 < 0 {
			codeB = rest
		} else {
			codeB = rest[:sp2]
			reason = rest[sp2+1:]
		}
		if len(codeB) != 3 {
			return nil, errBadResponse
		}
		code, err := strconv.Atoi(string(codeB))
		if err != nil || code < 100 || code > 599 {
			return nil, errBadResponse
		}
		h.statusCode = code
		if sp2 < 0 {
			h.status = string(codeB)
		} else {
			h.status = string(codeB) + " " + string(reason)
		}
		// 本代理不支持 Upgrade：101 意味着上游擅自更改协议，作废连接。
		if code == 101 {
			return nil, errBadResponse
		}
		if code >= 200 {
			return h, nil
		}
		// 其余 1xx 中间响应不允许带长度声明，其头部随状态行一起丢弃。
		if h.chunked || h.contentLen != -1 {
			return nil, errBadResponse
		}
		// 1xx：丢弃后继续读下一状态行（我们自己负责 100-continue）。
	}
}

// parseFieldsStrict 用于上游响应：任何头部畸形都映射为 errBadResponse。
func (h *msgHead) parseFieldsStrict(lines [][]byte) error {
	if err := h.parseFields(lines); err != nil {
		return errBadResponse
	}
	if h.chunked && h.contentLen != -1 {
		return errBadResponse
	}
	return nil
}

// requestFrame 决定请求正文分帧。
func (h *msgHead) requestFrame() frame {
	switch {
	case h.chunked:
		return frameChunked
	case h.contentLen >= 0:
		// 显式声明（含 Content-Length: 0）一律回写明确长度头。
		return frameLength
	default:
		// GET/POST 未声明长度：无正文，转发时也不生成长度头。
		return frameNone
	}
}

// statusError 携带可回送下游的 HTTP 状态码。
type statusError struct {
	code int
	err  error
}

func (e statusError) Error() string { return e.err.Error() }
func (e statusError) Unwrap() error { return e.err }

// ---------------------------------------------------------------------------
// chunked 解码（严格）
// ---------------------------------------------------------------------------

type chunkedReader struct {
	r            *bufio.Reader
	remaining    int64 // 当前块未读字节
	started      bool  // 是否已读到至少一个块头
	readTrailers bool  // 是否已读到结束块的尾部
	headerBytes  *int
	total        int64 // 已解码正文总字节（用于 32KiB 上限）
}

func newChunkedReader(r *bufio.Reader, headerBytes *int) *chunkedReader {
	return &chunkedReader{r: r, headerBytes: headerBytes}
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.readTrailers {
		return 0, io.EOF
	}
	if c.remaining == 0 {
		if err := c.nextChunk(); err != nil {
			return 0, err
		}
		if c.readTrailers {
			return 0, io.EOF
		}
	}
	n := int(c.remaining)
	if n > len(p) {
		n = len(p)
	}
	m, err := io.ReadFull(c.r, p[:n])
	c.remaining -= int64(m)
	c.total += int64(m)
	if c.total > MaxBody {
		return m, errBodyTooLarge
	}
	if err == io.ErrUnexpectedEOF {
		return m, errTruncated
	}
	if err == io.EOF && n == 0 {
		return 0, errTruncated
	}
	return m, err
}

func (c *chunkedReader) nextChunk() error {
	if c.started {
		// 上一块数据后必须紧跟 CRLF。
		line, err := readLineCRLF(c.r, c.headerBytes)
		if err != nil {
			return mapChunkLineErr(err)
		}
		if len(line) != 0 {
			return errBadChunk
		}
	}
	c.started = true
	line, err := readLineCRLF(c.r, c.headerBytes)
	if err != nil {
		return mapChunkLineErr(err)
	}
	size := line
	if semi := bytes.IndexByte(line, ';'); semi >= 0 {
		size = line[:semi] // chunk 扩展允许存在但被忽略
	}
	if len(size) == 0 {
		return errBadChunk
	}
	n, err := strconv.ParseUint(string(size), 16, 63)
	if err != nil {
		return errBadChunk
	}
	if n > MaxBody {
		// 单块声明就超过单请求上限，无需读其正文。
		return errBodyTooLarge
	}
	if n == 0 {
		return c.readTrailerSection()
	}
	c.remaining = int64(n)
	return nil
}

// readTrailerSection 读取并校验最后一个块之后的尾部块，遇到空行结束。
// 尾部不转发（重新生成分帧时丢弃），但其语法仍然必须合法。
func (c *chunkedReader) readTrailerSection() error {
	for {
		line, err := readLineCRLF(c.r, c.headerBytes)
		if err != nil {
			return mapChunkLineErr(err)
		}
		if len(line) == 0 {
			c.readTrailers = true
			return io.EOF
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return errBadChunk
		}
		for _, b := range line[:colon] {
			if !isTokenByte(b) {
				return errBadChunk
			}
		}
	}
}

func mapChunkLineErr(err error) error {
	if errors.Is(err, errHeaderTooBig) {
		return errBadChunk
	}
	if errors.Is(err, errBadRequest) {
		return errBadChunk
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errTruncated
	}
	return err
}

// ---------------------------------------------------------------------------
// chunked 编码（规范输出）
// ---------------------------------------------------------------------------

// chunkedWriter 把裸正文包装成规范的 chunked 分块并即时 flush，
// 保证大块正文不会在代理内存中堆积。
type chunkedWriter struct {
	w     *bufio.Writer
	flush bool
}

func (cw *chunkedWriter) WriteChunk(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(cw.w, "%x\r\n", len(p)); err != nil {
		return err
	}
	n, err := cw.w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	if _, err := cw.w.WriteString("\r\n"); err != nil {
		return err
	}
	if cw.flush {
		if err := cw.w.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (cw *chunkedWriter) closeChunked() error {
	if _, err := cw.w.WriteString("0\r\n\r\n"); err != nil {
		return err
	}
	return cw.w.Flush()
}

// ---------------------------------------------------------------------------
// 带空闲超时的连接
// ---------------------------------------------------------------------------

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}

// countingConn 统计写出的原始字节数（每次 Write 同步累加，无额外缓冲）。
type countingConn struct {
	net.Conn
	n *int64
}

func (c countingConn) Write(p []byte) (int, error) {
	m, err := c.Conn.Write(p)
	*c.n += int64(m)
	return m, err
}

// ---------------------------------------------------------------------------
// 未完成事件
// ---------------------------------------------------------------------------

// Phase 标识中止发生时正向搬运所处的阶段。
type Phase string

const (
	PhaseUpstreamConnect Phase = "upstream-connect"
	PhaseRequestHeaders  Phase = "request-headers"
	PhaseRequestBody     Phase = "request-body"
	PhaseResponseHeaders Phase = "response-headers"
	PhaseResponseBody    Phase = "response-body"
	PhaseDownstreamWrite Phase = "downstream-write"
)

// IncompleteEvent 记录一次“已经开始但没能完整结束”的转发。
// Forwarded > 0 表示源站已经收到部分请求字节——这部分副作用无法撤回。
type IncompleteEvent struct {
	Phase     Phase
	Method    string
	Target    string
	Forwarded int64 // 已转发给上游的请求字节（含头部的原始近似计数）
	Read      int64 // 已从下游读到的请求正文
	SentDown  int64 // 已发给下游的响应正文
	Err       string
	Time      time.Time
}

func digest(n int64) string {
	return strconv.FormatInt(n, 10)
}

func (e IncompleteEvent) String() string {
	return fmt.Sprintf("[incomplete %s %s %s forwarded=%s read=%s sent=%s err=%s]",
		e.Method, e.Target, e.Phase,
		digest(e.Forwarded), digest(e.Read), digest(e.SentDown), e.Err)
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

// Proxy 是固定上游地址的 TCP 反向代理。
type Proxy struct {
	upstream string
	listener net.Listener
	logger   *log.Logger

	mu     sync.Mutex
	closed bool
	events []IncompleteEvent
}

// New 创建指向上游 upstream（"host:port"）的代理。
func New(upstream string) *Proxy {
	return &Proxy{upstream: upstream}
}

// SetLogger 设置未完成事件的输出日志；不设置则只记录在内存里。
func (p *Proxy) SetLogger(l *log.Logger) {
	p.logger = l
}

// Serve 在 ln 上接受下游连接并阻塞服务，直到 ctx 取消或监听器关闭。
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	p.listener = ln
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go p.handle(c)
	}
}

// Addr 返回监听地址，Serve 之前可能为 nil。
func (p *Proxy) Addr() net.Addr {
	if p.listener == nil {
		return nil
	}
	return p.listener.Addr()
}

// Close 停止记录（监听器由 Serve 的 ctx 控制）。
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

// IncompleteEvents 返回未完成事件快照。
func (p *Proxy) IncompleteEvents() []IncompleteEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]IncompleteEvent, len(p.events))
	copy(out, p.events)
	return out
}

func (p *Proxy) record(ev IncompleteEvent) {
	ev.Time = time.Now()
	p.mu.Lock()
	p.events = append(p.events, ev)
	logger := p.logger
	p.mu.Unlock()
	// 已经转发过字节的未完成请求意味着源站副作用可能已发生，
	// 这类事件必须显眼地落日志。
	if logger != nil {
		logger.Print(ev.String())
	}
}

// hopByHop 是 RFC 7230 6.1 规定的逐跳头，转发时一律剔除。
var hopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"te":                  true,
	"transfer-encoding":   true, // 由代理重新生成
	"upgrade":             true,
	"trailer":             true,
	"proxy-authorization": true,
	"proxy-authenticate":  true,
}

func (p *Proxy) handle(downRaw net.Conn) {
	var downSentTotal int64 // 发给下游的全部响应字节
	idleDown := idleConn{Conn: downRaw, timeout: idleTimeout}
	down := countingConn{Conn: idleDown, n: &downSentTotal}
	downBR := bufio.NewReaderSize(down, 16*1024)
	downBW := bufio.NewWriterSize(down, 16*1024)

	defer down.Close()

	var upRaw net.Conn // 懒拨号；一旦建立即与本下游连接绑定
	var upBR *bufio.Reader
	var upBW *bufio.Writer
	var upReqWritten int64 // 写到上游的全部请求字节（起始行+头+正文）
	closeUp := func() {
		if upRaw != nil {
			_ = upRaw.Close()
			upRaw = nil
		}
	}
	defer closeUp()

	for {
		h, err := readRequestHead(downBR)
		if err != nil {
			// 干净的对端关闭（上一轮请求已完整处理）：安静退出。
			if errors.Is(err, io.EOF) {
				_ = downBW.Flush()
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_ = downBW.Flush()
				return
			}
			// 头部解析失败：还未触碰本次请求的上游转发，
			// 可以回一个错误响应，然后两端都必须关闭（流水线作废）。
			code := 400
			var se statusError
			if errors.As(err, &se) {
				code = se.code
			}
			if !errors.Is(err, errHeaderTooBig) {
				writeError(downBW, code)
			}
			_ = downBW.Flush()
			return
		}

		// 建立上游连接（失败回 502，且不记录副作用）。
		if upRaw == nil {
			c, derr := net.DialTimeout("tcp", p.upstream, 10*time.Second)
			if derr != nil {
				p.record(IncompleteEvent{
					Phase: PhaseUpstreamConnect, Method: h.method, Target: h.target, Err: derr.Error(),
				})
				writeError(downBW, 502)
				_ = downBW.Flush()
				return
			}
			idle := idleConn{Conn: c, timeout: idleTimeout}
			upRaw = countingConn{Conn: idle, n: &upReqWritten}
			upBR = bufio.NewReaderSize(upRaw, 16*1024)
			upBW = bufio.NewWriterSize(upRaw, 16*1024)
		}

		beforeReq := upReqWritten
		beforeResp := downSentTotal
		keepGoing, ferr := p.forward(downBR, downBW, upBR, upBW, upRaw, h)
		_ = downBW.Flush()
		if ferr != nil {
			ferr.ev.Forwarded = upReqWritten - beforeReq
			if ferr.ev.SentDown == 0 {
				ferr.ev.SentDown = downSentTotal - beforeResp
			}
			p.record(ferr.ev)
			// 两端连接都不得复用：关闭上游，并通过返回关闭下游。
			closeUp()
			return
		}
		if !keepGoing {
			closeUp()
			return
		}
	}
}

type forwardResult struct {
	ev IncompleteEvent
}

// writeError 回送一个最小的、带 Connection: close 的错误响应。
func writeError(w *bufio.Writer, code int) {
	body := fmt.Sprintf("%d error\n", code)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", code, httpStatus(code))
	fmt.Fprintf(w, "Content-Length: %d\r\n", len(body))
	w.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	w.WriteString("Connection: close\r\n\r\n")
	w.WriteString(body)
}

func httpStatus(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 413:
		return "Payload Too Large"
	case 417:
		return "Expectation Failed"
	case 502:
		return "Bad Gateway"
	default:
		return "Error"
	}
}

// writeFilteredHeaders 写出除逐跳头/Connection 点名头/显式跳过头之外的字段，
// 保留原始顺序与大小写。
func writeFilteredHeaders(w *bufio.Writer, h *msgHead, skip map[string]bool) error {
	for _, f := range h.fields {
		lname := strings.ToLower(f.name)
		if hopByHop[lname] || h.connTokens[lname] || skip[lname] {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s: %s\r\n", f.name, string(f.value)); err != nil {
			return err
		}
	}
	return nil
}

// forward 完整处理一次请求/响应交换。返回 keepGoing=false 表示连接必须终结。
func (p *Proxy) forward(
	downBR *bufio.Reader,
	downBW *bufio.Writer,
	upBR *bufio.Reader,
	upBW *bufio.Writer,
	upRaw net.Conn,
	h *msgHead,
) (bool, *forwardResult) {
	ev := IncompleteEvent{Method: h.method, Target: h.target}

	// ---- 向上游写请求起始行 ----
	fmt.Fprintf(upBW, "%s %s HTTP/1.1\r\n", h.method, h.target)

	// ---- 写过滤后的请求头 ----
	// 唯一、明确的长度编码在这里生成：原始 CL/TE 一律剔除，
	// 由代理自己恰好写出一种。Expect 由代理就地处理，也不转发。
	fr := h.requestFrame()
	reqSkip := map[string]bool{"content-length": true, "expect": true}
	if err := writeFilteredHeaders(upBW, h, reqSkip); err != nil {
		ev.Phase = PhaseRequestHeaders
		ev.Err = err.Error()
		return false, &forwardResult{ev}
	}
	switch fr {
	case frameLength:
		fmt.Fprintf(upBW, "Content-Length: %d\r\n", h.contentLen)
	case frameChunked:
		upBW.WriteString("Transfer-Encoding: chunked\r\n")
	}

	// Expect: 100-continue：由代理承担，先让下游放心发正文；
	// 上游侧不再携带 Expect。
	if h.hasExpect {
		downBW.WriteString("HTTP/1.1 100 Continue\r\n\r\n")
		if err := downBW.Flush(); err != nil {
			ev.Phase = PhaseDownstreamWrite
			ev.Err = err.Error()
			return false, &forwardResult{ev}
		}
	}
	upBW.WriteString("\r\n")
	if err := upBW.Flush(); err != nil {
		ev.Phase = PhaseRequestHeaders
		ev.Err = err.Error()
		return false, &forwardResult{ev}
	}

	buf := make([]byte, readChunk)

	// ---- 流式转发请求正文（不整份缓冲，32KiB 硬上限）----
	var bodyRead int64
	var bodyForwarded int64
	var reqBodyErr error

	flushEachChunk := fr == frameChunked // 分块请求逐块 flush，避免大正文堆积
	switch fr {
	case frameLength:
		bodyRead, bodyForwarded, reqBodyErr = pumpFixedRequest(downBR, upBW, h.contentLen, buf)
	case frameChunked:
		bodyRead, bodyForwarded, reqBodyErr = pumpChunkedRequest(downBR, upBW, buf, flushEachChunk)
	case frameNone:
		// 无正文。
	}
	ev.Read = bodyRead
	ev.Forwarded = bodyForwarded
	if reqBodyErr != nil {
		ev.Phase = PhaseRequestBody
		ev.Err = reqBodyErr.Error()
		// 此时上游可能已收到部分正文：记录未完成，不承诺撤回副作用。
		// 不再读取上游响应，直接终结两端。
		return false, &forwardResult{ev}
	}

	// ---- 读取上游响应头 ----
	rh, err := readResponseHead(upBR)
	if err != nil {
		ev.Phase = PhaseResponseHeaders
		ev.Err = err.Error()
		return false, &forwardResult{ev}
	}

	// ---- 决定上游响应正文分帧 ----
	respFrame := frameNone
	switch {
	case rh.chunked:
		respFrame = frameChunked
	case rh.contentLen >= 0:
		respFrame = frameLength
	case bodyAllowedForStatus(rh.statusCode) && methodAllowsResponseBody(h.method):
		// 无长度声明：读到上游关闭为止，两条连接都不能复用。
		respFrame = frameClose
	}

	// 上游是否可复用：显式 close、close 定界、或上游头部畸形时都不可复用。
	upReusable := !rh.wantClose && respFrame != frameClose
	downClose := rh.wantClose || h.wantClose || respFrame == frameClose

	// ---- 写下游响应行与过滤后的响应头 ----
	fmt.Fprintf(downBW, "HTTP/1.1 %s\r\n", rh.status)
	// 原始长度头剔除，由代理重新生成唯一、明确的长度编码。
	respSkip := map[string]bool{"content-length": true}
	if err := writeFilteredHeaders(downBW, rh, respSkip); err != nil {
		ev.Phase = PhaseDownstreamWrite
		ev.Err = err.Error()
		return false, &forwardResult{ev}
	}
	switch respFrame {
	case frameLength:
		fmt.Fprintf(downBW, "Content-Length: %d\r\n", rh.contentLen)
		downBW.WriteString("Connection: keep-alive\r\n")
	case frameChunked:
		downBW.WriteString("Transfer-Encoding: chunked\r\n")
		downBW.WriteString("Connection: keep-alive\r\n")
	case frameClose:
		// close 定界：不带长度头，靠连接结束界定正文。
		downBW.WriteString("Connection: close\r\n")
	case frameNone:
		downBW.WriteString("Content-Length: 0\r\n")
		if downClose {
			downBW.WriteString("Connection: close\r\n")
		} else {
			downBW.WriteString("Connection: keep-alive\r\n")
		}
	}
	downBW.WriteString("\r\n")
	if err := downBW.Flush(); err != nil {
		ev.Phase = PhaseDownstreamWrite
		ev.Err = err.Error()
		return false, &forwardResult{ev}
	}

	// ---- 流式转发响应正文 ----
	var sent int64
	var respErr error
	switch respFrame {
	case frameLength:
		sent, respErr = pumpFixedResponse(upBR, downBW, rh.contentLen, buf)
	case frameChunked:
		sent, respErr = pumpChunkedResponse(upBR, downBW, buf)
	case frameClose:
		sent, respErr = pumpUntilClose(upBR, downBW, buf)
	case frameNone:
	}
	ev.SentDown = sent
	if respErr != nil {
		// 上游响应截断 / 下游取消：两端作废，排队请求不再发送。
		if isDownstreamWriteErr(respErr) {
			ev.Phase = PhaseDownstreamWrite
		} else {
			ev.Phase = PhaseResponseBody
		}
		ev.Err = respErr.Error()
		return false, &forwardResult{ev}
	}

	// 正常结束一条交换：是否继续处理流水线中的下一条请求，
	// 取决于两端是否都还可复用。
	return upReusable && !downClose, nil
}

func isDownstreamWriteErr(err error) bool {
	// 写下游失败由 pump* 中包装成 errDownstreamWrite。
	return errors.Is(err, errDownstreamWrite)
}

var errDownstreamWrite = errors.New("httprelay: downstream write failed")

func bodyAllowedForStatus(code int) bool {
	return code >= 200 && code != 204 && code != 304
}

func methodAllowsResponseBody(method string) bool {
	// 所有方法的响应都可能带正文（HEAD 本代理不支持，可忽略）。
	return true
}

// ---------------------------------------------------------------------------
// 正文搬运
// ---------------------------------------------------------------------------

var errUpstreamTruncated = errors.New("httprelay: upstream response truncated")

// pumpFixedRequest 从下游搬运恰好 remaining 字节的定长请求正文到上游。
// 返回：已读下游字节、已转发上游字节、错误。固定缓冲，无整份缓冲。
func pumpFixedRequest(r *bufio.Reader, w *bufio.Writer, remaining int64, buf []byte) (int64, int64, error) {
	var read, sent int64
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		m, err := io.ReadFull(r, buf[:n])
		read += int64(m)
		if m > 0 {
			if werr := writeAndFlush(w, buf[:m]); werr != nil {
				return read, sent, werr
			}
			sent += int64(m)
		}
		remaining -= int64(m)
		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				return read, sent, errTruncated
			}
			return read, sent, err
		}
	}
	return read, sent, nil
}

// writeAndFlush 写出 p 并立即 flush，确保正文不滞留在代理缓冲中。
func writeAndFlush(w *bufio.Writer, p []byte) error {
	if _, err := w.Write(p); err != nil {
		return err
	}
	return w.Flush()
}

// pumpChunkedRequest 解码下游 chunked 正文，以 32KiB 为上限，
// 重新编码成规范 chunked 发往上游。
func pumpChunkedRequest(r *bufio.Reader, w *bufio.Writer, buf []byte, flush bool) (int64, int64, error) {
	hdrCount := new(int)
	cr := newChunkedReader(r, hdrCount)
	cw := &chunkedWriter{w: w, flush: flush}
	var read, sent int64
	for {
		n, err := cr.Read(buf)
		if n > 0 {
			read += int64(n)
			if werr := cw.WriteChunk(buf[:n]); werr != nil {
				return read, sent, werr
			}
			sent += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return read, sent, err
		}
	}
	if err := cw.closeChunked(); err != nil {
		return read, sent, err
	}
	return read, sent, nil
}

// pumpFixedResponse 搬运定长响应正文。
func pumpFixedResponse(r *bufio.Reader, w *bufio.Writer, remaining int64, buf []byte) (int64, error) {
	var sent int64
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		m, err := io.ReadFull(r, buf[:n])
		if m > 0 {
			if werr := writeAndFlush(w, buf[:m]); werr != nil {
				return sent, fmt.Errorf("%w: %v", errDownstreamWrite, werr)
			}
			sent += int64(m)
		}
		remaining -= int64(m)
		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				return sent, errUpstreamTruncated
			}
			return sent, err
		}
	}
	return sent, nil
}

// pumpChunkedResponse 解码上游 chunked 响应并重新规范编码发给下游。
// 响应正文不设 32KiB 上限（上限只约束单请求正文）。
func pumpChunkedResponse(r *bufio.Reader, w *bufio.Writer, buf []byte) (int64, error) {
	hdrCount := new(int)
	cr := newChunkedResponseReader(r, hdrCount)
	cw := &chunkedWriter{w: w, flush: true}
	var sent int64
	for {
		n, err := cr.Read(buf)
		if n > 0 {
			if werr := cw.WriteChunk(buf[:n]); werr != nil {
				return sent, fmt.Errorf("%w: %v", errDownstreamWrite, werr)
			}
			sent += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, errBadChunk) || errors.Is(err, errTruncated) {
				return sent, errUpstreamTruncated
			}
			return sent, err
		}
	}
	if err := cw.closeChunked(); err != nil {
		return sent, fmt.Errorf("%w: %v", errDownstreamWrite, err)
	}
	return sent, nil
}

// pumpUntilClose 搬运无长度声明、靠关闭定界的响应正文直到上游 EOF。
func pumpUntilClose(r *bufio.Reader, w *bufio.Writer, buf []byte) (int64, error) {
	var sent int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := writeAndFlush(w, buf[:n]); werr != nil {
				return sent, fmt.Errorf("%w: %v", errDownstreamWrite, werr)
			}
			sent += int64(n)
		}
		if err == io.EOF {
			return sent, nil
		}
		if err != nil {
			return sent, err
		}
	}
}

// chunkedResponseReader 与 chunkedReader 相同解码逻辑，但不施加 32KiB 上限。
type chunkedResponseReader struct {
	r           *bufio.Reader
	remaining   int64
	started     bool
	done        bool
	headerBytes *int
}

func newChunkedResponseReader(r *bufio.Reader, hb *int) *chunkedResponseReader {
	return &chunkedResponseReader{r: r, headerBytes: hb}
}

func (c *chunkedResponseReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.remaining == 0 {
		if err := c.nextChunk(); err != nil {
			return 0, err
		}
		if c.done {
			return 0, io.EOF
		}
	}
	n := int(c.remaining)
	if n > len(p) {
		n = len(p)
	}
	m, err := io.ReadFull(c.r, p[:n])
	c.remaining -= int64(m)
	if err == io.ErrUnexpectedEOF {
		return m, errTruncated
	}
	return m, err
}

func (c *chunkedResponseReader) nextChunk() error {
	if c.started {
		line, err := readResponseLine(c.r, c.headerBytes)
		if err != nil {
			return mapRespChunkErr(err)
		}
		if len(line) != 0 {
			return errBadChunk
		}
	}
	c.started = true
	line, err := readResponseLine(c.r, c.headerBytes)
	if err != nil {
		return mapRespChunkErr(err)
	}
	size := line
	if semi := bytes.IndexByte(line, ';'); semi >= 0 {
		size = line[:semi]
	}
	if len(size) == 0 {
		return errBadChunk
	}
	n, err := strconv.ParseUint(string(size), 16, 64)
	if err != nil {
		return errBadChunk
	}
	if n == 0 {
		for {
			line, err := readResponseLine(c.r, c.headerBytes)
			if err != nil {
				return mapRespChunkErr(err)
			}
			if len(line) == 0 {
				c.done = true
				return io.EOF
			}
			colon := bytes.IndexByte(line, ':')
			if colon <= 0 {
				return errBadChunk
			}
		}
	}
	c.remaining = int64(n)
	return nil
}

func mapRespChunkErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, errBadResponse) || errors.Is(err, errHeaderTooBig) {
		return errTruncated
	}
	return err
}

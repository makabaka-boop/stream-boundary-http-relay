package httprelay

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// upReq 是测试源站记录下的一条“实际收到”的请求。
type upReq struct {
	raw      []byte // 源站在该连接上收到的完整字节流切片（头+体，按连接切分）
	wire     []byte // 记录该请求时刻，连接上累计收到的原始字节快照
	method   string
	target   string
	cl       string // 源站看到的 Content-Length（可能重复）
	te       string
	conn     string
	body     []byte // 源站按自解析分帧读出的正文
	bodyHash string
	trailer  string
	headerRx []byte // 仅头部块（含末尾 CRLFCRLF）
	partial  bool   // 正文未读完整连接就断了
}

// testOrigin 是一个真实 TCP 源站：自行用本代理同款严格逻辑解析，
// 这样可以逐字节核对“源站实际收到了什么”。
type testOrigin struct {
	ln net.Listener

	mu      sync.Mutex
	reqs    []upReq
	conns   [][]byte // 每条 TCP 连接上收到的原始字节（用于核对请求边界）
	closed_ bool
}

func startTestOrigin() (*testOrigin, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	o := &testOrigin{ln: ln}
	go o.serve()
	return o, nil
}

func (o *testOrigin) addr() string { return o.ln.Addr().String() }

func (o *testOrigin) close() {
	o.mu.Lock()
	o.closed_ = true
	o.mu.Unlock()
	_ = o.ln.Close()
}

func (o *testOrigin) requests() []upReq {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]upReq, len(o.reqs))
	copy(out, o.reqs)
	return out
}

func (o *testOrigin) connBytes() [][]byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([][]byte, len(o.conns))
	copy(out, o.conns)
	return out
}

func (o *testOrigin) serve() {
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		go o.handle(c)
	}
}

// readCappedLine 源站自用：读一行 CRLF（同样拒绝裸 LF）。
func readCappedLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		p, err := r.ReadSlice('\n')
		line = append(line, p...)
		if len(line) > 1<<20 {
			return nil, fmt.Errorf("line too long")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, fmt.Errorf("bare LF")
		}
		return line[:len(line)-2], nil
	}
}

func (o *testOrigin) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReaderSize(c, 8192)
	var raw bytes.Buffer

	// 预先注册该连接的字节槽位，连接存活期间也能查看已收字节。
	o.mu.Lock()
	idx := len(o.conns)
	o.conns = append(o.conns, nil)
	o.mu.Unlock()
	snapshot := func() {
		cp := append([]byte{}, raw.Bytes()...)
		o.mu.Lock()
		o.conns[idx] = cp
		o.mu.Unlock()
	}
	defer snapshot()

	for {
		start, err := readCappedLine(r)
		if err != nil {
			break
		}
		req := upReq{}
		headBlock := append([]byte{}, start...)
		headBlock = append(headBlock, '\r', '\n')
		parts := bytes.Split(start, []byte{' '})
		if len(parts) == 3 {
			req.method = string(parts[0])
			req.target = string(parts[1])
		}

		var lines [][]byte
		for {
			line, lerr := readCappedLine(r)
			if lerr != nil {
				snapshot()
				return
			}
			headBlock = append(headBlock, line...)
			headBlock = append(headBlock, '\r', '\n')
			if len(line) == 0 {
				break
			}
			lines = append(lines, line)
		}
		req.headerRx = append([]byte{}, headBlock...)
		raw.Write(headBlock)

		var contentLengths [][]byte
		var tes [][]byte
		var conns [][]byte
		var trailers [][]byte
		for _, ln := range lines {
			ci := bytes.IndexByte(ln, ':')
			if ci <= 0 {
				continue
			}
			name := bytes.ToLower(bytes.TrimSpace(ln[:ci]))
			val := bytes.TrimSpace(ln[ci+1:])
			switch string(name) {
			case "content-length":
				contentLengths = append(contentLengths, val)
			case "transfer-encoding":
				tes = append(tes, val)
			case "connection":
				conns = append(conns, val)
			case "trailer":
				trailers = append(trailers, val)
			}
		}
		req.cl = joinComma(contentLengths)
		req.te = joinComma(tes)
		req.conn = joinComma(conns)
		req.trailer = joinComma(trailers)

		// 解析正文：优先 chunked；否则按唯一 CL。
		chunked := len(tes) > 0 && bytes.Equal(bytes.ToLower(tes[len(tes)-1]), []byte("chunked"))
		if chunked {
			body, terr := readOriginChunked(r, &raw)
			if terr != nil {
				// 出错也保留已解码出的正文（部分转发）。
				req.body = body
				req.partial = true
				sum := sha256.Sum256(req.body)
				req.bodyHash = hex.EncodeToString(sum[:])
				o.record(req, raw.Bytes())
				snapshot()
				return
			}
			req.body = body
		} else if len(contentLengths) > 0 {
			n, perr := strconv.ParseInt(string(contentLengths[0]), 10, 64)
			if perr != nil {
				o.record(req, raw.Bytes())
				snapshot()
				return
			}
			body := make([]byte, n)
			m, rerr := io.ReadFull(r, body)
			raw.Write(body[:m])
			req.body = body[:m]
			if rerr != nil {
				// 截断：记录实际收到的字节，标记 partial，连接随之结束。
				req.partial = true
				sum := sha256.Sum256(req.body)
				req.bodyHash = hex.EncodeToString(sum[:])
				o.record(req, raw.Bytes())
				snapshot()
				return
			}
		}
		sum := sha256.Sum256(req.body)
		req.bodyHash = hex.EncodeToString(sum[:])
		o.record(req, raw.Bytes())
		snapshot()

		if !o.respond(c, req) {
			snapshot()
			return
		}
	}
	snapshot()
}

func joinComma(vals [][]byte) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = string(v)
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// readOriginChunked 解码 chunked，把所有读到的原始字节同步记入 raw，
// 用于核对请求边界是否串字节。
func readOriginChunked(r *bufio.Reader, raw *bytes.Buffer) ([]byte, error) {
	var body bytes.Buffer
	for {
		line, err := readCappedLine(r)
		if err != nil {
			// 连接在此处结束：保留此前已完整解码的块正文。
			return body.Bytes(), err
		}
		raw.Write(line)
		raw.WriteString("\r\n")
		size := line
		if semi := bytes.IndexByte(line, ';'); semi >= 0 {
			size = line[:semi]
		}
		n, perr := strconv.ParseUint(string(size), 16, 64)
		if perr != nil {
			return nil, perr
		}
		if n == 0 {
			for {
				tl, terr := readCappedLine(r)
				raw.Write(tl)
				raw.WriteString("\r\n")
				if terr != nil {
					return nil, terr
				}
				if len(tl) == 0 {
					return body.Bytes(), nil
				}
			}
		}
		chunk := make([]byte, n)
		if _, rerr := io.ReadFull(r, chunk); rerr != nil {
			body.Write(chunk)
			raw.Write(chunk)
			return body.Bytes(), rerr
		}
		body.Write(chunk)
		raw.Write(chunk)
		crlf := make([]byte, 2)
		if _, rerr := io.ReadFull(r, crlf); rerr != nil {
			return body.Bytes(), rerr
		}
		raw.Write(crlf)
	}
}

func (o *testOrigin) record(req upReq, wire []byte) {
	req.wire = append([]byte{}, wire...)
	o.mu.Lock()
	o.reqs = append(o.reqs, req)
	o.mu.Unlock()
}

// respond 按路径决定响应行为。返回 false 表示随后关闭连接。
func (o *testOrigin) respond(c net.Conn, req upReq) bool {
	w := bufio.NewWriter(c)
	switch {
	case req.target == "/close-delim":
		// 无长度声明 + Connection: close：正文靠关闭定界。
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nConnection: close\r\nX-Echo-Content-Length: %d\r\n\r\n", len(req.body))
		w.Write(req.body)
		w.Flush()
		return false

	case req.target == "/truncate-fixed":
		// 声明 100 字节只发 30 即关闭：截断的定长响应。
		w.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
		w.Write(bytes.Repeat([]byte{'T'}, 30))
		w.Flush()
		return false

	case req.target == "/truncate-chunked":
		// chunked 响应中途截断（块数据不满、无 CRLF 直接关闭）。
		w.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
		w.WriteString("10\r\n")
		w.Write(bytes.Repeat([]byte{'C'}, 16))
		w.WriteString("\r\n")
		w.WriteString("20\r\n")
		w.Write(bytes.Repeat([]byte{'D'}, 10)) // 声明 32 字节只发 10
		w.Flush()
		return false

	case req.target == "/slow-chunked":
		// 持续慢速分块，直到对端关闭或达到上限，用于驱动下游取消场景。
		w.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
		w.Flush()
		payload := bytes.Repeat([]byte{'S'}, 4096)
		for i := 0; i < 5000; i++ {
			fmt.Fprintf(w, "1000\r\n")
			if _, err := w.Write(payload); err != nil {
				return false
			}
			w.WriteString("\r\n")
			if err := w.Flush(); err != nil {
				return false
			}
			time.Sleep(time.Millisecond)
		}
		w.WriteString("0\r\n\r\n")
		w.Flush()
		return true

	case req.target == "/no-response":
		// 读取请求后直接关闭，不回任何响应。
		w.Flush()
		return false

	case req.target == "/badhead":
		// 非法响应头（重复 Content-Length）。
		w.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabc")
		w.Flush()
		return false

	default:
		// 普通回显：以 chunked 回送一段 JSON，逐跳头不回显。
		echo := fmt.Sprintf(`{"method":%q,"path":%q,"len":%d,"sha256":%q,"te":%q}`,
			req.method, req.target, len(req.body), req.bodyHash, req.te)
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-SHA256: %s\r\nX-Echo-Length: %d\r\n\r\n",
			len(echo), req.bodyHash, len(req.body))
		w.WriteString(echo)
		w.Flush()
		return true
	}
}

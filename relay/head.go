package relay

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// MaxBody is the hard cap on any single de-framed request body.
const MaxBody = 32 * 1024

const (
	maxStartLine = 8 * 1024
	maxHeadBlock = 64 * 1024
)

// ProtoError marks a message that violates the supported wire grammar.
// Such a message is rejected and its transport is never reused.
type ProtoError struct{ Msg string }

func (e *ProtoError) Error() string { return "http protocol error: " + e.Msg }

func protof(format string, args ...any) error {
	return &ProtoError{Msg: fmt.Sprintf(format, args...)}
}

// Framing selects how the message body is framed on the wire.
type Framing int

const (
	FrameNone Framing = iota
	FrameLength
	FrameChunked
	FrameClose // response body delimited by connection close
)

// Header is one raw field. Names are preserved as received; comparisons are
// done case-insensitively. Values have only OWS around them removed.
type Header struct {
	Name  string
	Value string
}

// Head is a parsed request or response start line plus header block.
type Head struct {
	IsRequest bool

	// request
	Method string
	Target string

	// response
	StatusCode int
	Reason     string

	Headers []Header

	ContentLength int64
	HasLength     bool
	BodyFraming   Framing
	WantsClose    bool
	Expect100     bool
}

// readCRLFLine reads a single logical line terminated by CRLF. It never strips
// anything else: a bare LF, leading whitespace folding, or embedded CR is the
// caller's problem to reject. Accumulates across bufio buffer refills without
// trusting ReadSlice fragments on their own.
func readCRLFLine(br *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			if len(line)+len(frag) > limit {
				return nil, protof("header line too long")
			}
			line = append(line, frag...)
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(frag) < 2 || frag[len(frag)-2] != '\r' {
			return nil, protof("bare LF or missing CR before LF")
		}
		line = append(line, frag[:len(frag)-2]...)
		if len(line) > limit {
			return nil, protof("header line too long")
		}
		return line, nil
	}
}

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

// validFieldValue permits VCHAR / SP / HTAB / obs-text; no other controls.
func validFieldValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' || c == ' ' {
			continue
		}
		if c < 0x21 || (c > 0x7e && c < 0x80) {
			return false
		}
	}
	return true
}

func trimOWS(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func parseContentLength(raw string) (int64, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0, protof("empty content-length")
	}
	// RFC 9112: one canonical decimal value, no comma lists, no whitespace
	// between digits, and no leading zeros (a common request-smuggling form).
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, protof("invalid content-length %q", raw)
		}
	}
	if len(v) > 1 && v[0] == '0' {
		return 0, protof("non-canonical content-length %q", raw)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, protof("invalid content-length %q", raw)
	}
	return n, nil
}

// ReadHead parses one HTTP/1.1 start line and its CRLF-delimited headers.
// Folding, duplicate length declarations, and ambiguous framing are rejected.
func ReadHead(br *bufio.Reader) (*Head, error) {
	start, err := readCRLFLine(br, maxStartLine)
	if err != nil {
		return nil, err
	}

	h := &Head{}
	if len(start) >= 11 && hasTokenPrefix(start, "HTTP/") {
		h.IsRequest = false
		if err := parseStatusLine(h, string(start)); err != nil {
			return nil, err
		}
	} else {
		h.IsRequest = true
		if err := parseRequestLine(h, string(start)); err != nil {
			return nil, err
		}
	}

	total := len(start)
	var sawCL, sawTE, sawHost, sawConn bool
	var clCount int
	for {
		line, err := readCRLFLine(br, maxStartLine)
		if err != nil {
			return nil, err
		}
		total += len(line) + 2
		if total > maxHeadBlock {
			return nil, protof("header block too large")
		}
		if len(line) == 0 {
			break
		}
		// obs-fold: any continuation line is invalid in this proxy.
		if line[0] == ' ' || line[0] == '\t' {
			return nil, protof("folded header is not accepted")
		}
		colon := indexByte(line, ':')
		if colon <= 0 {
			return nil, protof("malformed header line")
		}
		name := string(line[:colon])
		for i := 0; i < len(name); i++ {
			if !isTokenByte(name[i]) {
				return nil, protof("invalid header name byte")
			}
		}
		value := trimOWS(string(line[colon+1:]))
		if !validFieldValue(value) {
			return nil, protof("invalid header field value")
		}
		h.Headers = append(h.Headers, Header{Name: name, Value: value})

		lname := asciiLower(name)
		switch lname {
		case "content-length":
			clCount++
			if clCount > 1 {
				return nil, protof("duplicate content-length")
			}
			n, err := parseContentLength(value)
			if err != nil {
				return nil, err
			}
			h.ContentLength, h.HasLength = n, true
			sawCL = true
		case "transfer-encoding":
			if sawTE || strings.Contains(value, ",") {
				return nil, protof("multiple transfer-encoding values")
			}
			if asciiLower(value) != "chunked" {
				return nil, protof("only transfer-encoding: chunked is supported")
			}
			sawTE = true
		case "connection":
			if sawConn {
				return nil, protof("duplicate connection")
			}
			sawConn = true
			for _, tok := range strings.Split(value, ",") {
				if asciiLower(trimOWS(tok)) == "close" {
					h.WantsClose = true
				}
			}
		case "host":
			if sawHost {
				return nil, protof("duplicate host")
			}
			if value == "" {
				return nil, protof("empty host")
			}
			sawHost = true
		case "expect":
			if strings.Contains(asciiLower(value), "100-continue") {
				h.Expect100 = true
			}
		}
	}

	if sawCL && sawTE {
		return nil, protof("content-length and transfer-encoding both present")
	}
	switch {
	case sawTE:
		h.BodyFraming = FrameChunked
	case sawCL:
		h.BodyFraming = FrameLength
	default:
		h.BodyFraming = FrameNone
	}

	if h.IsRequest {
		if !sawHost {
			return nil, protof("missing host")
		}
		switch h.Method {
		case "GET":
			// A GET has no body; an explicit zero is harmless but pointless.
			if h.BodyFraming != FrameNone && !(h.BodyFraming == FrameLength && h.ContentLength == 0) {
				return nil, protof("GET must not carry a body")
			}
			if h.ContentLength == 0 && h.BodyFraming == FrameLength {
				h.BodyFraming, h.HasLength = FrameNone, false
			}
		case "POST":
			if h.BodyFraming == FrameLength && h.ContentLength > MaxBody {
				return nil, protof("request body exceeds 32KiB")
			}
		default:
			return nil, &MethodError{Method: h.Method}
		}
	}
	return h, nil
}

// MethodError marks a verb this proxy does not implement.
type MethodError struct{ Method string }

func (e *MethodError) Error() string { return "method not implemented: " + e.Method }

func hasTokenPrefix(b []byte, p string) bool {
	if len(b) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if b[i] != p[i] {
			return false
		}
	}
	return true
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func parseRequestLine(h *Head, line string) error {
	sp1 := strings.IndexByte(line, ' ')
	if sp1 <= 0 {
		return protof("malformed request line")
	}
	method := line[:sp1]
	for i := 0; i < len(method); i++ {
		if !isTokenByte(method[i]) {
			return protof("invalid method token")
		}
	}
	rest := line[sp1+1:]
	sp2 := strings.IndexByte(rest, ' ')
	if sp2 <= 0 {
		return protof("malformed request line")
	}
	target := rest[:sp2]
	version := rest[sp2+1:]
	if version != "HTTP/1.1" {
		return protof("only HTTP/1.1 supported, got %q", version)
	}
	h.Method, h.Target = method, target
	if method != "CONNECT" && target[0] != '/' {
		return protof("only origin-form request target supported")
	}
	if method == "CONNECT" {
		// authority-form is parsed only so the verb reaches the method switch,
		// which refuses it with 501. This proxy never tunnels CONNECT.
	}
	for i := 0; i < len(target); i++ {
		c := target[i]
		if c < 0x20 || c == 0x7f {
			return protof("control character in target")
		}
	}
	return nil
}

func parseStatusLine(h *Head, line string) error {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return protof("malformed status line")
	}
	version := line[:sp]
	if version != "HTTP/1.1" && version != "HTTP/1.0" {
		return protof("unsupported upstream HTTP version %q", version)
	}
	rest := line[sp+1:]
	// skip exactly one SP gap between version and code
	for len(rest) > 0 && rest[0] == ' ' {
		rest = rest[1:]
	}
	if len(rest) < 3 {
		return protof("malformed status code")
	}
	code, err := strconv.Atoi(rest[:3])
	if err != nil || code < 100 || code > 599 {
		return protof("malformed status code")
	}
	rest = rest[3:]
	if rest != "" {
		if rest[0] != ' ' {
			return protof("garbage after status code")
		}
		reason := rest[1:]
		if !validFieldValue(reason) {
			return protof("invalid reason phrase")
		}
		h.Reason = reason
	}
	h.StatusCode = code
	return nil
}

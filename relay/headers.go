package relay

import (
	"fmt"
	"io"
)

// pumpBufSize bounds the in-memory copy window. Bodies are streamed; the proxy
// never holds a whole request at once.
const pumpBufSize = 4096

// hopHeaders are RFC 7230/9110 hop-by-hop fields, plus the framing fields this
// proxy regenerates itself, Expect (the proxy terminates 100-continue itself),
// and the non-standard but ubiquitous Proxy-Connection.
var hopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"content-length":      true, // re-emitted with one explicit length
	"expect":              true, // 100-continue is handled by this proxy
}

// connectionTokens parses the Connection header tokens that name additional
// per-connection headers which must not be forwarded.
func connectionTokens(h *Head) map[string]bool {
	out := map[string]bool{}
	for _, hdr := range h.Headers {
		if asciiLower(hdr.Name) != "connection" {
			continue
		}
		start := 0
		v := hdr.Value
		for i := 0; i <= len(v); i++ {
			if i == len(v) || v[i] == ',' {
				tok := asciiLower(trimOWS(v[start:i]))
				if tok != "" {
					out[tok] = true
				}
				start = i + 1
			}
		}
	}
	return out
}

// writeForwardedRequestHead emits one normalized request to upstream:
// original end-to-end headers in order, hop fields stripped, and exactly one
// unambiguous length encoding appended by the caller (CL or chunked).
func writeForwardedRequestHead(w io.Writer, h *Head) error {
	var b []byte
	b = append(b, h.Method...)
	b = append(b, ' ')
	b = append(b, h.Target...)
	b = append(b, ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n')

	drop := connectionTokens(h)
	for _, hdr := range h.Headers {
		name := asciiLower(hdr.Name)
		if hopHeaders[name] || drop[name] {
			continue
		}
		b = appendHeader(b, hdr.Name, hdr.Value)
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

// writeForwardedResponseHead mirrors the request path for responses.
func writeForwardedResponseHead(w io.Writer, h *Head) error {
	var b []byte
	b = append(b, "HTTP/1.1 "...)
	b = fmt.Appendf(b, "%03d", h.StatusCode)
	if h.Reason != "" {
		b = append(b, ' ')
		b = append(b, h.Reason...)
	}
	b = append(b, '\r', '\n')

	drop := connectionTokens(h)
	for _, hdr := range h.Headers {
		name := asciiLower(hdr.Name)
		if hopHeaders[name] || drop[name] {
			continue
		}
		b = appendHeader(b, hdr.Name, hdr.Value)
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

func appendHeader(b []byte, name, value string) []byte {
	b = append(b, name...)
	b = append(b, ':', ' ')
	b = append(b, value...)
	b = append(b, '\r', '\n')
	return b
}

// copyExact streams exactly n bytes from r to w through a fixed 4KiB window.
// A short source or sink is an error, never a silent truncation. Returns the
// number of bytes copied before the error (if any).
func copyExact(w io.Writer, r io.Reader, n int64) (int64, error) {
	buf := make([]byte, pumpBufSize)
	var copied int64
	for copied < n {
		want := n - copied
		if int64(len(buf)) < want {
			want = int64(len(buf))
		}
		rn, rerr := r.Read(buf[:want])
		if rn > 0 {
			wn, werr := w.Write(buf[:rn])
			copied += int64(wn)
			if werr != nil {
				return copied, werr
			}
			if wn != rn {
				return copied, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if copied < n {
				return copied, io.ErrUnexpectedEOF
			}
			return copied, nil
		}
		if rn == 0 {
			// A well-behaved Reader must not do this; treat it as truncation
			// rather than spinning forever.
			return copied, io.ErrNoProgress
		}
	}
	return copied, nil
}

// rechunk streams a de-framed body from r and writes it with HTTP chunked
// transfer coding in fixed 4KiB chunks. The caller emits the final 0-chunk
// only when the source body ends without error.
func rechunk(w io.Writer, r io.Reader) (int64, error) {
	buf := make([]byte, pumpBufSize)
	var total int64
	for {
		// Call Read directly: io.ReadFull would wrap the body-terminating
		// io.EOF returned alongside a partial final buffer as
		// ErrUnexpectedEOF, indistinguishable from a truncated message.
		n, rerr := r.Read(buf)
		if n > 0 {
			if _, err := fmt.Fprintf(w, "%x\r\n", n); err != nil {
				return total, err
			}
			wn, err := w.Write(buf[:n])
			total += int64(wn)
			if err != nil {
				return total, err
			}
			if wn != n {
				return total, io.ErrShortWrite
			}
			if _, err := w.Write([]byte("\r\n")); err != nil {
				return total, err
			}
		}
		if rerr == nil {
			continue
		}
		if rerr == io.EOF {
			break // clean body end: the zero chunk was validated
		}
		// Truncation, framing errors, and everything else are fatal: never
		// emit the terminating zero chunk for a body that did not end.
		return total, rerr
	}
	return total, nil
}

func writeChunkEnd(w io.Writer) error {
	_, err := w.Write([]byte("0\r\n\r\n"))
	return err
}

// drainToClose copies until source EOF (response body delimited by close).
func drainToClose(w io.Writer, r io.Reader) (int64, error) {
	return io.CopyBuffer(w, r, make([]byte, pumpBufSize))
}

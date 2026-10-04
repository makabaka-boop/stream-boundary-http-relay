package relay

import (
	"bufio"
	"errors"
	"io"
	"strconv"
)

// chunkedReader decodes RFC 9112 chunked transfer coding with zero tolerance
// for framing drift. maxDechunk caps cumulative de-framed body bytes; a value
// <= 0 means unlimited.
//
// Any violation (bad hex, stray CR, oversized body, malformed trailer) is a
// permanent error: the caller must stop framing and tear the connection down.
type chunkedReader struct {
	br         *bufio.Reader
	maxDechunk int64

	state     chunkState
	remaining int64 // bytes left in the current chunk-data section
	total     int64 // de-framed bytes already produced
	bodyDone  bool
}

type chunkState int

const (
	chunkSize chunkState = iota
	chunkData
	chunkDataCRLF
)

// NewChunkedReader wraps br. maxDechunk<=0 disables the cumulative size cap.
func NewChunkedReader(br *bufio.Reader, maxDechunk int64) *chunkedReader {
	return &chunkedReader{br: br, maxDechunk: maxDechunk}
}

// BodyDone reports whether the terminating zero chunk and trailers were consumed.
func (c *chunkedReader) BodyDone() bool { return c.bodyDone }

// Read returns de-framed bytes. It never returns (0, nil): either data is
// produced, EOF follows a fully validated trailer, or an error is reported.
func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.bodyDone {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Boundary bookkeeping between chunk sections happens here, before data,
	// so callers see only a flat body byte stream.
	if c.state == chunkDataCRLF {
		if err := c.consumeCRLF(); err != nil {
			return 0, err
		}
	}
	if c.state == chunkSize {
		zero, err := c.readChunkSize()
		if err != nil {
			return 0, err
		}
		if zero {
			if err := c.readTrailers(); err != nil {
				return 0, err
			}
			c.bodyDone = true
			return 0, io.EOF
		}
	}

	// chunkData
	lim := p
	if int64(len(lim)) > c.remaining {
		lim = lim[:c.remaining]
	}
	n, err := c.br.Read(lim)
	c.remaining -= int64(n)
	c.total += int64(n)
	if c.remaining == 0 {
		// Validate the section terminator immediately: a byte that is not
		// CRLF must be caught even if the caller treats this read as "full".
		if cerr := c.consumeCRLF(); cerr != nil {
			return n, cerr
		}
		// Advance to the next size line so a malformed following chunk is
		// surfaced before the caller mistakes the body for complete.
		zero, zerr := c.readChunkSize()
		if zerr != nil {
			return n, zerr
		}
		if zero {
			if terr := c.readTrailers(); terr != nil {
				return n, terr
			}
			c.bodyDone = true
		}
	} else if err != nil {
		err = frameEOF(err)
	}
	return n, err
}

func (c *chunkedReader) consumeCRLF() error {
	cr, err := c.br.ReadByte()
	if err != nil {
		return frameEOF(err)
	}
	if cr != '\r' {
		return protof("expected CR after chunk data")
	}
	lf, err := c.br.ReadByte()
	if err != nil {
		return frameEOF(err)
	}
	if lf != '\n' {
		return protof("expected LF after chunk data")
	}
	c.state = chunkSize
	return nil
}

// errChunkTruncated is a bare connection EOF where a chunk framing element was
// required. It is distinct from io.EOF, which a reader may legitimately see
// once the zero chunk and trailers have already completed the body.
var errChunkTruncated = errors.New("chunked message truncated (unexpected EOF)")

// frameEOF maps a bare connection EOF while awaiting a required framing
// element to errChunkTruncated. Only the zero chunk can end a chunked body.
func frameEOF(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errChunkTruncated
	}
	return err
}

// readChunkSize parses one chunk-size line. Extensions after ';' are accepted
// syntactically and discarded. Returns zero==true for the terminating chunk.
func (c *chunkedReader) readChunkSize() (bool, error) {
	line, err := readCRLFLine(c.br, maxStartLine)
	if err != nil {
		return false, frameEOF(err)
	}
	if semi := indexByte(line, ';'); semi >= 0 {
		line = line[:semi]
	}
	sizeRaw := string(line)
	if sizeRaw == "" {
		return false, protof("empty chunk-size")
	}
	// No whitespace anywhere around the hex size.
	for i := 0; i < len(sizeRaw); i++ {
		if !isHexDigit(sizeRaw[i]) {
			return false, protof("invalid hex digit in chunk-size %q", sizeRaw)
		}
	}
	size, err := strconv.ParseUint(sizeRaw, 16, 64)
	if err != nil {
		return false, protof("bad chunk-size %q", sizeRaw)
	}
	if size == 0 {
		return true, nil
	}
	if c.maxDechunk > 0 && int64(size) > c.maxDechunk-c.total {
		return false, protof("dechunked body exceeds limit")
	}
	c.remaining = int64(size)
	c.state = chunkData
	return false, nil
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// readTrailers consumes the trailing header section up to its blank line.
// obs-fold and malformed fields are rejected; values are not forwarded.
func (c *chunkedReader) readTrailers() error {
	for {
		line, err := readCRLFLine(c.br, maxStartLine)
		if err != nil {
			return frameEOF(err)
		}
		if len(line) == 0 {
			return nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			return protof("folded chunk trailer")
		}
		colon := indexByte(line, ':')
		if colon <= 0 {
			return protof("malformed chunk trailer")
		}
		for i := 0; i < colon; i++ {
			if !isTokenByte(line[i]) {
				return protof("invalid trailer name byte")
			}
		}
		if !validFieldValue(trimOWS(string(line[colon+1:]))) {
			return protof("invalid trailer value")
		}
	}
}

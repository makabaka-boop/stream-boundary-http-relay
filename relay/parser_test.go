package relay

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func headOf(t *testing.T, raw string) *Head {
	t.Helper()
	h, err := ReadHead(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("unexpected parse error: %v\nraw: %q", err, raw)
	}
	return h
}

func headErr(t *testing.T, raw string) {
	t.Helper()
	_, err := ReadHead(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatalf("expected rejection, raw: %q", raw)
	}
	var pe *ProtoError
	if !errors.As(err, &pe) {
		t.Fatalf("expected ProtoError, got %T: %v", err, err)
	}
}

func TestParseValid(t *testing.T) {
	h := headOf(t, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n")
	if h.Method != "POST" || h.Target != "/x" || h.ContentLength != 5 || h.BodyFraming != FrameLength {
		t.Fatalf("bad parse: %+v", h)
	}
}

func TestRejectDuplicateContentLength(t *testing.T) {
	headErr(t, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n")
}

func TestRejectClAndTe(t *testing.T) {
	headErr(t, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")
}

func TestRejectFoldedHeader(t *testing.T) {
	headErr(t, "GET / HTTP/1.1\r\nHost: a\r\nX-A: 1\r\n folded\r\n\r\n")
}

func TestRejectBareLF(t *testing.T) {
	_, err := ReadHead(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\nHost: a\n\n")))
	if err == nil {
		t.Fatal("expected bare-LF rejection")
	}
}

func TestRejectBadVersionsAndMethods(t *testing.T) {
	headErr(t, "GET / HTTP/1.0\r\nHost: a\r\n\r\n")
	// An unknown but token-shaped verb is a 501 MethodError, not a grammar error.
	if _, err := ReadHead(bufio.NewReader(strings.NewReader("GOT / HTTP/1.1\r\nHost: a\r\n\r\n"))); err == nil {
		t.Fatal("expected MethodError for GOT")
	} else {
		var me *MethodError
		if !errors.As(err, &me) {
			t.Fatalf("expected MethodError, got %v", err)
		}
	}
	if _, err := ReadHead(bufio.NewReader(strings.NewReader("PUT / HTTP/1.1\r\nHost: a\r\n\r\n"))); err == nil {
		t.Fatal("expected MethodError for PUT")
	} else {
		var me *MethodError
		if !errors.As(err, &me) {
			t.Fatalf("expected MethodError, got %v", err)
		}
	}
}

func TestRejectOversizedLength(t *testing.T) {
	headErr(t, "POST /big HTTP/1.1\r\nHost: a\r\nContent-Length: 32769\r\n\r\n")
	// exactly at limit is fine
	h := headOf(t, "POST /big HTTP/1.1\r\nHost: a\r\nContent-Length: 32768\r\n\r\n")
	if h.ContentLength != 32768 {
		t.Fatalf("limit edge broken: %d", h.ContentLength)
	}
}

func TestRejectMultipleTe(t *testing.T) {
	headErr(t, "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
	headErr(t, "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n")
}

func TestRejectClList(t *testing.T) {
	headErr(t, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\n")
	headErr(t, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 01\r\n\r\n")
}

func TestRejectGetBody(t *testing.T) {
	headErr(t, "GET /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n")
	headErr(t, "GET /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n")
}

func dechunk(t *testing.T, raw string, wantBody string, max int64) {
	t.Helper()
	cr := NewChunkedReader(bufio.NewReader(strings.NewReader(raw)), max)
	got, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("dechunk error: %v (want body %q)", err, wantBody)
	}
	if string(got) != wantBody {
		t.Fatalf("dechunk body = %q, want %q", got, wantBody)
	}
}

func dechunkErr(t *testing.T, raw string, max int64) {
	t.Helper()
	cr := NewChunkedReader(bufio.NewReader(strings.NewReader(raw)), max)
	if _, err := io.ReadAll(cr); err == nil {
		t.Fatalf("expected chunk framing error for %q", raw)
	} else {
		var pe *ProtoError
		if !errors.As(err, &pe) {
			t.Fatalf("expected ProtoError, got %T %v", err, err)
		}
	}
}

func TestChunkedDecode(t *testing.T) {
	dechunk(t, "5\r\nhello\r\n0\r\n\r\n", "hello", MaxBody)
	dechunk(t, "5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: v\r\n\r\n", "hello world", MaxBody)
	// extensions ignored
	dechunk(t, "5;name=val\r\nhello\r\n0\r\n\r\n", "hello", MaxBody)
	// chunk split across arbitrarily tiny reads still decodes fully
	raw := "10\r\n0123456789abcdef\r\n0\r\n\r\n"
	for _, size := range []int{1, 2, 3, 7} {
		cr := NewChunkedReader(bufio.NewReaderSize(strings.NewReader(raw), size), MaxBody)
		got, err := io.ReadAll(cr)
		if err != nil || len(got) != 16 {
			t.Fatalf("tiny reader size=%d: n=%d err=%v", size, len(got), err)
		}
	}
}

func TestChunkedReject(t *testing.T) {
	dechunkErr(t, "x\r\nhello\r\n0\r\n\r\n", MaxBody)             // bad hex
	dechunkErr(t, "5\r\nhello\r0\r\n\r\n", MaxBody)               // CR not LF
	dechunkErr(t, "5\r\nhello\n0\r\n\r\n", MaxBody)               // bare LF
	dechunkErr(t, "3\r\nabc\r\nG\r\nzzzzz\r\n0\r\n\r\n", MaxBody) // bad next chunk-size
	dechunkErr(t, "5\r\nhello\r\n0\r\n fold\r\n\r\n", MaxBody)    // folded trailer
	dechunkErr(t, "5\r\nhello\r\n 1\r\nb\r\n0\r\n\r\n", MaxBody)  // size line has leading space
}

func TestChunkedSizeCap(t *testing.T) {
	// One chunk claiming more than the cap.
	dechunkErr(t, "10000\r\n"+strings.Repeat("a", 0x10000)+"\r\n0\r\n\r\n", MaxBody)
	// Sum of chunks over the cap.
	big := "10000\r\n" + strings.Repeat("a", 0x10000) + "\r\n1\r\nb\r\n0\r\n\r\n"
	dechunkErr(t, big, MaxBody)
}

func TestRechunkRoundTrip(t *testing.T) {
	body := bytes.Repeat([]byte("Z"), 10000)
	raw := "2710\r\n" + string(body) + "\r\n0\r\n\r\n"
	cr := NewChunkedReader(bufio.NewReader(strings.NewReader(raw)), MaxBody)
	var out bytes.Buffer
	n, err := rechunk(&out, cr)
	if err != nil || n != 10000 {
		t.Fatalf("rechunk n=%d err=%v", n, err)
	}
	if err := writeChunkEnd(&out); err != nil {
		t.Fatal(err)
	}
	// The re-emitted stream must decode back to the same body and hash.
	back := NewChunkedReader(bufio.NewReader(&out), 0)
	all, err := io.ReadAll(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(all, body) {
		t.Fatalf("round trip mismatch")
	}
	sum1 := sha256.Sum256(body)
	sum2 := sha256.Sum256(all)
	if hex.EncodeToString(sum1[:]) != hex.EncodeToString(sum2[:]) {
		t.Fatal("digest mismatch")
	}
}

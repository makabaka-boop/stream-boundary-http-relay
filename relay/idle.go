package relay

import (
	"net"
	"time"
)

// idleConn refreshes its deadline on every successful Read/Write so that a
// peer trickling bytes one at a time ("slow read") is not killed by an overall
// deadline, while a truly silent peer still is.
type idleConn struct {
	net.Conn
	idle time.Duration
}

// newIdleConn wraps c. idle<=0 means no deadlines at all.
func newIdleConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	return &idleConn{Conn: c, idle: idle}
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	n, err := c.Conn.Read(p)
	if err == nil {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	n, err := c.Conn.Write(p)
	if err == nil {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

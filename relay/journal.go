package relay

import (
	"log"
	"sync"
	"time"
)

// EventKind enumerates the journal events the proxy emits.
type EventKind string

const (
	// EvAccepted: a request head was valid and forwarding began.
	EvAccepted EventKind = "accepted"
	// EvCompleted: the full request body was forwarded and the response was
	// fully relayed. Upstream side effects are committed.
	EvCompleted EventKind = "completed"
	// EvIncomplete: forwarding started but the exchange did not finish.
	// ForwardedBytes records how many *body* bytes already reached upstream;
	// those bytes are NOT withdrawn and origin side effects stand.
	EvIncomplete EventKind = "incomplete"
	// EvRejected: the request was refused; Forwarded==true means its head or
	// part of its body had already gone upstream when the framing broke.
	EvRejected EventKind = "rejected"
)

// Event is one structured proxy decision.
type Event struct {
	Time           time.Time
	Kind           EventKind
	ConnID         uint64
	Seq            int
	Method         string
	Target         string
	Reason         string
	Forwarded      bool
	ForwardedBytes int64
}

// Journal records per-request lifecycle events.
type Journal interface {
	Record(ev Event)
}

// StdLogger writes events through a *log.Logger.
type StdLogger struct{ L *log.Logger }

func (s StdLogger) Record(ev Event) {
	if s.L == nil {
		return
	}
	switch ev.Kind {
	case EvAccepted:
		s.L.Printf("conn#%d seq=%d %s %s accepted", ev.ConnID, ev.Seq, ev.Method, ev.Target)
	case EvCompleted:
		s.L.Printf("conn#%d seq=%d %s %s completed body=%d", ev.ConnID, ev.Seq, ev.Method, ev.Target, ev.ForwardedBytes)
	case EvIncomplete:
		s.L.Printf("conn#%d seq=%d %s %s INCOMPLETE forwarded=%t bytes=%d reason=%s",
			ev.ConnID, ev.Seq, ev.Method, ev.Target, ev.Forwarded, ev.ForwardedBytes, ev.Reason)
	case EvRejected:
		s.L.Printf("conn#%d seq=%d %s %s rejected forwarded=%t bytes=%d reason=%s",
			ev.ConnID, ev.Seq, ev.Method, ev.Target, ev.Forwarded, ev.ForwardedBytes, ev.Reason)
	}
}

// MemoryJournal keeps events for assertions in tests.
type MemoryJournal struct {
	mu     sync.Mutex
	events []Event
}

func (m *MemoryJournal) Record(ev Event) {
	m.mu.Lock()
	m.events = append(m.events, ev)
	m.mu.Unlock()
}

// Events returns a snapshot copy.
func (m *MemoryJournal) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
}

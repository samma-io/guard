// Package audit publishes block and dry-run decisions to NATS, so every block
// can be traced to a rule, a source and a reason.
//
// Events are deduplicated per (rule, client IP) inside a window. An attacker
// hammering the service produces one event per window, not one per request.
package audit

import (
	"encoding/json"
	"sync"
	"time"
)

// Event is one published audit record.
type Event struct {
	Time    time.Time `json:"time"`
	Ref     string    `json:"ref"` // also returned to the client as X-Guard-Ref
	Verdict string    `json:"verdict"`
	RuleID  string    `json:"rule_id"`
	Kind    string    `json:"kind"`
	Origin  string    `json:"origin"`
	Source  string    `json:"source,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Host    string    `json:"host,omitempty"`
	Path    string    `json:"path,omitempty"`
	Method  string    `json:"method,omitempty"`
	UA      string    `json:"ua,omitempty"`
	// Suppressed is how many matching events were folded into this one since
	// the previous event for the same rule and IP.
	Suppressed uint64 `json:"suppressed,omitempty"`
}

// Publisher is the part of a NATS connection the auditor needs.
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Auditor deduplicates and sends events without blocking the caller.
type Auditor struct {
	pub     Publisher
	subject string
	window  time.Duration
	queue   chan Event
	onRes   func(result string)

	mu   sync.Mutex
	seen map[string]*entry
}

type entry struct {
	last       time.Time
	suppressed uint64
}

// New creates an auditor. pub may be nil, in which case events are only counted.
func New(pub Publisher, subject string, window time.Duration, onResult func(string)) *Auditor {
	if onResult == nil {
		onResult = func(string) {}
	}
	return &Auditor{
		pub:     pub,
		subject: subject,
		window:  window,
		queue:   make(chan Event, 4096),
		onRes:   onResult,
		seen:    map[string]*entry{},
	}
}

// Record queues an event unless one for the same rule and IP went out within
// the window. It never blocks; a full queue drops the event.
func (a *Auditor) Record(ev Event) {
	key := ev.RuleID + "|" + ev.IP
	a.mu.Lock()
	e, ok := a.seen[key]
	if ok && ev.Time.Sub(e.last) < a.window {
		e.suppressed++
		a.mu.Unlock()
		a.onRes("suppressed")
		return
	}
	if !ok {
		e = &entry{}
		a.seen[key] = e
	}
	ev.Suppressed = e.suppressed
	e.last = ev.Time
	e.suppressed = 0
	a.mu.Unlock()

	select {
	case a.queue <- ev:
	default:
		a.onRes("dropped")
	}
}

// Run sends queued events and prunes old dedup entries until stop closes.
func (a *Auditor) Run(stop <-chan struct{}) {
	prune := time.NewTicker(a.window * 2)
	defer prune.Stop()
	for {
		select {
		case <-stop:
			return
		case ev := <-a.queue:
			a.send(ev)
		case now := <-prune.C:
			a.mu.Lock()
			for k, e := range a.seen {
				if now.Sub(e.last) > a.window*2 {
					delete(a.seen, k)
				}
			}
			a.mu.Unlock()
		}
	}
}

func (a *Auditor) send(ev Event) {
	if a.pub == nil {
		a.onRes("disabled")
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		a.onRes("failed")
		return
	}
	if err := a.pub.Publish(a.subject, b); err != nil {
		a.onRes("failed")
		return
	}
	a.onRes("sent")
}

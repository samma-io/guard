package audit

import (
	"testing"
	"time"
)

func TestDedup(t *testing.T) {
	a := New(nil, "s", time.Minute, nil)
	t0 := time.Now()
	a.Record(Event{Time: t0, RuleID: "r", IP: "1.2.3.4"})
	a.Record(Event{Time: t0.Add(time.Second), RuleID: "r", IP: "1.2.3.4"})
	a.Record(Event{Time: t0.Add(2 * time.Second), RuleID: "r", IP: "1.2.3.4"})
	a.Record(Event{Time: t0.Add(2 * time.Minute), RuleID: "r", IP: "1.2.3.4"})
	if got := len(a.queue); got != 2 {
		t.Fatalf("queued %d, want 2", got)
	}
	<-a.queue
	if ev := <-a.queue; ev.Suppressed != 2 {
		t.Fatalf("suppressed %d, want 2", ev.Suppressed)
	}
}

package store

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/samma-io/guard/internal/rules"
)

func dyn(t *testing.T, ip string, ttl time.Duration) *rules.Rule {
	t.Helper()
	r, err := rules.Parse([]byte(`{"id":"`+ip+`","kind":"ip","match":"`+ip+`","action":"block","expires":"`+time.Now().Add(ttl).Format(time.RFC3339Nano)+`"}`),
		rules.OriginDynamic, rules.DefaultLimits, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func blocked(s *Store, ip string) bool {
	return s.Current().Evaluate(rules.Request{IP: netip.MustParseAddr(ip)}, time.Now()).Verdict == rules.VerdictBlock
}

func TestPutDeleteRebuild(t *testing.T) {
	s := New(2, 0)
	if err := s.PutDynamic("ip.a", dyn(t, "203.0.113.1", time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.Rebuild()
	if !blocked(s, "203.0.113.1") {
		t.Fatal("rule not active after rebuild")
	}
	s.DeleteDynamic("ip.a")
	s.Rebuild()
	if blocked(s, "203.0.113.1") {
		t.Fatal("rule still active after delete")
	}
}

func TestLimit(t *testing.T) {
	s := New(1, 0)
	_ = s.PutDynamic("a", dyn(t, "203.0.113.1", time.Hour))
	var full ErrFull
	if err := s.PutDynamic("b", dyn(t, "203.0.113.2", time.Hour)); !errors.As(err, &full) {
		t.Fatalf("got %v, want ErrFull", err)
	}
	// replacing an existing key is allowed at the limit
	if err := s.PutDynamic("a", dyn(t, "203.0.113.3", time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestSweepDropsExpired(t *testing.T) {
	s := New(10, 0)
	_ = s.PutDynamic("a", dyn(t, "203.0.113.1", 20*time.Millisecond))
	s.Rebuild()
	time.Sleep(40 * time.Millisecond)
	s.Rebuild()
	if s.DynamicCount() != 0 {
		t.Fatal("expired rule not swept")
	}
}

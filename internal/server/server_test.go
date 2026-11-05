package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samma-io/guard/internal/audit"
	"github.com/samma-io/guard/internal/baseline"
	"github.com/samma-io/guard/internal/metrics"
	"github.com/samma-io/guard/internal/store"
)

type pubSpy struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (p *pubSpy) Publish(_ string, b []byte) error {
	p.mu.Lock()
	p.msgs = append(p.msgs, b)
	p.mu.Unlock()
	return nil
}

func newServer(t *testing.T) (*Server, *audit.Auditor) {
	t.Helper()
	base, err := baseline.Parse([]byte(`{"rules":[
		{"id":"lb","kind":"cidr","match":"10.0.0.0/8","action":"allow"},
		{"id":"admin","kind":"path","match":"/admin","action":"block"},
		{"id":"bad","kind":"ip","match":"203.0.113.44","action":"block"}
	]}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(10, 0)
	st.SetBaseline(base)
	aud := audit.New(&pubSpy{}, "s", time.Minute, nil)
	ready := &atomic.Bool{}
	ready.Store(true)
	return &Server{
		Store:          st,
		Audit:          aud,
		Metrics:        metrics.New(),
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
		Ready:          ready,
	}, aud
}

func do(h http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/check", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCheck(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	cases := []struct {
		name    string
		headers map[string]string
		code    int
	}{
		{"allow", map[string]string{"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/"}, 200},
		{"block ip", map[string]string{"X-Forwarded-For": "203.0.113.44"}, 403},
		{"forged left entry ignored", map[string]string{"X-Forwarded-For": "8.8.8.8, 203.0.113.44"}, 403},
		{"spoofing a good ip does not help", map[string]string{"X-Forwarded-For": "203.0.113.44, 8.8.8.8"}, 200},
		{"trusted proxy skipped", map[string]string{"X-Forwarded-For": "203.0.113.44, 172.20.0.5"}, 403},
		{"path block", map[string]string{"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/admin/x?y=1"}, 403},
		{"encoded path", map[string]string{"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/%61dmin"}, 403},
		{"dot segments", map[string]string{"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/public/../admin"}, 403},
		{"double slash", map[string]string{"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "//admin"}, 403},
		{"allowlist wins over path", map[string]string{"X-Forwarded-For": "10.1.2.3", "X-Forwarded-Uri": "/admin"}, 200},
		{"x-real-ip fallback", map[string]string{"X-Real-Ip": "203.0.113.44"}, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := do(h, c.headers)
			if w.Code != c.code {
				t.Fatalf("got %d, want %d", w.Code, c.code)
			}
			if c.code == 403 && w.Header().Get("X-Guard-Ref") == "" {
				t.Fatal("block without X-Guard-Ref")
			}
		})
	}
}

func TestReadiness(t *testing.T) {
	s, _ := newServer(t)
	s.Ready.Store(false)
	r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("got %d, want 503 while not ready", w.Code)
	}
}

func TestNormHost(t *testing.T) {
	for in, want := range map[string]string{"API.Example.com:443": "api.example.com", "example.com.": "example.com", "[2001:db8::1]:8443": "2001:db8::1"} {
		if got := normHost(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

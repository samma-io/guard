// Package server implements the forwardAuth endpoint Traefik calls.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/samma-io/guard/internal/audit"
	"github.com/samma-io/guard/internal/metrics"
	"github.com/samma-io/guard/internal/rules"
	"github.com/samma-io/guard/internal/store"
)

// Server answers /check, /healthz and /readyz.
type Server struct {
	Store          *store.Store
	Audit          *audit.Auditor
	Metrics        *metrics.Registry
	TrustedProxies []netip.Prefix
	Ready          *atomic.Bool
	Now            func() time.Time
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/check", s.check)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Ready.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mux
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	now := s.Now()
	req := s.requestFrom(r)

	d := s.Store.Current().Evaluate(req, now)

	kind := ""
	if d.Rule != nil {
		kind = string(d.Rule.Kind)
	}

	switch d.Verdict {
	case rules.VerdictBlock:
		ref := newRef()
		s.record(ref, req, d, now)
		w.Header().Set("X-Guard-Ref", ref)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden\n"))
	case rules.VerdictLog:
		s.record(newRef(), req, d, now)
		w.Header().Set("X-Guard-Decision", "log")
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("X-Guard-Decision", "allow")
		w.WriteHeader(http.StatusOK)
	}
	s.Metrics.Decision(string(d.Verdict), kind, time.Since(start))
}

func (s *Server) record(ref string, req rules.Request, d rules.Decision, now time.Time) {
	if s.Audit == nil {
		return
	}
	ev := audit.Event{
		Time:    now.UTC(),
		Ref:     ref,
		Verdict: string(d.Verdict),
		RuleID:  d.Rule.ID,
		Kind:    string(d.Rule.Kind),
		Origin:  string(d.Rule.Origin),
		Source:  d.Rule.Source,
		Reason:  d.Rule.Reason,
		Host:    req.Host,
		Path:    req.Path,
		Method:  req.Method,
		UA:      truncate(req.UA, 256),
	}
	if req.IP.IsValid() {
		ev.IP = req.IP.String()
	}
	s.Audit.Record(ev)
}

// requestFrom builds the decision input from the headers Traefik forwards.
func (s *Server) requestFrom(r *http.Request) rules.Request {
	h := r.Header
	return rules.Request{
		IP:     s.clientIP(h),
		Host:   normHost(h.Get("X-Forwarded-Host")),
		Path:   normPath(h.Get("X-Forwarded-Uri")),
		UA:     strings.ToLower(h.Get("User-Agent")),
		Method: h.Get("X-Forwarded-Method"),
	}
}

// clientIP takes the rightmost X-Forwarded-For entry that is not one of our
// own proxies. Entries further left are supplied by the client and can be
// forged, so they are never trusted. Falls back to X-Real-Ip.
func (s *Server) clientIP(h http.Header) netip.Addr {
	var parts []string
	for _, v := range h.Values("X-Forwarded-For") {
		parts = append(parts, strings.Split(v, ",")...)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		a = a.Unmap()
		if s.trusted(a) {
			continue
		}
		return a
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(h.Get("X-Real-Ip"))); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

// normPath decodes and cleans the path so /%61dmin, //admin and
// /x/../admin all match a rule on /admin.
func normPath(uri string) string {
	if uri == "" {
		return ""
	}
	p := uri
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	p = path.Clean("/" + p)
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func newRef() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

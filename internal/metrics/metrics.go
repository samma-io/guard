// Package metrics exposes Prometheus text-format metrics without pulling in
// the client library, to keep the image and dependency tree small.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// latency buckets in seconds; /check should live in the first few
var buckets = []float64{0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01}

type counterVec struct {
	mu sync.Mutex
	m  map[string]*atomic.Uint64
}

func (c *counterVec) inc(labels string) {
	c.mu.Lock()
	v, ok := c.m[labels]
	if !ok {
		v = &atomic.Uint64{}
		c.m[labels] = v
	}
	c.mu.Unlock()
	v.Add(1)
}

func (c *counterVec) write(w io.Writer, name string) {
	c.mu.Lock()
	keys := make([]string, 0, len(c.m))
	for k := range c.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s} %d\n", name, k, c.m[k].Load())
	}
	c.mu.Unlock()
}

// Registry holds every metric the service reports.
type Registry struct {
	decisions counterVec // verdict, kind
	rejected  counterVec // reason
	audit     counterVec // result

	hist  [9]atomic.Uint64 // len(buckets)+1 (+Inf)
	sumNs atomic.Uint64
	count atomic.Uint64

	rulesBaseline atomic.Int64
	rulesDynamic  atomic.Int64
	lastSync      atomic.Int64 // unix seconds of last KV update or initial load
	natsUp        atomic.Int64
	ready         atomic.Int64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		decisions: counterVec{m: map[string]*atomic.Uint64{}},
		rejected:  counterVec{m: map[string]*atomic.Uint64{}},
		audit:     counterVec{m: map[string]*atomic.Uint64{}},
	}
}

func lbl(k, v string) string { return k + `="` + strings.ReplaceAll(v, `"`, `'`) + `"` }

// Decision records one /check outcome and its latency.
func (r *Registry) Decision(verdict, kind string, d time.Duration) {
	if kind == "" {
		kind = "none"
	}
	r.decisions.inc(lbl("verdict", verdict) + "," + lbl("kind", kind))
	s := d.Seconds()
	i := len(buckets)
	for j, b := range buckets {
		if s <= b {
			i = j
			break
		}
	}
	r.hist[i].Add(1)
	r.sumNs.Add(uint64(d.Nanoseconds()))
	r.count.Add(1)
}

// Rejected counts a dynamic rule that failed validation.
func (r *Registry) Rejected(reason string) { r.rejected.inc(lbl("reason", reason)) }

// Audit counts audit publish results: sent, suppressed, failed.
func (r *Registry) Audit(result string) { r.audit.inc(lbl("result", result)) }

// Rules sets the rule gauges.
func (r *Registry) Rules(baseline, dynamic int) {
	r.rulesBaseline.Store(int64(baseline))
	r.rulesDynamic.Store(int64(dynamic))
}

// Synced marks a successful KV update.
func (r *Registry) Synced(t time.Time) { r.lastSync.Store(t.Unix()) }

// NATSUp sets the connection gauge.
func (r *Registry) NATSUp(up bool) { r.natsUp.Store(b2i(up)) }

// Ready sets the readiness gauge.
func (r *Registry) Ready(ok bool) { r.ready.Store(b2i(ok)) }

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ServeHTTP writes the metrics in Prometheus text format.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintln(w, "# HELP guard_decisions_total Decisions made by /check.")
	fmt.Fprintln(w, "# TYPE guard_decisions_total counter")
	r.decisions.write(w, "guard_decisions_total")

	fmt.Fprintln(w, "# HELP guard_check_duration_seconds Time spent deciding one request inside the service.")
	fmt.Fprintln(w, "# TYPE guard_check_duration_seconds histogram")
	var cum uint64
	for i, b := range buckets {
		cum += r.hist[i].Load()
		fmt.Fprintf(w, "guard_check_duration_seconds_bucket{le=\"%g\"} %d\n", b, cum)
	}
	cum += r.hist[len(buckets)].Load()
	fmt.Fprintf(w, "guard_check_duration_seconds_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(w, "guard_check_duration_seconds_sum %g\n", float64(r.sumNs.Load())/1e9)
	fmt.Fprintf(w, "guard_check_duration_seconds_count %d\n", r.count.Load())

	fmt.Fprintln(w, "# HELP guard_rules Rules currently loaded.")
	fmt.Fprintln(w, "# TYPE guard_rules gauge")
	fmt.Fprintf(w, "guard_rules{origin=\"baseline\"} %d\n", r.rulesBaseline.Load())
	fmt.Fprintf(w, "guard_rules{origin=\"dynamic\"} %d\n", r.rulesDynamic.Load())

	fmt.Fprintln(w, "# HELP guard_rules_rejected_total Dynamic rules refused by validation.")
	fmt.Fprintln(w, "# TYPE guard_rules_rejected_total counter")
	r.rejected.write(w, "guard_rules_rejected_total")

	fmt.Fprintln(w, "# HELP guard_audit_events_total Audit events by result.")
	fmt.Fprintln(w, "# TYPE guard_audit_events_total counter")
	r.audit.write(w, "guard_audit_events_total")

	fmt.Fprintln(w, "# HELP guard_sync_last_update_timestamp_seconds Unix time of the last rule update from NATS.")
	fmt.Fprintln(w, "# TYPE guard_sync_last_update_timestamp_seconds gauge")
	fmt.Fprintf(w, "guard_sync_last_update_timestamp_seconds %d\n", r.lastSync.Load())

	fmt.Fprintln(w, "# HELP guard_nats_connected 1 when connected to NATS.")
	fmt.Fprintln(w, "# TYPE guard_nats_connected gauge")
	fmt.Fprintf(w, "guard_nats_connected %d\n", r.natsUp.Load())

	fmt.Fprintln(w, "# HELP guard_ready 1 when baseline and initial rule sync are loaded.")
	fmt.Fprintln(w, "# TYPE guard_ready gauge")
	fmt.Fprintf(w, "guard_ready %d\n", r.ready.Load())
}

package rules

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Request is what the decision is based on. All fields come from the headers
// Traefik sends to a forwardAuth endpoint.
type Request struct {
	IP     netip.Addr
	Host   string // lowercase, no port
	Path   string // path only, no query
	UA     string // lowercase
	Method string
}

// Verdict is the outcome of Evaluate.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictBlock Verdict = "block"
	VerdictLog   Verdict = "log" // allowed, but a dry-run rule matched
)

// Decision is a verdict and the rule that produced it (nil for the default).
type Decision struct {
	Verdict Verdict
	Rule    *Rule
}

type prefixTable struct {
	byLen map[int]map[netip.Prefix][]*Rule
	lens  []int // distinct lengths, longest first
}

func (t *prefixTable) add(r *Rule) {
	if t.byLen == nil {
		t.byLen = map[int]map[netip.Prefix][]*Rule{}
	}
	b := r.prefix.Bits()
	m, ok := t.byLen[b]
	if !ok {
		m = map[netip.Prefix][]*Rule{}
		t.byLen[b] = m
		t.lens = append(t.lens, b)
	}
	m[r.prefix] = append(m[r.prefix], r)
}

func (t *prefixTable) finish() {
	sort.Sort(sort.Reverse(sort.IntSlice(t.lens)))
}

// RuleSet is immutable once built. The store builds a new one on every change
// and swaps it in atomically, so lookups never take a lock.
type RuleSet struct {
	ips   map[netip.Addr][]*Rule
	v4    prefixTable
	v6    prefixTable
	hosts map[string][]*Rule
	paths []*Rule // longest match first
	uas   []*Rule

	count map[Origin]int
}

// Build indexes rules for fast lookup.
func Build(rules []*Rule) *RuleSet {
	rs := &RuleSet{
		ips:   map[netip.Addr][]*Rule{},
		hosts: map[string][]*Rule{},
		count: map[Origin]int{},
	}
	for _, r := range rules {
		rs.count[r.Origin]++
		switch r.Kind {
		case KindIP:
			rs.ips[r.addr] = append(rs.ips[r.addr], r)
		case KindCIDR:
			if r.prefix.Addr().Is4() {
				rs.v4.add(r)
			} else {
				rs.v6.add(r)
			}
		case KindHost:
			rs.hosts[r.Match] = append(rs.hosts[r.Match], r)
		case KindPath:
			rs.paths = append(rs.paths, r)
		case KindUA:
			rs.uas = append(rs.uas, r)
		}
	}
	rs.v4.finish()
	rs.v6.finish()
	sort.SliceStable(rs.paths, func(i, j int) bool { return len(rs.paths[i].Match) > len(rs.paths[j].Match) })
	return rs
}

// Empty is a RuleSet with no rules; everything is allowed.
func Empty() *RuleSet { return Build(nil) }

// Count returns how many rules of each origin the set holds.
func (rs *RuleSet) Count(o Origin) int { return rs.count[o] }

// Evaluate decides one request.
//
// Precedence: any matching allow rule wins (allow rules only exist in the
// baseline, so detection can never lock out your own ranges). Otherwise the
// most specific matching block rule wins, in the order exact IP, CIDR
// (longest prefix first), host, path (longest first), user agent. A match on
// a log rule allows the request but is reported. No match allows.
func (rs *RuleSet) Evaluate(req Request, now time.Time) Decision {
	var block, logged, allowedBy *Rule
	allow := false

	consider := func(list []*Rule) {
		for _, r := range list {
			if allow || !r.Active(now) || !r.InScope(req.Host) {
				continue
			}
			switch r.Action {
			case ActionAllow:
				allow = true
				allowedBy = r
				return
			case ActionBlock:
				if block == nil {
					block = r
				}
			case ActionLog:
				if logged == nil {
					logged = r
				}
			}
		}
	}

	if req.IP.IsValid() {
		ip := req.IP.Unmap()
		consider(rs.ips[ip])
		t := &rs.v4
		if ip.Is6() {
			t = &rs.v6
		}
		for _, l := range t.lens {
			if allow {
				break
			}
			p, err := ip.Prefix(l)
			if err != nil {
				continue
			}
			consider(t.byLen[l][p])
		}
	}
	if !allow && req.Host != "" {
		consider(rs.hosts[req.Host])
	}
	if !allow && req.Path != "" {
		for _, r := range rs.paths {
			if allow {
				break
			}
			if strings.HasPrefix(req.Path, r.Match) {
				consider([]*Rule{r})
			}
		}
	}
	if !allow && req.UA != "" {
		for _, r := range rs.uas {
			if allow {
				break
			}
			if strings.Contains(req.UA, r.Match) {
				consider([]*Rule{r})
			}
		}
	}

	switch {
	case allow:
		return Decision{Verdict: VerdictAllow, Rule: allowedBy}
	case block != nil:
		return Decision{Verdict: VerdictBlock, Rule: block}
	case logged != nil:
		return Decision{Verdict: VerdictLog, Rule: logged}
	default:
		return Decision{Verdict: VerdictAllow}
	}
}

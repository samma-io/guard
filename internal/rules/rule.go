// Package rules holds the rule model, validation and the in-memory RuleSet
// that answers allow/block questions for the /check endpoint.
package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Kind is what a rule matches on.
type Kind string

const (
	KindIP   Kind = "ip"   // exact client IP
	KindCIDR Kind = "cidr" // client IP inside a prefix
	KindHost Kind = "host" // exact request host
	KindPath Kind = "path" // request path prefix
	KindUA   Kind = "ua"   // case-insensitive substring of User-Agent
)

// Action is what happens when a rule matches.
type Action string

const (
	ActionAllow Action = "allow" // baseline only: always let through
	ActionBlock Action = "block" // return 403
	ActionLog   Action = "log"   // dry run: allow, but record the match
)

// Origin says where a rule came from. Precedence depends on it.
type Origin string

const (
	OriginBaseline Origin = "baseline" // ConfigMap, reviewed in git
	OriginDynamic  Origin = "dynamic"  // NATS KV, pushed by detection
)

// Scope limits a rule to some hosts. Empty means every protected ingress.
type Scope struct {
	Hosts []string `json:"hosts,omitempty"`
}

// Rule is one document in the baseline file or one value in the KV bucket.
type Rule struct {
	ID      string     `json:"id"`
	Kind    Kind       `json:"kind"`
	Match   string     `json:"match"`
	Action  Action     `json:"action"`
	Scope   Scope      `json:"scope,omitempty"`
	Reason  string     `json:"reason,omitempty"`
	Source  string     `json:"source,omitempty"`
	Created time.Time  `json:"created,omitempty"`
	Expires *time.Time `json:"expires,omitempty"`

	Origin Origin `json:"-"`

	// parsed forms, filled by Normalize
	addr   netip.Addr
	prefix netip.Prefix
	hosts  map[string]struct{}
}

// Limits bound what a dynamic rule may do. Baseline rules are trusted and
// only need to be well formed.
type Limits struct {
	MaxTTL          time.Duration // longest allowed lifetime of a dynamic rule
	MinPrefixV4     int           // broadest IPv4 prefix a dynamic rule may block
	MinPrefixV6     int           // broadest IPv6 prefix a dynamic rule may block
	AllowDynamicAll bool          // permit dynamic host/path/ua rules with no scope
}

// DefaultLimits are deliberately conservative.
var DefaultLimits = Limits{
	MaxTTL:      7 * 24 * time.Hour,
	MinPrefixV4: 16,
	MinPrefixV6: 32,
}

var (
	ErrNoTTL        = errors.New("dynamic rule needs an expires time")
	ErrTTLTooLong   = errors.New("dynamic rule expires too far in the future")
	ErrExpired      = errors.New("rule has already expired")
	ErrDynamicAllow = errors.New("dynamic rules may not allow; allowlists live in the baseline")
	ErrTooBroad     = errors.New("prefix is broader than the dynamic limit")
)

// Parse decodes and validates one rule.
func Parse(data []byte, origin Origin, lim Limits, now time.Time) (*Rule, error) {
	var r Rule
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	r.Origin = origin
	if err := r.Normalize(lim, now); err != nil {
		return nil, err
	}
	return &r, nil
}

// Normalize checks the rule and fills its parsed fields.
func (r *Rule) Normalize(lim Limits, now time.Time) error {
	if r.ID == "" {
		return errors.New("id is required")
	}
	if r.Match == "" {
		return errors.New("match is required")
	}
	switch r.Action {
	case ActionAllow, ActionBlock, ActionLog:
	case "":
		r.Action = ActionBlock
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}

	switch r.Kind {
	case KindIP:
		a, err := netip.ParseAddr(r.Match)
		if err != nil {
			return fmt.Errorf("ip: %w", err)
		}
		r.addr = a.Unmap()
	case KindCIDR:
		p, err := netip.ParsePrefix(r.Match)
		if err != nil {
			return fmt.Errorf("cidr: %w", err)
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		r.prefix = p
	case KindHost:
		r.Match = strings.ToLower(strings.TrimSuffix(r.Match, "."))
	case KindPath:
		if !strings.HasPrefix(r.Match, "/") {
			return errors.New("path must start with /")
		}
	case KindUA:
		r.Match = strings.ToLower(r.Match)
	default:
		return fmt.Errorf("unknown kind %q", r.Kind)
	}

	if len(r.Scope.Hosts) > 0 {
		r.hosts = make(map[string]struct{}, len(r.Scope.Hosts))
		for _, h := range r.Scope.Hosts {
			r.hosts[strings.ToLower(strings.TrimSuffix(h, "."))] = struct{}{}
		}
	}

	if r.Expires != nil && !r.Expires.After(now) {
		return ErrExpired
	}

	if r.Origin == OriginDynamic {
		if r.Action == ActionAllow {
			return ErrDynamicAllow
		}
		if r.Expires == nil {
			return ErrNoTTL
		}
		if lim.MaxTTL > 0 && r.Expires.Sub(now) > lim.MaxTTL {
			return ErrTTLTooLong
		}
		if r.Kind == KindCIDR {
			min := lim.MinPrefixV4
			if r.prefix.Addr().Is6() {
				min = lim.MinPrefixV6
			}
			if r.prefix.Bits() < min {
				return fmt.Errorf("%w: /%d < /%d", ErrTooBroad, r.prefix.Bits(), min)
			}
		}
		if !lim.AllowDynamicAll && (r.Kind == KindPath || r.Kind == KindUA) && len(r.hosts) == 0 {
			return errors.New("dynamic path and ua rules need scope.hosts")
		}
	}
	return nil
}

// Active reports whether the rule is still in force.
func (r *Rule) Active(now time.Time) bool {
	return r.Expires == nil || r.Expires.After(now)
}

// InScope reports whether the rule applies to this host.
func (r *Rule) InScope(host string) bool {
	if r.hosts == nil {
		return true
	}
	_, ok := r.hosts[host]
	return ok
}

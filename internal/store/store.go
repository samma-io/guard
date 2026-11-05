// Package store owns the current RuleSet. Sources (the baseline file and the
// NATS KV watcher) push changes into it; it rebuilds an immutable RuleSet and
// swaps it in with one atomic store, so /check never waits on a lock.
package store

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samma-io/guard/internal/rules"
)

// Store keeps baseline and dynamic rules and publishes a RuleSet built from both.
type Store struct {
	current atomic.Pointer[rules.RuleSet]

	mu       sync.Mutex
	baseline []*rules.Rule
	dynamic  map[string]*rules.Rule // KV key -> rule
	maxDyn   int

	dirty    chan struct{}
	debounce time.Duration
	now      func() time.Time

	// OnRebuild is called after every swap, for metrics.
	OnRebuild func(rs *rules.RuleSet)
}

// New returns an empty store. maxDynamic caps how many dynamic rules are kept.
func New(maxDynamic int, debounce time.Duration) *Store {
	s := &Store{
		dynamic:  map[string]*rules.Rule{},
		maxDyn:   maxDynamic,
		dirty:    make(chan struct{}, 1),
		debounce: debounce,
		now:      time.Now,
	}
	s.current.Store(rules.Empty())
	return s
}

// Current is the RuleSet to evaluate against. Safe for concurrent use.
func (s *Store) Current() *rules.RuleSet { return s.current.Load() }

// SetBaseline replaces all baseline rules and rebuilds immediately.
func (s *Store) SetBaseline(rs []*rules.Rule) {
	s.mu.Lock()
	s.baseline = rs
	s.mu.Unlock()
	s.Rebuild()
}

// ErrFull is returned by PutDynamic when the dynamic rule cap is reached.
type ErrFull struct{ Max int }

func (e ErrFull) Error() string { return "dynamic rule limit reached" }

// PutDynamic adds or replaces a dynamic rule under its KV key.
// The rebuild is debounced, so a burst of puts causes one swap.
func (s *Store) PutDynamic(key string, r *rules.Rule) error {
	s.mu.Lock()
	if _, exists := s.dynamic[key]; !exists && s.maxDyn > 0 && len(s.dynamic) >= s.maxDyn {
		s.mu.Unlock()
		return ErrFull{Max: s.maxDyn}
	}
	s.dynamic[key] = r
	s.mu.Unlock()
	s.markDirty()
	return nil
}

// DeleteDynamic removes a dynamic rule.
func (s *Store) DeleteDynamic(key string) {
	s.mu.Lock()
	_, ok := s.dynamic[key]
	delete(s.dynamic, key)
	s.mu.Unlock()
	if ok {
		s.markDirty()
	}
}

// ReplaceDynamic swaps the full dynamic set, used after an initial KV load.
func (s *Store) ReplaceDynamic(m map[string]*rules.Rule) {
	s.mu.Lock()
	s.dynamic = m
	s.mu.Unlock()
	s.Rebuild()
}

// DynamicCount returns how many dynamic rules are held.
func (s *Store) DynamicCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dynamic)
}

func (s *Store) markDirty() {
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

// Rebuild builds a new RuleSet from current state, dropping expired dynamic
// rules, and swaps it in.
func (s *Store) Rebuild() {
	now := s.now()
	s.mu.Lock()
	all := make([]*rules.Rule, 0, len(s.baseline)+len(s.dynamic))
	all = append(all, s.baseline...)
	for k, r := range s.dynamic {
		if !r.Active(now) {
			delete(s.dynamic, k)
			continue
		}
		all = append(all, r)
	}
	s.mu.Unlock()

	rs := rules.Build(all)
	s.current.Store(rs)
	if s.OnRebuild != nil {
		s.OnRebuild(rs)
	}
}

// Run handles debounced rebuilds and a periodic sweep of expired rules.
// It returns when ctx is done.
func (s *Store) Run(ctx context.Context, sweep time.Duration) {
	t := time.NewTicker(sweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.dirty:
			if s.debounce > 0 {
				select {
				case <-time.After(s.debounce):
				case <-ctx.Done():
					return
				}
			}
			s.Rebuild()
		case <-t.C:
			s.Rebuild()
		}
	}
}

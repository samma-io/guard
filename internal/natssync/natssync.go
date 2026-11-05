// Package natssync keeps the store in step with a NATS JetStream KV bucket.
//
// On start it reads every key (WatchAll delivers current values first, then a
// nil marker), replaces the dynamic rules in one go and signals that the
// initial sync is done. After that each put or delete is applied as it
// arrives. If NATS goes away the store keeps its last good rules; the client
// reconnects and the watcher resumes on its own.
package natssync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/samma-io/guard/internal/rules"
	"github.com/samma-io/guard/internal/store"
)

// Syncer applies KV changes to a store.
type Syncer struct {
	KV     jetstream.KeyValue
	Store  *store.Store
	Limits rules.Limits
	Log    *slog.Logger

	// Rejected is called with a short reason for each refused rule.
	Rejected func(reason string)
	// Synced is called after the initial load and after every change.
	Synced func(time.Time)
}

// Run watches the bucket until ctx is done. initial is closed once the first
// full load has been applied.
func (s *Syncer) Run(ctx context.Context, initial chan<- struct{}) error {
	w, err := s.KV.WatchAll(ctx)
	if err != nil {
		return fmt.Errorf("watch %s: %w", s.KV.Bucket(), err)
	}
	defer w.Stop()

	loading := true
	pending := map[string]*rules.Rule{}

	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-w.Updates():
			if !ok {
				return errors.New("kv watcher closed")
			}
			if e == nil { // end of initial values
				if loading {
					s.Store.ReplaceDynamic(pending)
					pending = nil
					loading = false
					s.Log.Info("initial rule sync done", "bucket", s.KV.Bucket(), "dynamic_rules", s.Store.DynamicCount())
					s.synced()
					close(initial)
				}
				continue
			}
			s.apply(e, loading, pending)
			if !loading {
				s.synced()
			}
		}
	}
}

func (s *Syncer) apply(e jetstream.KeyValueEntry, loading bool, pending map[string]*rules.Rule) {
	key := e.Key()
	switch e.Operation() {
	case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
		if loading {
			delete(pending, key)
		} else {
			s.Store.DeleteDynamic(key)
		}
		return
	}

	r, err := rules.Parse(e.Value(), rules.OriginDynamic, s.Limits, time.Now())
	if err != nil {
		reason := reasonOf(err)
		s.Log.Warn("rejected dynamic rule", "key", key, "revision", e.Revision(), "reason", reason, "error", err)
		if s.Rejected != nil {
			s.Rejected(reason)
		}
		// A rejected update must not leave an older version of the rule active.
		if loading {
			delete(pending, key)
		} else {
			s.Store.DeleteDynamic(key)
		}
		return
	}

	if loading {
		pending[key] = r
		return
	}
	if err := s.Store.PutDynamic(key, r); err != nil {
		s.Log.Warn("dropped dynamic rule", "key", key, "error", err)
		if s.Rejected != nil {
			s.Rejected("limit")
		}
	}
}

func (s *Syncer) synced() {
	if s.Synced != nil {
		s.Synced(time.Now())
	}
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, rules.ErrNoTTL):
		return "no_ttl"
	case errors.Is(err, rules.ErrTTLTooLong):
		return "ttl_too_long"
	case errors.Is(err, rules.ErrExpired):
		return "expired"
	case errors.Is(err, rules.ErrDynamicAllow):
		return "dynamic_allow"
	case errors.Is(err, rules.ErrTooBroad):
		return "too_broad"
	default:
		return "invalid"
	}
}

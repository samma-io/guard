// Package baseline loads the reviewed rules shipped in a ConfigMap.
//
// The file is JSON: {"rules": [ {rule}, ... ]}. Every rule must be valid or
// the whole file is rejected, so a typo never silently drops an allowlist.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/samma-io/guard/internal/rules"
)

type file struct {
	Rules []json.RawMessage `json:"rules"`
}

// Load reads and validates the baseline file.
func Load(path string, now time.Time) ([]*rules.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, now)
}

// Parse validates baseline content.
func Parse(data []byte, now time.Time) ([]*rules.Rule, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	out := make([]*rules.Rule, 0, len(f.Rules))
	seen := map[string]bool{}
	for i, raw := range f.Rules {
		r, err := rules.Parse(raw, rules.OriginBaseline, rules.Limits{}, now)
		if err != nil {
			return nil, fmt.Errorf("baseline rule %d: %w", i, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("baseline rule %d: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out, nil
}

// Watch reloads the file when its modification time changes. Kubernetes
// updates mounted ConfigMaps by swapping a symlink, which changes the mtime
// seen through the mount path. A bad file is reported and the previous rules
// are kept.
func Watch(path string, every time.Duration, stop <-chan struct{}, apply func([]*rules.Rule), report func(error)) {
	var last time.Time
	if st, err := os.Stat(path); err == nil {
		last = st.ModTime()
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			st, err := os.Stat(path)
			if err != nil || st.ModTime().Equal(last) {
				continue
			}
			last = st.ModTime()
			rs, err := Load(path, time.Now())
			if err != nil {
				report(err)
				continue
			}
			apply(rs)
		}
	}
}

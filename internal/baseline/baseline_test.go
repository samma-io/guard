package baseline

import (
	"testing"
	"time"
)

func TestExampleBaseline(t *testing.T) {
	rs, err := Load("../../examples/baseline.json", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 {
		t.Fatalf("got %d rules", len(rs))
	}
}

func TestRejectsDuplicatesAndBadRules(t *testing.T) {
	for _, js := range []string{
		`{"rules":[{"id":"a","kind":"ip","match":"1.2.3.4"},{"id":"a","kind":"ip","match":"1.2.3.5"}]}`,
		`{"rules":[{"id":"a","kind":"ip","match":"nope"}]}`,
	} {
		if _, err := Parse([]byte(js), time.Now()); err == nil {
			t.Errorf("accepted %s", js)
		}
	}
}

package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)

func mustRule(t *testing.T, origin Origin, js string) *Rule {
	t.Helper()
	r, err := Parse([]byte(js), origin, DefaultLimits, now)
	if err != nil {
		t.Fatalf("parse %s: %v", js, err)
	}
	return r
}

func exp(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }

func req(ip, host, path, ua string) Request {
	r := Request{Host: host, Path: path, UA: ua}
	if ip != "" {
		r.IP = netip.MustParseAddr(ip)
	}
	return r
}

func TestDynamicValidation(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want error
	}{
		{"no ttl", `{"id":"a","kind":"ip","match":"1.2.3.4","action":"block"}`, ErrNoTTL},
		{"ttl too long", `{"id":"a","kind":"ip","match":"1.2.3.4","action":"block","expires":"` + exp(30*24*time.Hour) + `"}`, ErrTTLTooLong},
		{"expired", `{"id":"a","kind":"ip","match":"1.2.3.4","action":"block","expires":"` + exp(-time.Minute) + `"}`, ErrExpired},
		{"dynamic allow", `{"id":"a","kind":"ip","match":"1.2.3.4","action":"allow","expires":"` + exp(time.Hour) + `"}`, ErrDynamicAllow},
		{"too broad v4", `{"id":"a","kind":"cidr","match":"10.0.0.0/8","action":"block","expires":"` + exp(time.Hour) + `"}`, ErrTooBroad},
		{"too broad v6", `{"id":"a","kind":"cidr","match":"2001:db8::/16","action":"block","expires":"` + exp(time.Hour) + `"}`, ErrTooBroad},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.js), OriginDynamic, DefaultLimits, now)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	bad := []string{
		`{"id":"a","kind":"ip","match":"not-an-ip","expires":"` + exp(time.Hour) + `"}`,
		`{"id":"a","kind":"nope","match":"x","expires":"` + exp(time.Hour) + `"}`,
		`{"id":"","kind":"ip","match":"1.2.3.4","expires":"` + exp(time.Hour) + `"}`,
		`{"id":"a","kind":"path","match":"/admin","expires":"` + exp(time.Hour) + `"}`, // dynamic path without scope
		`{"id":"a","kind":"ip","match":"1.2.3.4","expires":"` + exp(time.Hour) + `","extra":1}`,
	}
	for i, js := range bad {
		if _, err := Parse([]byte(js), OriginDynamic, DefaultLimits, now); err == nil {
			t.Errorf("bad rule %d accepted", i)
		}
	}
}

func TestBaselineAllowsPermanentAndAllow(t *testing.T) {
	mustRule(t, OriginBaseline, `{"id":"own","kind":"cidr","match":"10.0.0.0/8","action":"allow"}`)
	mustRule(t, OriginBaseline, `{"id":"b","kind":"path","match":"/wp-login.php"}`)
}

func TestPrecedence(t *testing.T) {
	h := exp(time.Hour)
	rs := Build([]*Rule{
		mustRule(t, OriginBaseline, `{"id":"office","kind":"cidr","match":"198.51.100.0/24","action":"allow"}`),
		mustRule(t, OriginDynamic, `{"id":"office-attack","kind":"ip","match":"198.51.100.7","action":"block","expires":"`+h+`"}`),
		mustRule(t, OriginDynamic, `{"id":"bad-ip","kind":"ip","match":"203.0.113.44","action":"block","expires":"`+h+`"}`),
		mustRule(t, OriginDynamic, `{"id":"bad-net","kind":"cidr","match":"203.0.113.0/24","action":"block","expires":"`+h+`"}`),
		mustRule(t, OriginDynamic, `{"id":"dry","kind":"cidr","match":"192.0.2.0/24","action":"log","expires":"`+h+`"}`),
		mustRule(t, OriginBaseline, `{"id":"wp","kind":"path","match":"/wp-login.php","action":"block"}`),
		mustRule(t, OriginDynamic, `{"id":"api-admin","kind":"path","match":"/admin","action":"block","scope":{"hosts":["api.example.com"]},"expires":"`+h+`"}`),
		mustRule(t, OriginDynamic, `{"id":"scanner","kind":"ua","match":"sqlmap","action":"block","scope":{"hosts":["api.example.com"]},"expires":"`+h+`"}`),
	})

	cases := []struct {
		name    string
		r       Request
		verdict Verdict
		rule    string
	}{
		{"baseline allow beats dynamic block", req("198.51.100.7", "x", "/", ""), VerdictAllow, "office"},
		{"exact ip beats cidr", req("203.0.113.44", "x", "/", ""), VerdictBlock, "bad-ip"},
		{"cidr", req("203.0.113.9", "x", "/", ""), VerdictBlock, "bad-net"},
		{"log rule allows", req("192.0.2.5", "x", "/", ""), VerdictLog, "dry"},
		{"path everywhere", req("8.8.8.8", "shop.example.com", "/wp-login.php", ""), VerdictBlock, "wp"},
		{"scoped path in scope", req("8.8.8.8", "api.example.com", "/admin/users", ""), VerdictBlock, "api-admin"},
		{"scoped path out of scope", req("8.8.8.8", "shop.example.com", "/admin/users", ""), VerdictAllow, ""},
		{"ua", req("8.8.8.8", "api.example.com", "/", "sqlmap/1.7"), VerdictBlock, "scanner"},
		{"default allow", req("8.8.8.8", "api.example.com", "/", "curl/8"), VerdictAllow, ""},
		{"no ip still checks path", req("", "x", "/wp-login.php", ""), VerdictBlock, "wp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := rs.Evaluate(c.r, now)
			got := ""
			if d.Rule != nil {
				got = d.Rule.ID
			}
			if d.Verdict != c.verdict || got != c.rule {
				t.Fatalf("got %s/%s, want %s/%s", d.Verdict, got, c.verdict, c.rule)
			}
		})
	}
}

func TestExpiryIgnoredAtLookup(t *testing.T) {
	r := mustRule(t, OriginDynamic, `{"id":"x","kind":"ip","match":"203.0.113.1","action":"block","expires":"`+exp(time.Minute)+`"}`)
	rs := Build([]*Rule{r})
	if d := rs.Evaluate(req("203.0.113.1", "", "", ""), now); d.Verdict != VerdictBlock {
		t.Fatal("should block before expiry")
	}
	if d := rs.Evaluate(req("203.0.113.1", "", "", ""), now.Add(2*time.Minute)); d.Verdict != VerdictAllow {
		t.Fatal("should allow after expiry")
	}
}

func TestIPv6AndMapped(t *testing.T) {
	h := exp(time.Hour)
	rs := Build([]*Rule{
		mustRule(t, OriginDynamic, `{"id":"v6","kind":"cidr","match":"2001:db8:1::/48","action":"block","expires":"`+h+`"}`),
		mustRule(t, OriginDynamic, `{"id":"v4","kind":"ip","match":"203.0.113.5","action":"block","expires":"`+h+`"}`),
	})
	if d := rs.Evaluate(req("2001:db8:1:2::9", "", "", ""), now); d.Verdict != VerdictBlock {
		t.Fatal("v6 prefix not matched")
	}
	if d := rs.Evaluate(req("::ffff:203.0.113.5", "", "", ""), now); d.Verdict != VerdictBlock {
		t.Fatal("v4-mapped address not matched")
	}
}

func BenchmarkEvaluate(b *testing.B) {
	h := now.Add(time.Hour)
	var all []*Rule
	for i := 0; i < 50000; i++ {
		r := &Rule{ID: fmt.Sprint(i), Kind: KindIP, Match: fmt.Sprintf("100.%d.%d.%d", i>>16&255, i>>8&255, i&255), Action: ActionBlock, Expires: &h, Origin: OriginDynamic}
		if err := r.Normalize(DefaultLimits, now); err != nil {
			b.Fatal(err)
		}
		all = append(all, r)
	}
	for i := 0; i < 2000; i++ {
		r := &Rule{ID: fmt.Sprint("c", i), Kind: KindCIDR, Match: fmt.Sprintf("101.%d.%d.0/24", i>>8&255, i&255), Action: ActionBlock, Expires: &h, Origin: OriginDynamic}
		if err := r.Normalize(DefaultLimits, now); err != nil {
			b.Fatal(err)
		}
		all = append(all, r)
	}
	rs := Build(all)
	q := req("8.8.8.8", "api.example.com", "/v1/users", "mozilla/5.0")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.Evaluate(q, now)
	}
}

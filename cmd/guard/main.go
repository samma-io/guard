// Command guard is the Traffic Guard decision service.
//
// Traefik's forwardAuth middleware calls GET /check for every request on a
// protected ingress. Guard answers 200 (allow) or 403 (block) from an
// in-memory rule set built from a baseline file and a NATS JetStream KV bucket.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/samma-io/guard/internal/audit"
	"github.com/samma-io/guard/internal/baseline"
	"github.com/samma-io/guard/internal/metrics"
	"github.com/samma-io/guard/internal/natssync"
	"github.com/samma-io/guard/internal/rules"
	"github.com/samma-io/guard/internal/server"
	"github.com/samma-io/guard/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type config struct {
	listen, metricsListen string
	baselineFile          string
	natsEnabled           bool
	natsURL, natsCreds    string
	bucket, auditSubject  string
	auditWindow           time.Duration
	trusted               []netip.Prefix
	limits                rules.Limits
	maxDynamic            int
	debounce, sweep       time.Duration
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func loadConfig() (config, error) {
	c := config{
		listen:        env("LISTEN_ADDR", ":8081"),
		metricsListen: env("METRICS_ADDR", ":9090"),
		baselineFile:  env("BASELINE_FILE", "/etc/guard/baseline.json"),
		natsURL:       env("NATS_URL", "nats://nats.nats.svc.cluster.local:4222"),
		natsCreds:     env("NATS_CREDS", ""),
		bucket:        env("NATS_KV_BUCKET", "samma-guard-rules"),
		auditSubject:  env("NATS_AUDIT_SUBJECT", "samma-io.guard.audit"),
		limits:        rules.DefaultLimits,
	}
	var err error
	if c.natsEnabled, err = strconv.ParseBool(env("NATS_ENABLED", "true")); err != nil {
		return c, fmt.Errorf("NATS_ENABLED: %w", err)
	}
	durs := []struct {
		key string
		def string
		dst *time.Duration
	}{
		{"AUDIT_WINDOW", "60s", &c.auditWindow},
		{"MAX_TTL", "168h", &c.limits.MaxTTL},
		{"REBUILD_DEBOUNCE", "100ms", &c.debounce},
		{"EXPIRY_SWEEP", "30s", &c.sweep},
	}
	for _, d := range durs {
		if *d.dst, err = time.ParseDuration(env(d.key, d.def)); err != nil {
			return c, fmt.Errorf("%s: %w", d.key, err)
		}
	}
	ints := []struct {
		key string
		def string
		dst *int
	}{
		{"MIN_PREFIX_V4", "16", &c.limits.MinPrefixV4},
		{"MIN_PREFIX_V6", "32", &c.limits.MinPrefixV6},
		{"MAX_DYNAMIC_RULES", "100000", &c.maxDynamic},
	}
	for _, d := range ints {
		if *d.dst, err = strconv.Atoi(env(d.key, d.def)); err != nil {
			return c, fmt.Errorf("%s: %w", d.key, err)
		}
	}
	for _, s := range strings.Split(env("TRUSTED_PROXIES", ""), ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return c, fmt.Errorf("TRUSTED_PROXIES %q: %w", s, err)
		}
		c.trusted = append(c.trusted, p.Masked())
	}
	return c, nil
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level()}))
	if err := run(log); err != nil {
		log.Error("guard stopped", "error", err)
		os.Exit(1)
	}
}

func level() slog.Level {
	var l slog.Level
	_ = l.UnmarshalText([]byte(env("LOG_LEVEL", "info")))
	return l
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	reg := metrics.New()
	st := store.New(cfg.maxDynamic, cfg.debounce)
	st.OnRebuild = func(rs *rules.RuleSet) {
		reg.Rules(rs.Count(rules.OriginBaseline), rs.Count(rules.OriginDynamic))
	}

	// Baseline first. A broken baseline is fatal at start: better to stay
	// unready than to run without the allowlist.
	base, err := baseline.Load(cfg.baselineFile, time.Now())
	switch {
	case errors.Is(err, os.ErrNotExist):
		log.Warn("no baseline file, starting with no baseline rules", "path", cfg.baselineFile)
	case err != nil:
		return fmt.Errorf("baseline: %w", err)
	default:
		st.SetBaseline(base)
		log.Info("baseline loaded", "rules", len(base))
	}
	go baseline.Watch(cfg.baselineFile, 10*time.Second, ctx.Done(),
		func(rs []*rules.Rule) { st.SetBaseline(rs); log.Info("baseline reloaded", "rules", len(rs)) },
		func(err error) { log.Error("baseline reload failed, keeping previous rules", "error", err) })
	go st.Run(ctx, cfg.sweep)

	ready := &atomic.Bool{}
	var pub audit.Publisher

	if cfg.natsEnabled {
		nc, err := connectNATS(cfg, log, reg)
		if err != nil {
			return err
		}
		defer nc.Drain()
		pub = nc

		js, err := jetstream.New(nc)
		if err != nil {
			return fmt.Errorf("jetstream: %w", err)
		}
		kv, err := js.KeyValue(ctx, cfg.bucket)
		if err != nil {
			return fmt.Errorf("kv bucket %q: %w", cfg.bucket, err)
		}
		initial := make(chan struct{})
		sy := &natssync.Syncer{
			KV: kv, Store: st, Limits: cfg.limits, Log: log,
			Rejected: reg.Rejected, Synced: reg.Synced,
		}
		go func() {
			if err := sy.Run(ctx, initial); err != nil {
				log.Error("rule sync stopped", "error", err)
				cancel()
			}
		}()
		go func() {
			select {
			case <-initial:
				ready.Store(true)
				reg.Ready(true)
			case <-ctx.Done():
			}
		}()
	} else {
		log.Warn("NATS disabled, serving baseline rules only")
		ready.Store(true)
		reg.Ready(true)
	}

	aud := audit.New(pub, cfg.auditSubject, cfg.auditWindow, reg.Audit)
	go aud.Run(ctx.Done())

	srv := &server.Server{Store: st, Audit: aud, Metrics: reg, TrustedProxies: cfg.trusted, Ready: ready}
	api := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", reg)
	met := &http.Server{Addr: cfg.metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() { errc <- api.ListenAndServe() }()
	go func() { errc <- met.ListenAndServe() }()
	log.Info("guard listening", "version", version, "addr", cfg.listen, "metrics", cfg.metricsListen, "nats", cfg.natsEnabled)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			cancel()
			return err
		}
	}
	// Stop taking traffic first so Traefik moves to other replicas.
	ready.Store(false)
	reg.Ready(false)
	sh, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	_ = api.Shutdown(sh)
	_ = met.Shutdown(sh)
	return nil
}

func connectNATS(cfg config, log *slog.Logger, reg *metrics.Registry) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("samma-guard"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			reg.NATSUp(false)
			log.Warn("nats disconnected, keeping last good rules", "error", err)
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			reg.NATSUp(true)
			log.Info("nats reconnected", "url", c.ConnectedUrlRedacted())
		}),
	}
	if cfg.natsCreds != "" {
		opts = append(opts, nats.UserCredentials(cfg.natsCreds))
	}
	nc, err := nats.Connect(cfg.natsURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	reg.NATSUp(true)
	return nc, nil
}

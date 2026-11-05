# guard: block bad traffic at the Traefik ingress

Traffic Guard is a small Go service that Traefik asks, for every request on a
protected ingress, whether to let it through. It answers `200` (allow) or
`403` (block) from rules held in memory. Rules come from two places:

- **Baseline**: reviewed rules in git, shipped as a ConfigMap. Allowlists live
  here and only here.
- **Live rules**: pushed by the detection platform into a NATS JetStream KV
  bucket. Every guard replica watches the bucket, so a new block is active
  everywhere within about a second.

It is part of [Samma](https://github.com/samma-io/guide): the scanners in
[detect](https://github.com/samma-io/detect) find problems, guard acts on them.

```
client ─► LB ─► Traefik ──GET /check──► guard (×3) ◄── watch ── NATS KV samma-guard-rules ◄── detection
                   │   ◄── 200 / 403 ───     │                                 
                   ▼                         └── block events ──► samma-io.guard.audit
               your app
```

---

## Turn it on for an ingress

Install the chart, then add one annotation to any Ingress you want protected:

```yaml
metadata:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: traefik-guard@kubernetescrd
```

Ingresses without the annotation are not affected.

```bash
helm install guard charts/guard -n guard-system --create-namespace \
  --set nats.url=nats://nats.nats.svc.cluster.local:4222 \
  --set nats.credsSecret=guard-nats
```

### Get the real client IP right

Guard blocks on the client IP, so Traefik must see it. Either set
`externalTrafficPolicy: Local` on the Traefik Service or use PROXY protocol on
the load balancer, and configure Traefik's `forwardedHeaders.trustedIPs` for
your LB. Guard takes the **rightmost** `X-Forwarded-For` entry that is not in
`trustedProxies`; entries further left come from the client and are never
trusted.

---

## Rules

One JSON document per rule. In the KV bucket the key is `<kind>.<id>`, for
example `ip.8f2c`; deleting the key removes the rule.

```json
{
  "id": "8f2c",
  "kind": "ip",
  "match": "203.0.113.44",
  "action": "block",
  "scope": { "hosts": ["api.example.com"] },
  "reason": "credential stuffing, 412 failed logins in 5 min",
  "source": "detection/auth-anomaly",
  "created": "2026-11-05T09:20:00Z",
  "expires": "2026-11-06T09:20:00Z"
}
```

| Field | Values |
|---|---|
| `kind` | `ip`, `cidr`, `host`, `path` (prefix, decoded and cleaned so `/%61dmin` and `/x/../admin` match `/admin`), `ua` (case-insensitive substring) |
| `action` | `block` (default), `log` (dry run: allow but audit), `allow` (baseline only) |
| `scope.hosts` | limit the rule to these hosts; empty means every protected ingress |
| `expires` | required for live rules |

### Precedence

1. Any matching **allow** rule wins. Allow rules only exist in the baseline,
   so detection can never block your own ranges or monitors.
2. Otherwise the most specific **block** wins: exact IP, then CIDR (longest
   prefix first), host, path (longest first), user agent.
3. A matching **log** rule allows the request and writes an audit event.
4. No match allows.

### What live rules may not do

Guard refuses a rule from NATS (and counts it in
`guard_rules_rejected_total{reason}`) when it:

- has no `expires`, or expires further out than `MAX_TTL` (default 7 days)
- uses `action: allow`
- blocks a CIDR broader than `/16` (IPv4) or `/32` (IPv6)
- is a `path` or `ua` rule without `scope.hosts`
- has unknown fields or is malformed

A refused update also removes any earlier version of the same key, so a bad
write never leaves a stale rule in force. Permanent rules belong in the
baseline, where they get a review.

Block an IP by hand:

```bash
./examples/block.sh 203.0.113.44 2h "credential stuffing" manual/mattias
```

---

## Behaviour when things break

| Situation | What happens |
|---|---|
| guard unreachable | Traefik returns an error to the client (fail closed). Run 3 replicas; the chart sets a PDB and spreads pods across nodes. |
| NATS unreachable | guard keeps serving the last good rules, reconnects on its own, `guard_nats_connected` drops to 0. |
| Pod starting | not ready until the baseline and the full KV bucket are loaded, so Traefik never routes to a pod with half the rules. |
| Bad baseline on reload | logged, previous baseline kept. A bad baseline at start stops the pod. |
| Rule expires | ignored at lookup immediately, removed in the next sweep (30 s). |

---

## Audit

Every block (and every `log` match) publishes an event to
`samma-io.guard.audit`. The client gets the same `ref` in the `X-Guard-Ref`
response header, so a support ticket can be traced to the rule. Events are
deduplicated per rule and IP within `AUDIT_WINDOW`; the next event carries a
`suppressed` count.

```json
{"time":"2026-11-05T08:32:41Z","ref":"9b6b630cc9b1a3e2","verdict":"block","rule_id":"pre","kind":"ip","origin":"dynamic","source":"detection/auth-anomaly","ip":"203.0.113.10","host":"api.example.com","path":"/login","method":"POST","ua":"python-requests/2.32"}
```

---

## Configuration

| Env | Default | |
|---|---|---|
| `LISTEN_ADDR` | `:8081` | `/check`, `/healthz`, `/readyz` |
| `METRICS_ADDR` | `:9090` | `/metrics` (Prometheus) |
| `BASELINE_FILE` | `/etc/guard/baseline.json` | `{"rules":[...]}`, reloaded on change |
| `NATS_ENABLED` | `true` | `false` serves baseline only |
| `NATS_URL` | `nats://nats.nats.svc.cluster.local:4222` | |
| `NATS_CREDS` | | path to a `.creds` file |
| `NATS_KV_BUCKET` | `samma-guard-rules` | |
| `NATS_AUDIT_SUBJECT` | `samma-io.guard.audit` | |
| `TRUSTED_PROXIES` | | CIDRs to skip in `X-Forwarded-For` |
| `MAX_TTL` | `168h` | |
| `MIN_PREFIX_V4` / `MIN_PREFIX_V6` | `16` / `32` | |
| `MAX_DYNAMIC_RULES` | `100000` | |
| `AUDIT_WINDOW` | `60s` | |
| `LOG_LEVEL` | `info` | |

NATS users and permissions: [deploy/nats-permissions.md](deploy/nats-permissions.md).

## Metrics

`guard_decisions_total{verdict,kind}`, `guard_check_duration_seconds`,
`guard_rules{origin}`, `guard_rules_rejected_total{reason}`,
`guard_audit_events_total{result}`, `guard_sync_last_update_timestamp_seconds`,
`guard_nats_connected`, `guard_ready`.

---

## Develop

```bash
go test -race ./...
go test -run x -bench . -benchmem ./internal/rules/   # ~65 ns/lookup, 0 allocs, 52k rules
docker build -t guard .
```

Run locally against NATS:

```bash
nats-server -js &
nats kv add samma-guard-rules --history 5
BASELINE_FILE=./examples/baseline.json go run ./cmd/guard
curl -i -H 'X-Forwarded-For: 203.0.113.44' localhost:8081/check
```

The chart needs Kubernetes 1.30 or later (it uses the `sleep` preStop action)
and Traefik v3 CRDs (`traefik.io/v1alpha1`).

Images: `ghcr.io/samma-io/guard:latest` on every push to `main`,
`sha-<short>` per commit, and the version on `v*` tags.

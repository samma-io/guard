# NATS accounts and permissions

Rules in `samma-guard-rules` decide who can reach your services, so treat
write access to the bucket as a control plane.

## Create the bucket

```bash
nats kv add samma-guard-rules --history 5 --replicas 3
```

## Users

| User | Needs | Must not |
|---|---|---|
| `guard` | read the bucket, publish audit events | write rules |
| `detection` | put and delete keys in the bucket | read audit, touch other buckets |

Example (nsc / operator mode), subjects as JetStream uses them for a KV bucket:

```bash
# guard: watch the bucket and publish audit
nsc add user guard \
  --allow-pub '$JS.API.STREAM.INFO.KV_samma-guard-rules' \
  --allow-pub '$JS.API.CONSUMER.CREATE.KV_samma-guard-rules.>' \
  --allow-pub '$JS.API.CONSUMER.DELETE.KV_samma-guard-rules.>' \
  --allow-pub '$JS.FC.KV_samma-guard-rules.>' \
  --allow-pub 'samma-io.guard.audit' \
  --allow-sub '_INBOX.>'

# detection: write rules only
nsc add user detection \
  --allow-pub '$KV.samma-guard-rules.>' \
  --allow-pub '$JS.API.STREAM.INFO.KV_samma-guard-rules' \
  --allow-sub '_INBOX.>'
```

Export the guard creds into the cluster:

```bash
kubectl -n guard-system create secret generic guard-nats \
  --from-file=guard.creds=./guard.creds
```

and set `nats.credsSecret: guard-nats` in the chart values.

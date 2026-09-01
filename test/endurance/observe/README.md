# Watching a soak

Prometheus scrapes the soak server and Grafana draws it.

```
bash test/endurance/run.sh &
bash test/endurance/observe/up.sh
```

`up.sh` prints the dashboard address. Grafana listens on every interface at
port 3000, so another machine on the network reaches it.

The soak creates `dims-soak-net` and gives its server the alias `dims`, so
this stack joins that network and scrapes `dims:8001`. Start the soak first.

`run.sh` sets `DIMS_METRICS_ENABLED=on`, so a run publishes its metrics with
no further setting.

## The dashboard

Six sections, from the top.

**Overview** reports the request rate, the error ratio, the p99 latency,
requests in flight, resident memory, and ready workers.

**Request path** breaks the rate down by outcome, by status code, and by
endpoint, with the latency quantiles beside them.

**Source fetch** separates a slow origin from a broken one. The libcurl code
panel tells DNS from TLS from a reset connection, and the origin status panel
reports what the origin returned.

**Image processing** answers which command spends the time. The mean seconds
per call panel is the one that names an expensive operation, because a
watermark fetches an overlay and a resize does not. The exception panel splits
ImageMagick failures by kind: `resource_limit` is the pixel cache reaching a
ceiling, `corrupt_image` is a bad source, and `policy` is `policy.xml`
refusing a coder.

**Guard and signature** reports what the network guard refused and why, the
allowlist checks by mode, and the signature results. Under
`DimsAllowlistSigned log` the refused line is what `enforce` would reject.

**Resources** puts ImageMagick use beside its limit, so the ratio is visible.
The process memory panel is the one a soak watches for a trend.

## Stopping it

```
docker compose -f test/endurance/observe/compose.yaml down
```

Prometheus keeps 24 hours and stores it in the container, so removing the
container drops the history.

## Anonymous access

Grafana runs with the login form off and anonymous viewing on. It reads a
local soak and holds nothing worth protecting. A deployment that reaches
further sets `GF_AUTH_ANONYMOUS_ENABLED=false` in `compose.yaml`.

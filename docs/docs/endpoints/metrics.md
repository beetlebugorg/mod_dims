# /metrics

```
/metrics
```

Reports the module, ImageMagick, and httpd in the Prometheus text format. A
Prometheus server scrapes it, and so does an OpenTelemetry Collector through
its `prometheus` receiver.

Two lines turn it on. The directive is the switch, and the location names the
path.

```apacheconf
DimsMetricsEnabled on

<Location /metrics>
    SetHandler dims-metrics
</Location>
```

[`DimsMetricsEnabled`](/configuration/metrics) defaults to `Off`, so a server
that upgrades publishes no metrics until an operator turns it on.

## What it reports

```
# HELP dims_requests_total Requests by endpoint and outcome.
# TYPE dims_requests_total counter
dims_requests_total{endpoint="dims5",outcome="success"} 18423
dims_requests_total{endpoint="dims5",outcome="download_timeout"} 4

# HELP dims_request_duration_seconds Time to serve a request.
# TYPE dims_request_duration_seconds histogram
dims_request_duration_seconds_bucket{endpoint="dims5",le="0.025"} 17155
dims_request_duration_seconds_bucket{endpoint="dims5",le="+Inf"} 18427
dims_request_duration_seconds_sum{endpoint="dims5"} 314.288000
dims_request_duration_seconds_count{endpoint="dims5"} 18427
```

| Metric | Type | Labels |
|---|---|---|
| `dims_requests_total` | counter | `endpoint`, `outcome` |
| `dims_responses_total` | counter | `endpoint`, `code` |
| `dims_requests_in_flight` | gauge | `endpoint` |
| `dims_request_duration_seconds` | histogram | `endpoint` |
| `dims_source_fetch_duration_seconds` | histogram | |
| `dims_source_bytes` | histogram | |
| `dims_source_bytes_total` | counter | |
| `dims_source_format_total` | counter | `format` |
| `dims_origin_responses_total` | counter | `code` |
| `dims_imagemagick_duration_seconds` | histogram | |
| `dims_source_frames` | histogram | |
| `dims_output_bytes` | histogram | |
| `dims_output_bytes_total` | counter | |
| `dims_output_format_total` | counter | `format` |
| `dims_imagemagick_resource_bytes` | gauge | `resource` |
| `dims_imagemagick_resource_max_bytes` | gauge | `resource` |
| `dims_imagemagick_resource_limit_bytes` | gauge | `resource` |
| `dims_process_resident_bytes` | gauge | |
| `dims_process_resident_max_bytes` | gauge | |
| `dims_process_virtual_bytes` | gauge | |
| `dims_workers` | gauge | |
| `dims_httpd_workers` | gauge | `state` |
| `dims_httpd_processes` | gauge | |
| `dims_httpd_processes_limit` | gauge | |
| `dims_httpd_threads_per_process` | gauge | |
| `dims_httpd_connections` | gauge | `state` |
| `dims_httpd_generation` | gauge | |

`endpoint` holds `dims3`, `dims4`, `dims5`, or `local`.

`outcome` holds `success`, `failure`, `download_timeout`,
`imagemagick_timeout`, `bad_client`, `bad_url`, `bad_arguments`,
`hostname_not_in_whitelist`, `file_not_found`, or `network_refused`.

`code` holds `200`, `400`, `403`, `404`, `429`, `500`, `502`, `503`, `504`, or
`other`. The list bounds the label, because
[`DimsOriginStatusMode`](/configuration/cache-control) `forward` reports the
status the origin returned.

`format` holds `jpeg`, `png`, `gif`, `webp`, `avif`, `heic`, `tiff`, `svg`, or
`other`.

`resource` holds `area`, `memory`, `map`, or `disk`.

## The whole server

Every metric describes the server, with no `client` label. The client id is a
legacy of `/dims3/` and `/dims4/`, and `/dims5/` dropped it.

A deployment that serves several clients gives each its own `<VirtualHost>`,
which separates the clients, the allowlist, and the keys. The counters stay
shared, because the module creates one block for the process. Separate metrics
need separate instances.

## Per process and per server

Most metrics come from a block every worker adds to, so they describe the whole
server.

`dims_imagemagick_resource_bytes`, `dims_process_resident_bytes`, and
`dims_process_virtual_bytes` are per worker. Each child writes its own numbers
when a request ends, and this endpoint sums the live workers. The matching
`_max_bytes` gauge reports the widest single worker, so one worker at its
ceiling is visible beside three idle ones. `dims_workers` counts the workers in
the sum.

`dims_process_resident_bytes` and `dims_process_virtual_bytes` read
`/proc/self/statm`. A platform without it omits both.

## Kubernetes

The container serves images on 8000 and metrics on 8001, so a Service exposes
8000 and a scrape targets 8001.

```shell
docker run -p 8000:8000 -p 8001:8001 -e DIMS_METRICS_ENABLED=on \
  ghcr.io/beetlebugorg/mod_dims:latest
```

An OpenTelemetry Collector reads it through the `prometheus` receiver:

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: mod_dims
          static_configs:
            - targets: ['mod-dims:8001']
```

## Worker headroom

`dims_httpd_workers{state="ready"}` against `dims_httpd_processes_limit` times
`dims_httpd_threads_per_process` is the headroom the pool has left. Ready
workers near zero while `dims_requests_in_flight` climbs means the pool is
full.

:::note
`dims_build_info` names the mod_dims, ImageMagick, and libcurl versions.
[`DimsStatusVerbose`](/configuration/output) `Off` drops it, the same way it
drops the version lines from [`/dims-status/`](/endpoints/status).
:::

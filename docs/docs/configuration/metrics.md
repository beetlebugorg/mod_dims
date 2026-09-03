# Metrics

## DimsMetricsEnabled

```apacheconf
DimsMetricsEnabled on
```

Whether the module serves [`/metrics`](/endpoints/metrics). Default `Off`.

The directive is the switch, and a `<Location>` names the path. Both are
needed:

```apacheconf
DimsMetricsEnabled on

<Location /metrics>
    SetHandler dims-metrics
</Location>
```

With the directive `Off` the handler declines the request and httpd answers
404, so a configuration that keeps the location stops publishing when the
directive goes off.

The container reads `DIMS_METRICS_ENABLED`. The image sets it to `off`. It
serves metrics on port 8001.

:::note
The endpoint reports the counters, the uptime, and the library versions. Serve
it on a port your callers cannot reach, or restrict the location to your
monitoring host. `DimsStatusVerbose Off` drops the version labels.
:::

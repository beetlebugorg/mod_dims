# Soak test

This directory finds the Apache worker configuration that gives the most
throughput on a fixed CPU and memory budget with no failures. It is an
operational tool. It is not part of `make test`, and nothing in the module or
the C test harness depends on it.

## What it does

`run.sh` runs the production server image under a hard CPU and memory limit,
drives it with a mix of resize, crop, thumbnail, format, strip, and watermark
requests, and sweeps the Apache MPM sizing. For each configuration it records
throughput, tail latency, HTTP errors, socket errors, peak memory, and the
kernel OOM-kill count.

The images are three sizes of one pexels photo, downloaded once and served from
a local origin. The load generator is `wrk`, built in a throwaway image. `wrk`
is never a module or test dependency and never ships in the server image.

## Requirements

- Docker.
- Internet on the first run, to download the pexels images and build `wrk`.
  Later runs reuse both.

## Run

```
bash test/soak/run.sh
```

Environment variables tune the run:

- `CPUS`, `MEM` — the container limits. Default `2` and `1g`.
- `DUR`, `WARM` — the measure and warm-up time per point. Default `30s`, `10s`.
- `CONN`, `WT` — the wrk connection and thread count. Default `32`, `4`.
- `SOAK_GRID` — the sweep, a semicolon-separated list of `ServerLimit
  ThreadsPerChild` pairs, e.g. `SOAK_GRID="2 2;4 2"`.

Results print as a table and land in `results.tsv`.

## Read the table

- `req_s` — throughput. Higher is better.
- `p99_ms` — the 99th percentile latency under the offered load.
- `non2xx`, `sockerr` — request failures. A shipped configuration holds both at
  zero.
- `oom` — kernel OOM-kills. Any value above zero fails the configuration.
- `peak_MiB` — the peak container memory.

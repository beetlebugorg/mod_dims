# Resources

Every limit here is per process. httpd runs several, so the total a host may
use is the limit multiplied by the worker count.

## DimsDownloadTimeout

```apacheconf
DimsDownloadTimeout 3000
```

How long a source fetch may take, in milliseconds. Default 3000.

## DimsImagemagickTimeout

```apacheconf
DimsImagemagickTimeout 3000
```

How long the transformation may take, in milliseconds. Default 3000.

ImageMagick reports progress during an operation, and the request is abandoned
when the total passes this. It does not report progress while filling the pixel
cache, so a very large decode can run past it.

## DimsImagemagickMemorySize

```apacheconf
DimsImagemagickMemorySize 512
```

Megabytes of memory for the pixel cache. Default 512. Past this ImageMagick
maps a file instead.

## DimsImagemagickMapSize

```apacheconf
DimsImagemagickMapSize 1024
```

Megabytes of memory mapped file for the pixel cache. Default 1024. Past this
ImageMagick reads and writes the file directly.

## DimsImagemagickDiskSize

```apacheconf
DimsImagemagickDiskSize 2048
```

Megabytes of disk for the pixel cache. Default 2048. Past this the operation
fails.

## DimsImagemagickAreaSize

```apacheconf
DimsImagemagickAreaSize 128
```

Megabytes any single image may use. Default 128. An image larger than this is
cached on disk rather than in memory.

## Workers

The container sizes the httpd worker pool from its CPU allocation at start, so
a larger container scales without a change. Three environment variables control
it. Each one defaults to `auto`.

| Variable | Directive | Default |
| --- | --- | --- |
| DIMS_SERVER_LIMIT | ServerLimit | auto |
| DIMS_THREADS_PER_CHILD | ThreadsPerChild | auto |
| DIMS_MAX_WORKERS | MaxRequestWorkers | auto |

Image work is CPU-bound. A soak test on several container sizes found that
throughput peaks near one worker per vCPU and drops with more. Two threads per
child, split across processes, give the lowest tail latency, because two
processes share less ImageMagick lock state than one process with more threads.
One thread per child is slow: the single thread cannot both accept and process.

So `auto` sets `ThreadsPerChild` to 2 and `ServerLimit` to half the vCPU count,
at least 2. `MaxRequestWorkers` is their product. Set a variable to a number to
pin it. `DIMS_MAX_WORKERS` must equal `DIMS_SERVER_LIMIT` times
`DIMS_THREADS_PER_CHILD`.

| Container | ServerLimit | ThreadsPerChild | MaxRequestWorkers | Throughput |
| --- | --- | --- | --- | --- |
| 2 vCPU, 1 GB | 2 | 2 | 4 | 18 req/s |
| 4 vCPU, 2 GB | 2 | 2 | 4 | 35 req/s |
| 6 vCPU, 3 GB | 3 | 2 | 6 | 40 req/s |
| 8 vCPU, 4 GB | 4 | 2 | 8 | — |

The throughput is for a mixed resize, crop, format, and watermark load on full
size photos. A lighter load or a smaller source reaches a higher number. The 6
vCPU row is indicative, and the 8 vCPU row follows the rule, not a measurement,
because the test host has eight cores and the load generator needs some.

`DIMS_MAX_CONNECTIONS_PER_CHILD` recycles a child after that many connections,
which returns its memory to the system. The default is 10000. Set it to 0 to
keep a child for the life of the server.

## Choosing values

Each worker may hold as much pixel cache and disk as the limits above allow.
With the default four workers, four processes may each hold the memory limit at
once. Divide the memory the container has by the worker count from the Workers
section, and set the limits from that. At the worker counts above the memory is
not the limit; each optimum held under 250 MB, and CPU sets the rate.

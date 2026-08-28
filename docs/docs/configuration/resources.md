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

## DimsMaxInFlight

```apacheconf
DimsMaxInFlight 0
```

Largest number of requests in the image stage at once, across every worker.
Default 0, which means no limit.

The other limits here are per process. This one is server wide: every worker
adds to one counter. A request over the cap gets a 503 and does no image work,
so a burst sheds load rather than exhausting memory. Without a cap, the number
of requests decoding at once equals the worker count, and each one can hold a
full pixel cache.

Set it below the point where the concurrent pixel caches exceed the host
memory. The counter covers the fetch as well as the transform, so a slow origin
counts against it.

## Choosing values

With `ServerLimit 16` and the defaults, sixteen processes may each hold 512 MB
of pixel cache and write 2 GB to disk. Divide the memory a host has by the
worker count, and set the limits from that. `DimsMaxInFlight` puts a ceiling on
the concurrent requests directly, below the worker count when the per process
limits alone are not enough.

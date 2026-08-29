# The soak

This directory hammers mod_dims with signed requests for hours and reports
whether the module crashed, leaked memory, or answered a request in a way the
contract does not allow.

It is an operational tool. `make test` does not run it, and nothing in the
module or the C test harness depends on it.

`test/soak/` answers a different question: which Apache worker configuration
gives the most throughput. This one answers whether the module survives.

## What it does

It runs the production server image under a CPU and memory limit, serves
thousands of real files from a local origin, and sends signed `/dims3/`,
`/dims4/`, and `/dims5/` requests at it.

Each request is built from a seed. The generator picks the endpoint, the
source, a chain of one to six operations, an argument for each one, the query
parameters, and a mutation to apply after signing. A run with the same seed
sends the same requests, so a failure repeats.

Each request also carries the result it requires. The client compares the
response against it and records every mismatch.

## Requirements

- Docker.
- About 3 GB of disk for the corpus, and internet access the first time.

## Build the corpus

```
bash test/endurance/corpus.sh
```

The govdocs1 archives download in a few minutes. The Commons images take about
ten more, at one per second. Classifying the result takes a few minutes again.
The whole step is resumable: a second run adds only what is missing.

| Variable | Default | What it does |
|---|---|---|
| `GOVDOCS` | `4` | archives of a thousand real files each, about 450 MB apiece |
| `COMMONS` | `600` | individual images from Wikimedia Commons |
| `DERIVE` | `900` | re-encodings made on this machine |
| `MAX_BYTES` | `6291456` | the largest source to keep |
| `RATE` | `1` | seconds between downloads from Commons |

The corpus has four parts.

**govdocs1**, from digitalcorpora. Real files a US government website served:
PDF, PostScript, Word, Excel, PowerPoint, Flash, HTML, and text, along with
JPEG and GIF. Most of them are not images. A production service receives
files like these by accident, and it has to refuse each one without crashing.

**Wikimedia Commons**, for the formats govdocs1 is thin on: PNG, TIFF, WebP,
SVG, and animated GIF. Real files, so they hold header values a re-encoding
does not produce.

**Derived variants**, one per format and per feature the module reads: the
colour spaces, the bit depths, the alpha channel, the interlacing, and the
frame count.

**The generated set**: empty files, truncated streams, damaged payloads, files
under the wrong extension, an 8000 by 8000 image that is 100 KB on disk, a
300 frame GIF, and four SVGs, one of which points at an external resource.

Every file is classified by reading it through the ImageMagick the module runs,
under the policy the module ships, from a stream rather than a filename. The
module reads a fetched source the same way, so the class comes from a decode
and not from the extension.

Two cases the decode alone gets wrong, and the classifier corrects:

- A gzip, bzip2, xz, or zip container. `identify` writes its input to a file
  and unwraps it. The module reads the source as a blob and does not, so these
  are `reject`.
- An SVG holding a reference or a document type declaration. The SVG guard
  refuses it before the renderer sees it, and the decoder never complains, so
  these are `either`.

| Class | Meaning |
|---|---|
| `image` | it decodes, so a valid request must return an image |
| `reject` | it does not decode, so every request for it must fail |
| `either` | large, multi-frame, or a guarded SVG: both results are allowed |

## Run it

```
bash test/endurance/run.sh
```

| Variable | Default | What it does |
|---|---|---|
| `MODE` | `soak` | `soak`, `asan`, or `valgrind` |
| `DURATION` | `10800` | seconds, so three hours |
| `CONNECTIONS` | `16` | requests in flight |
| `CPUS`, `MEM` | `4`, `2g` | the container limits |
| `SEED` | the clock | set it to repeat a run exactly |
| `EURL` | `gcm` | how `/dims4/` encrypts `eurl`: `gcm`, `ecb`, or `none` |
| `INTERVAL` | `15` | seconds between memory samples |

Output lands in `runs/<timestamp>-<mode>/`: `report.txt`, `samples.tsv`,
`failures.ndjson`, `soak.log`, and `httpd.log`. All of it is ignored by git.

The run exits non-zero when a child crashed, the kernel killed one, or any
request failed its check.

### The modes

| Mode | What it answers |
|---|---|
| `soak` | Does the production image survive hours of traffic? Reports crashes and the memory trend. |
| `asan` | The module built with AddressSanitizer and UndefinedBehaviorSanitizer. A bad read reports where it happened, not hours later. |
| `valgrind` | One httpd process under memcheck, stopped with a signal so it reports the leaks at exit. |

`soak` runs the production image with production settings, with one change:
`DIMS_MAX_CONNECTIONS_PER_CHILD=0`. The production default recycles a child
after 10000 connections, which returns whatever it leaked to the system. That
is correct in production and it hides a leak here.

## Read the report

```
child crashes   0
httpd processes 3 at the start, 3 distinct over the run
oom kills       0
memory first    488 MiB resident
memory last     609 MiB resident
memory peak     2048 MiB in the cgroup
memory floor    +12.4 MiB/hour
```

`child crashes` counts `exit signal` in the httpd log. Any value above zero is
a defect. The line under it is the independent check: the worker pool is fixed
and a child is never recycled, so a count of distinct httpd processes above the
starting count means one was replaced. That reading comes from the samples, so
it holds even when the daemon rotated the log away.

`memory floor` is a straight line fitted to the least resident memory in each
15 minute window, and the report prints that series under it. The floor is the
right measure: a sample of resident memory swings by a gigabyte depending on
what a worker holds part way through a decode, and that swing buries a leak. A
leak raises the floor.

Read the series, not only the slope. A floor that is flat and then steps up
once is a high-water mark the allocator kept. A floor that climbs steadily is a
leak, and `MODE=valgrind` reports the allocation it came from.

The client's own counts follow:

```
soak requests          3184022
soak failures          0
soak failure.transport 0
soak failure.status    0
soak failure.empty-body 0
soak failure.not-an-image 0
soak failure.served-a-refusal 0
```

| Failure | Meaning |
|---|---|
| `transport` | the request did not finish: a reset, a timeout, or a partial body |
| `status` | a decodable source and a valid request did not return 2xx |
| `empty-body` | a 2xx with no body |
| `not-an-image` | a 2xx whose body is text, not an image |
| `served-a-refusal` | a request the module had to refuse was answered |

`failures.ndjson` holds one line per failure with the full URL, the command
chain, the source, and the mutation.

The mutation table follows. It counts the result of each mutation, because
some of them depend on a configuration setting:

```
mutation                 answered      refused
none                      2214880            0
flip-signature                  0        61204
six-signature               61180            0
upper-signature             61402            0
```

`flip-signature` refused every time, which is required. `six-signature` and
`upper-signature` were answered on `/dims4/`, which is what
`strncasecmp(hash, gen_hash, 6)` does. On `/dims5/` the same two are required
to be refused, and the client checks that.

## What it checks

Firm, and a failure when broken:

- A valid signature over a decodable source returns 2xx with an image body.
- A source the toolchain cannot decode is never answered with 2xx.
- A changed signature, a missing one, an expired request, an unknown client, a
  command chain rewritten after signing, and a source URL swapped after signing
  are never answered with 2xx.
- `/dims5/` refuses a truncated signature, an uppercased one, an added
  parameter, and a control character in a signed field.
- Reordering the query does not change the answer. Both endpoints look
  parameters up by name, and `/dims5/` sorts its canonical query.
- No request ends in a reset, a timeout, or a truncated body.

Counted and reported, because the answer depends on a setting:

- `/dims4/` with a signature truncated to six characters, or uppercased.
- `/dims4/` with a parameter added after signing.
- A duplicate `url` parameter.
- An expiry far in the future, which `DimsMaxExpiryPeriod` governs.
- An operation argument outside what it reads.

## Repeat a failure

The report prints the seed. Run again with it and the same corpus, and the
same requests go out in the same order:

```
SEED=1756500000 DURATION=600 bash test/endurance/run.sh
```

To look at the requests without sending any, the client prints them:

```
docker run --rm -v $PWD/test/endurance/corpus/manifest.tsv:/m.tsv:ro \
    mod-dims:soak-client --manifest /m.tsv --seed 1756500000 --dump 20
```

## What it does not do

It does not compare bytes. `make test` does that, against the golden files.
This checks that the module keeps answering correctly under load, not that a
given request produces a given image.

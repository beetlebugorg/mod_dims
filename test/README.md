# The mod_dims test harness

The harness records what mod_dims returns, byte for byte, and fails when that
changes. Every other change to the module depends on it.

## Running it

```
make test           # run the suite
make test-update    # rewrite the golden files, then run again
make test RUN=--run=TestResize
make test-shell     # a shell inside the service container
make down           # stop the services
```

Everything runs in Docker. The host needs no toolchain.

## What it is made of

| Path | What it holds |
|---|---|
| `compose.yaml` | two services: `dims` and `origin` |
| `Dockerfile` | builds ImageMagick 6, mod_dims, and the test binary |
| `conf/dims-test.conf` | the fixed configuration the golden files record |
| `conf/origin.conf` | the fixture origin, including its redirect and error endpoints |
| `origin/` | the fixture images |
| `golden/<env>/` | one file per case |
| `lib/` | the runner, the golden comparison, the signer, the request helper |
| `http/` | the cases |

## Design rules

**One language, no new runtime.** The harness is C. It links libcurl and
libcrypto, which the module already depends on.

**No network access.** The compose network is `internal`. The `origin` service
serves the fixtures. A case that reaches the internet is a bug in the case.

**Named assertions first.** A case asserts the properties it cares about, then
compares bytes. A width change reports `width: want 100, got 50`, not `bytes
differ`.

**A missing golden file is a failure.** It is never a silent pass. That is the
defect a missing baseline would otherwise become: a case that checks nothing.

**A case that fails today is an expected failure, not a deleted case.** Mark it
with a short phrase naming the defect it records. Write the phrase, not a
tracker number or a review identifier: a reader who clones the repository has
only what is in it.

```c
{ "TestSignatureIsFullLength", test_signature_is_full_length, "the signature compares six characters" },
```

The runner reports it as `xfail`. When the fix lands, the case starts passing,
the runner reports `XPASS`, and the run fails until the marker is removed. That
is how each pull request proves it closed the defect.

## The golden files

Golden bytes depend on the ImageMagick build, so the directory name carries the
distribution and the ImageMagick version:

```
golden/debian12-im6.9/grid.TestResize.golden.png
```

`lib/environment.c` builds the name. Regenerating on a different build writes a
new directory rather than overwriting someone else's.

The name carries no architecture. amd64 and arm64 were measured to produce all
90 files byte for byte identical, so they share one set, and the arm64 CI job
runs the same cases against the same baselines. Two sets would let the
architectures drift apart with nothing to notice, because each would only ever
be compared against itself.

A change that moves a golden file needs a reason in the pull request, and each
one attaches before and after images. A golden change anywhere else is a bug.

## Where the cases come from

Most are ported from go-dims by name, so the two projects verify one
specification instead of two that drift.
The go-dims cases are MIT licensed; `NOTICE` records the credit and every
ported file keeps its header.

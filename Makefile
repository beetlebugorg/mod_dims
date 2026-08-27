# mod_dims
#
#   make builder-local   build the toolchain image for this machine
#   make builder         build it for both architectures and push it
#   make test            build the module and run the suite
#
# The build itself is CMake:
#
#   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build

REGISTRY ?= ghcr.io/beetlebugorg/mod_dims

# Read the ImageMagick version straight from the builder, so the tag and the
# toolchain cannot disagree.
IMAGEMAGICK_VERSION := $(shell sed -n 's/^ARG IMAGEMAGICK_VERSION=//p' Dockerfile.builder)
BUILDER_TAG := builder-im$(IMAGEMAGICK_VERSION)

# Pull the toolchain, or build it when the registry does not have it yet.
# A fresh checkout, a pull request opened before the toolchain is published,
# and a machine with no registry access all work the same way.
toolchain:
	@docker image inspect $(REGISTRY):$(BUILDER_TAG) >/dev/null 2>&1 && \
	    echo "toolchain $(BUILDER_TAG) already here" || \
	  docker pull -q $(REGISTRY):$(BUILDER_TAG) 2>/dev/null || \
	  $(MAKE) builder-local

builder-local:
	docker buildx build --load -t $(REGISTRY):$(BUILDER_TAG) -f Dockerfile.builder .
	@echo "built $(REGISTRY):$(BUILDER_TAG)"

builder:
	docker buildx build --push \
	    --platform linux/amd64,linux/arm64 \
	    -t $(REGISTRY):$(BUILDER_TAG) \
	    -t $(REGISTRY):builder \
	    -f Dockerfile.builder .

builder-tag:
	@echo $(REGISTRY):$(BUILDER_TAG)

test:
	$(MAKE) -C test test

.PHONY: builder builder-local builder-tag toolchain test

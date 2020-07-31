# mod-dims Docker Containers

These containers can be used to build Ubuntu (deb) packages.

## Building Ubuntu Debian Package

The first step is to build the Docker image that will be used to generate a Debian package. This
step only needs to happen once for each version of Ubuntu you want to build packages for.

```bash
$ docker build . -t mod-dims/ubuntu:16.04 -f Dockerfile-ubuntu-16.04
```

Now we can build specific versions of mod-dims by running the image we just generated. Pass in
`-e DIMS_VERSION=3.3.20` to build the release tagged `release/3.3.20`. Only tagged releases
(i.e. `release/3.3.20`) are supported.

The Debian packages are built in the `/build` directory inside the container. Mount this
directory locally using `-v` to get access to the package on your build host.

```bash
$ docker run --rm --name moddims -e DIMS_VERSION=3.3.20 -v $PWD/build:/build mod-dims/ubuntu:16.04
```

You should now have a package in your local `./build` directory.

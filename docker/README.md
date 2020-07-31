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

## Developing using Docker

Like building packages, the first step is to build the Docker image that will be used to
run mod-dims inside Apache. This image includes a custom build of Imagemagick 6.9.x that
works with mod-dims.

```bash
$ docker build . -t mod-dims/dev:16.04 -f Dockerfile-dev
```

When run this image will compile mod-dims and install it. It expects mod-dims source
code to be in `/build` so make sure to mount the source code when you run this container. 
It will then start up Apache to test mod-dims.

```bash
$ docker run -it --rm --name moddims-dev -p 80:80 -v $PWD/../:/build mod-dims/dev:16.04
```

In a browser go to http://localhost/dims-status/ and you should see the mod-dims status page.

At this point you can make changes to the mod-dims source code and restart the container to
test your changes.
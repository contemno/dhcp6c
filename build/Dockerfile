# Generic OPNsense package build environment.
#
# FreeBSD OCI containers require a FreeBSD host running Podman/Buildah
# (ocijail runtime) -- they do NOT run under Docker on Linux/macOS.
# On a Linux host, use the GitHub Actions workflow or a FreeBSD VM with
# build-package.sh instead.
#
#   podman build --build-arg PORTS_BRANCH=stable/25.7 -t opnsense-portbuild build/
#   podman run -it --rm \
#       -v $PWD/packages:/packages \
#       -v $PWD/distfiles:/usr/ports/distfiles \
#       opnsense-portbuild
#
# Pin the base image to the FreeBSD major of the target OPNsense
# (`freebsd-version` on the box; OPNsense 25.x = FreeBSD 14.x).
FROM docker.io/freebsd/freebsd-base:14.3

# pkg is not in the base image; bootstrap it, then a minimal toolset.
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f && \
    pkg update && \
    pkg install -y git gmake pkgconf autoconf automake libtool

ARG PORTS_BRANCH=stable/25.7
RUN git clone --depth 1 -b ${PORTS_BRANCH} \
        https://github.com/opnsense/ports /usr/ports

COPY build-package.sh /usr/local/bin/build-package.sh
RUN chmod 555 /usr/local/bin/build-package.sh

# BATCH=yes  -> never block on interactive options dialogs.
# PACKAGES   -> `make package` also deposits results in /packages/All.
ENV BATCH=yes \
    PACKAGES=/packages
RUN mkdir -p /packages

WORKDIR /usr/ports
CMD ["/bin/sh"]

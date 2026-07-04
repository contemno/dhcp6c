#!/bin/sh
#
# Full custom OPNsense firmware build via opnsense/tools.
#
# This is the heavyweight path: it checks out the OPNsense forks of
# FreeBSD src, ports, core and plugins (many GB) and builds a complete
# firmware image. Run it on a real FreeBSD builder (bare metal or VM)
# whose major version matches the target release -- expect tens of GB
# of disk and hours of build time. Not suited to CI runners or
# containers.
#
# usage: build-image.sh <settings> [target]
#   settings  release configuration under tools/config, e.g. 25.7
#   target    tools make target, e.g. vga, serial, nano, dvd
#             (see https://github.com/opnsense/tools for the full list
#             and for output locations)

set -eu

SETTINGS=${1:?usage: build-image.sh <settings e.g. 25.7> [target e.g. vga]}
TARGET=${2:-vga}

if [ ! -d /usr/tools ]; then
	echo ">>> cloning opnsense/tools into /usr/tools"
	git clone https://github.com/opnsense/tools /usr/tools
fi

echo ">>> fetching source trees for ${SETTINGS} (this is large)"
make -C /usr/tools update SETTINGS="${SETTINGS}"

echo ">>> building '${TARGET}' image for ${SETTINGS}"
make -C /usr/tools "${TARGET}" SETTINGS="${SETTINGS}"

echo ">>> done -- see the opnsense/tools README for image output paths"

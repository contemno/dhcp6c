#!/bin/sh
#
# Build a single OPNsense package from the opnsense/ports tree.
#
# Runs on any FreeBSD system (VM, jail, OCI container, CI guest) as root.
# The toolchain (cc, make, lex, yacc) ships in the FreeBSD base system;
# the ports framework builds or installs anything else it needs.
#
# usage: build-package.sh [-p category/port] [-b ports-branch]
#                         [-a gh-account] [-t gh-tag-or-commit] [-o outdir]
#
#   -p  port origin to build                    (default: opnsense/dhcp6c)
#   -b  opnsense/ports branch or tag            (default: master)
#   -a  override the port's GH_ACCOUNT, e.g. a fork owner
#   -t  override the port's GH_TAGNAME, a tag or full commit hash
#   -o  directory to copy the built .pkg into   (default: ./artifacts)
#
# -a/-t swap the port's upstream for a fork/commit; distinfo is
# regenerated with `make makesum` so fetch checksums match.

set -eu

PORT=opnsense/dhcp6c
PORTS_BRANCH=master
PORTS_DIR=/usr/ports
GH_ACCOUNT_OVERRIDE=""
GH_TAGNAME_OVERRIDE=""
OUT=./artifacts

while getopts p:b:a:t:o:h opt; do
	case $opt in
	p) PORT=$OPTARG ;;
	b) PORTS_BRANCH=$OPTARG ;;
	a) GH_ACCOUNT_OVERRIDE=$OPTARG ;;
	t) GH_TAGNAME_OVERRIDE=$OPTARG ;;
	o) OUT=$OPTARG ;;
	h|*) sed -n '2,20p' "$0"; exit 1 ;;
	esac
done

# resolve OUT before we cd anywhere
case $OUT in
/*) ;;
*) OUT="$(pwd)/$OUT" ;;
esac
mkdir -p "$OUT"

if [ ! -d "$PORTS_DIR/Mk" ]; then
	echo ">>> cloning opnsense/ports ($PORTS_BRANCH) into $PORTS_DIR"
	git clone --depth 1 -b "$PORTS_BRANCH" \
	    https://github.com/opnsense/ports "$PORTS_DIR"
fi

MAKE_ARGS="BATCH=yes"
[ -n "$GH_ACCOUNT_OVERRIDE" ] && MAKE_ARGS="$MAKE_ARGS GH_ACCOUNT=$GH_ACCOUNT_OVERRIDE"
[ -n "$GH_TAGNAME_OVERRIDE" ] && MAKE_ARGS="$MAKE_ARGS GH_TAGNAME=$GH_TAGNAME_OVERRIDE"

cd "$PORTS_DIR/$PORT"

if [ -n "$GH_ACCOUNT_OVERRIDE$GH_TAGNAME_OVERRIDE" ]; then
	echo ">>> regenerating distinfo for overridden source"
	make $MAKE_ARGS makesum
fi

echo ">>> building $PORT"
make $MAKE_ARGS package

PKGFILE=$(make $MAKE_ARGS -V PKGFILE)
cp "$PKGFILE" "$OUT"/
echo ">>> built: $OUT/$(basename "$PKGFILE")"

# OPNsense build pipeline

Tooling to build this repo's `dhcp6c` — or any OPNsense package, or a full
custom firmware image — from source. Everything OPNsense must be built on
FreeBSD; each path below just differs in where that FreeBSD lives.

| Path | Where it runs | Use it for |
|---|---|---|
| GitHub Actions (`.github/workflows/build-package.yml`) | FreeBSD VM on a stock GitHub runner | hands-off `.pkg` builds; every push to `master` produces a dhcp6c package artifact |
| Build container (`build/Dockerfile`) | Podman on a **FreeBSD host** | interactive shell to build any port repeatedly |
| Plain script (`build/build-package.sh`) | any FreeBSD VM/jail | one-shot package builds without container plumbing |
| Image script (`build/build-image.sh`) | a beefy FreeBSD builder | complete custom firmware images via opnsense/tools |

The web-UI side of the `allow-missing` option (a per-interface checkbox that
makes the config generator emit it) is a separate opnsense/core patch — see
[`patches/README.md`](../patches/README.md).

## CI packages (recommended)

On every push to `master`, the workflow builds `opnsense/dhcp6c` **from that
commit** by pointing the port's `GH_ACCOUNT`/`GH_TAGNAME` at this repository,
and uploads the resulting `.pkg` as a build artifact.

For any other package, use *Run workflow* (workflow_dispatch) and set:

- `port` — e.g. `opnsense/dhcp6c`, `dns/dnsmasq` (OPNsense's own ports live
  under the `opnsense/` category of the ports tree, not `net/`)
- `ports_branch` — opnsense/ports branch or tag; leave empty to use the
  repo-wide default (see below)
- `gh_account` / `gh_tagname` — optional fork owner + tag/commit to build a
  patched source instead of the port's pinned upstream
- `freebsd_release` — VM version; match the target box (`freebsd-version`;
  OPNsense 25.x = FreeBSD 14.x)

## Manual builds

On any FreeBSD system of the matching major version:

```sh
pkg install -y git
git clone https://github.com/contemno/dhcp6c && cd dhcp6c

# stock port:
sh build/build-package.sh -p opnsense/dhcp6c -b 26.1.11

# this fork at a specific commit (example: the allow-missing change):
sh build/build-package.sh -p opnsense/dhcp6c -b 26.1.11 \
    -a contemno -t faaa71afe30844bfcb3286ee97e184b24696b238

ls artifacts/          # -> dhcp6c-*.pkg
```

With a FreeBSD host running Podman, `build/Dockerfile` wraps the same script
in a reusable environment (see the header comment for build/run commands).
FreeBSD OCI containers do **not** run under Docker on Linux/macOS — that is
what the CI path is for.

## Installing on the target box

```sh
cp /usr/local/sbin/dhcp6c /usr/local/sbin/dhcp6c.orig   # once, for rollback
pkg add -f dhcp6c-*.pkg
pkg lock dhcp6c        # optional: pin against pkg operations while testing
```

An OPNsense system update can still replace the binary; for permanent use,
carry the change in the port your firmware is built from.

## Full firmware image

```sh
sh build/build-image.sh 26.1 vga
```

Thin wrapper around [opnsense/tools](https://github.com/opnsense/tools):
`make update` pulls the OPNsense src/ports/core/plugins trees (many GB), then
builds the requested image target. Plan for a dedicated FreeBSD builder,
tens of GB of disk, and hours of runtime. To bake a patched package (like
this dhcp6c) into the image, point the port at your fork in the checked-out
`/usr/ports` before building, the same `GH_ACCOUNT`/`GH_TAGNAME` way.

## Verify on first use

A few things worth a 30-second check the first time, since ref and variable
conventions drift between releases:

- the `opnsense/ports` ref for your release — releases are tags like
  `26.1.11`; the repo has **no** `stable/*` branches. The workflow takes
  the ref from the `PORTS_BRANCH` repository variable (Settings > Secrets
  and variables > Actions > Variables), falling back to `master` when
  unset — a new release only needs the variable flipped, no commit
- that `ports/opnsense/dhcp6c/Makefile` pins its source via `GH_ACCOUNT` /
  `GH_TAGNAME` (`grep GH_ Makefile`) — the override flags rely on those
  (verified at tag `26.1.11`: `USE_GITHUB` with `GH_ACCOUNT=opnsense`)
- `vmactions/freebsd-vm` supports your requested `freebsd_release`

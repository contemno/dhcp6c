# OPNsense core patches

## opnsense-core-allow-missing-ui.diff

Exposes this fork's dhcp6c `allow-missing` option (#1) in the OPNsense web
UI, per tracked interface. Generated against opnsense/core `stable/26.1`
(26.1.x releases).

### What it adds

Under **Interfaces → [assigned interface]** with IPv6 type *Track Interface*
(and the *Prefix ID* variant, which shares the same storage), a new
**Dynamic device** checkbox:

> Allow this device to be missing when the DHCPv6 client starts

Checked, it stores `track6_allow_missing` on that interface in config.xml,
and the dhcp6c.conf generator emits `allow-missing;` inside that
interface's `prefix-interface` block — in both the normal and the
advanced-mode generators. Unchecked (the default) nothing changes.

With the flag in place the boot-order problem solves itself end to end:

1. dhcp6c starts while the device (e.g. a ZeroTier `zt*` interface) does
   not exist yet — logged as a warning instead of killing the whole
   client, so every other interface keeps its DHCPv6/PD.
2. When the device appears, OPNsense's existing link-up handling
   reconfigures the tracking interface, regenerates dhcp6c.conf and sends
   dhcp6c a SIGHUP (`interface_track6_configure()` in interfaces.inc).
3. The re-parse finds the device and the delegated prefix is assigned as
   usual.

### Requirements

The **patched dhcp6c from this repository** must be installed (see
`build/README.md` — the CI artifact from any master build works). The
stock dhcp6c rejects `allow-missing` as a configuration error and will
refuse to start, taking DHCPv6 down on all interfaces — so only enable
the checkbox once the patched package is in place.

### Applying

The patch uses opnsense/core repo paths (`src/...`), which map onto
`/usr/local/...` on an installed system. Directly on the firewall:

```sh
fetch -o /tmp/allow-missing-ui.diff \
    https://raw.githubusercontent.com/contemno/dhcp6c/master/patches/opnsense-core-allow-missing-ui.diff
patch -d /usr/local -p2 --dry-run < /tmp/allow-missing-ui.diff   # verify first
patch -d /usr/local -p2 < /tmp/allow-missing-ui.diff
```

No service restart is needed; the changes take effect the next time the
interface page is saved (which regenerates dhcp6c.conf and restarts the
client).

Alternatively, commit the patch to a fork of opnsense/core and use the
native tooling, which is easier to re-run: `opnsense-patch -a <account>
-r core <commit-hash>`.

### Caveats

- Firmware updates replace `interfaces.inc` and `interfaces.php`; reapply
  the patch after each update. The checkbox *setting* lives in config.xml
  and survives updates on its own — worst case the option is silently
  ignored until the patch is reapplied.
- After an OPNsense upgrade to a release newer than 26.1, re-verify the
  patch context still applies (`--dry-run`) before applying.

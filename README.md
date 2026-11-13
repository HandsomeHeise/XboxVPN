# XboxVPN

XboxVPN is a standalone DashLaunch plugin that connects an Xbox 360 to Mullvad
over WireGuard. It uses a Mullvad profile stored on the console's hard drive.

## Requirements

- An Xbox 360 running retail kernel `17559`, with DashLaunch, an internal hard
  drive, and a wired Ethernet connection with IPv4.
- A Mullvad account with active service.
- A Windows PC with PowerShell 7, the Xbox 360 SDK, and MSBuild 4.0 to build
  the plugin.

## Build

Open PowerShell 7 in the repository directory. If the SDK is installed in a
custom location, set `$env:XEDK` to the SDK directory before building.

```powershell
.\build.ps1
```

The script writes `Build/XboxVPN.xex` and verifies its import libraries and
resident memory range.

## Install and connect

1. In the [Mullvad WireGuard configuration generator](https://mullvad.net/en/account/wireguard-config),
   choose Linux, generate a device key for the Xbox, and download a profile
   for a single relay with an IPv4 endpoint.
2. Copy the downloaded `.conf` file to the root of the Xbox hard drive as
   `Hdd:\VPN.ini`. Keep the file private because it contains the device's
   WireGuard private key. If the file is missing at startup, XboxVPN creates
   a blank template and checks for a valid profile every three seconds.
3. Copy `Build/XboxVPN.xex` to `Hdd:\XboxVPN.xex` and select it in an unused
   DashLaunch plugin slot. Save the DashLaunch settings. If Migraine is in
   the plugin list, remove its entry because both plugins use the same
   resident memory range.
4. Restart the console with the DVD tray closed. XboxVPN starts automatically
   once Ethernet has an IPv4 address. If you use xbWatson, look for
   `[XboxVPN] Mullvad connected`.

To change relays, replace `Hdd:\VPN.ini` and restart. To boot with XboxVPN
inactive, start with the DVD tray open or clear its DashLaunch slot and restart.

## Profile format

The `[Interface]` section needs `PrivateKey`, `Address` with an IPv4 `/32`,
and `DNS` with one IPv4 resolver. The `[Peer]` section needs `PublicKey`,
`AllowedIPs` containing `0.0.0.0/0`, and `Endpoint` with a numeric IPv4 address
and UDP port. The profile may also contain IPv6 entries. `MTU` from 1280 to
1420 and `PersistentKeepalive` are optional.

## Connection behavior

The Xbox uses its regular connection while waiting for a valid profile and
Ethernet IPv4. Once the adapter starts, XboxVPN blocks Internet IPv4 until the
WireGuard handshake succeeds and whenever the tunnel drops. LAN traffic, DHCP,
and ARP stay direct. DNS queries on TCP and UDP port 53 go through the tunnel
to the profile's resolver. XboxVPN blocks IPv6 while the adapter is active.

On supported XAM builds, the first successful handshake refreshes the Xbox
Live gateway connection. This can interrupt an existing Xbox Live session.
XboxVPN stays loaded when you switch games.

## Third-party code

The WireGuard protocol code and reference crypto come from
[wireguard-lwip](https://github.com/smartalock/wireguard-lwip/tree/c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d).
XboxVPN supplies its own network adapter. Local changes cover opaque network
types, MSVC packing and C++ portability, big-endian X25519 word conversion,
and replay-window arithmetic. See the [WireGuard license](third_party/wireguard/LICENSE)
and [X25519 license](third_party/wireguard/src/crypto/refc/x25519-license.txt).

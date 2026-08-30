# linux-eoip

Two small tunnelling daemons for Linux:

| | |
|---|---|
| **eoip** | Ethernet over IP, wire-compatible with Mikrotik RouterOS EoIP. Bridges Ethernet segments over IP protocol 47 (GRE) using `tap` devices. |
| **vip** | "Virtual IP", a point-to-point IP tunnel over IP protocol 50 (configurable) using `tun` devices. Its own format, not compatible with anything else. Adds packet coalescing and optional LZO compression for links where per-packet overhead matters. |

Each tunnel gets its own network interface, named after its config section,
and its own transmit thread.

## Building

    cmake -B build
    cmake --build build
    sudo cmake --install build

Requires CMake 3.13 or later and a C compiler; binaries land in
`CMAKE_INSTALL_PREFIX/bin`, `/usr/local/bin` by default.

`liblzo2` is optional and detected automatically. It is only used by `vip`,
for the `compression` option; without it, `vip` still builds and runs, but
cannot compress or decompress.

| CMake option | Default | Meaning |
|---|---|---|
| `WITH_LZO` | `AUTO` | `AUTO` uses liblzo2 if present, `ON` fails configuration when it is missing, `OFF` builds without it. |
| `CMAKE_BUILD_TYPE` | `Release` | Standard CMake build types. |
| `RING_SLOTS` | `64` | Receive ring depth, in slots of one max-size payload each. |
| `TX_BATCH` | `16` | `eoip` transmit batch depth, per tunnel. |
| `EOIP_MAXPAYLOAD` | `2048` | `eoip`: largest tunnelled payload, bytes. |
| `VIP_MAXPAYLOAD` | `65536` | `vip`: largest tunnelled payload, bytes. |

`recvmmsg`, `sendmmsg` and CPU affinity are probed for and used when present,
with working fallbacks when they are not, so no configuration is needed for
those.

### Sizing for a small target

The defaults assume a machine with memory to spare. `RING_SLOTS` multiplied by
the payload size is a single allocation made once, and `TX_BATCH` multiplied by
the payload size is allocated *per tunnel*, so on a router they are the two to
turn down. The configure output prints what you chose:

    cmake -B build -DRING_SLOTS=8 -DTX_BATCH=4 -DVIP_MAXPAYLOAD=2048
    ...
    -- Receive ring: eoip 16KB, vip 16KB

At the defaults `vip` reserves 4MB for its receive ring alone.

So to guarantee a build with compression support:

    cmake -B build -DWITH_LZO=ON

Both daemons need raw sockets and the ability to create network interfaces,
so run them as root, or grant `CAP_NET_RAW` and `CAP_NET_ADMIN`.

## Configuration

Both read an INI file. Each section defines one tunnel, and the section name
becomes the interface name, so it must be a valid interface name: shorter
than 16 characters. A config with no sections is an error.

Ready-made samples are in `examples/`; copy one to the default path to get
started:

    sudo cp examples/eoip.cfg /etc/eoip.cfg

### eoip

    eoip [configfile [bindip]]

`configfile` defaults to `/etc/eoip.cfg`. `bindip` is only read when both
arguments are given; it binds the raw socket to one local address. The
process writes its pid to `/var/run/eoip-<configfile basename>`.

| Key | Default | Meaning |
|---|---|---|
| `id` | — | Tunnel id, 1 to 65535. Must match the remote side, and be unique within this config. |
| `dst` | — | Remote peer address. Required unless `dynamic=1`. |
| `dynamic` | `0` | Learn the peer address from incoming packets instead of pinning it. See [Security](#security). |

    [eoip0]
    id=123
    dst=192.168.20.1

    [eoip1]
    id=124
    dst=1.1.1.2

### vip

    vip [-c configfile] [-b bindip] [-p protocol] [-v]

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config` | `/etc/vip.cfg` | Config file. |
| `-b`, `--bind` | — | Bind the raw socket to one local address. |
| `-p`, `--protocol` | `50` | IP protocol number. Must match the remote side. |
| `-v`, `--verbose` | off | Report compression savings every 50MB, per tunnel. |
| `-h`, `--help` | | Usage. |

| Key | Default | Meaning |
|---|---|---|
| `id` | — | Tunnel id, 1 to 255. Must match the remote side, and be unique within this config. |
| `dst` | — | Remote peer address. At least one destination is required. |
| `dst1`, `dst2` | — | Additional peers. Outgoing packets are sent to each in turn, round-robin. |
| `delay` | `1000` | Microseconds to wait for further packets before sending, so several small packets can travel in one datagram. |
| `maxpacked` | `1500` | Byte budget for one coalesced datagram. Values above 32768 are clamped; above 1500 you are relying on IP fragmentation. |
| `compression` | `0` | Set to `1` for LZO. Requires a build with `liblzo2`. Applied per packet only when it actually shrinks the data. |

    [vip0]
    id=1
    dst=194.146.153.7
    delay=10000
    maxpacked=1400

## Peer address validation

A tunnel accepts packets only from the peer it is configured for: `dst` for
`eoip`, any of `dst`/`dst1`/`dst2` for `vip`. Packets carrying a valid tunnel
id from any other source are dropped, and the first drop on each tunnel is
reported once so a mismatch is visible without flooding the log.

This matters if a peer's packets reach you from an address other than the one
you configured — it is behind NAT, or it is multihomed and picks a different
egress address. Configure the address the packets actually arrive from, add it
as `dst1`/`dst2` on `vip`, or use `dynamic=1` on `eoip`.

`eoip` tunnels with `dynamic=1` are exempt: they accept any source and adopt
it as the new peer, which is what that mode is for.

## Security

**Neither daemon authenticates or encrypts anything.**

`vip` masks its payload with a fixed single-byte XOR. That is obfuscation, not
encryption — anyone who can see the traffic can read and modify it. `eoip` does
not even do that.

Peer validation is by source address, which is only as strong as your network's
ability to reject spoofed source addresses. On a path where an attacker can
forge them, knowing a tunnel id — 16 bits on `eoip`, 8 on `vip` — is enough to
inject frames straight onto the bridged segment.

`dynamic=1` is weaker still: any host that can reach you and guess the tunnel id
takes over the tunnel, because adopting the sender's address is the documented
behaviour. Do not use it on a public address or on any network you do not fully
control, host by host.

If the path is not trusted, run these tunnels inside one that is — IPsec or
WireGuard.

## Notes and limits

- The receive thread is pinned to CPU 0 and transmit thread *n* to CPU *n*+1.
  On a machine with fewer CPUs than tunnels this fails harmlessly: an
  "Affinity error" line is printed and the thread runs unpinned.
- `SIGTERM` and `SIGINT` close the tunnel devices and exit.
- Both daemons fork into the background after creating their interfaces, so a
  script can configure the interfaces as soon as the process returns.
- Payloads larger than `MAXPAYLOAD` (2048 bytes in `eoip`, 65536 in `vip`) are
  not handled; see the comment at the top of each source file for the
  space-versus-throughput tradeoff behind those numbers.

## Repository layout

    CMakeLists.txt          top-level build, option handling, liblzo2 detection
    src/                    the two daemons and the config.h template
    third_party/minini/     vendored INI parser (ITB CompuPhase, Apache-2.0)
    examples/               sample configs for both daemons

`third_party/minini` is kept separate because it is not ours and carries a
different license from the daemons; see the header in `minIni.c`.

## License

GPL v3 or later; see `COPYING`. Written by Denys Fedoryshchenko
<nuclearcat@nuclearcat.com>.

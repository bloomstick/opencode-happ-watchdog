# The Happ daemon (`happd`) pipe protocol - field notes

Everything below was reverse-engineered from live traffic of the Windows Happ desktop
client + its `HappService` daemon and **verified in regular use** as of 2026-10. It is
not official documentation; a Happ update can change any of it. The watchdog (`happ-failover.ps1`)
is the reference implementation for everything described here.

## Discovery

- The daemon listens on one named pipe **per Windows session**: `\\.\pipe\happd-<sessionId>`
  (e.g. `happd-3`). Enumerate with `[System.IO.Directory]::GetFiles('\\.\pipe\')` and match `happd-*`.
- Clients must run in the same Windows session as the GUI for the usual flow to work.
- The GUI keeps **two long-lived client connections** open; extra clients (like this
  watchdog) coexist fine.

## Framing

- Each message is **4-byte big-endian length prefix + compact UTF-8 JSON**.
- Every request carries a `request-id`; the daemon replies with frames echoing it, so a
  caller sends a burst and then drains matching frames.

## The burst model (the key insight)

- A connection speaks in **one burst**: `client-hello` first, then any further frames
  - frames written *later* on the same connection are **ignored** by the daemon
    (except `heartbeat`, which any connected client can keep sending)
- The connection **owns** the process records it spawns
- When the owning client disconnects, the daemon **kills its owned records** (this is
  why a watchdog quit drops the tunnel it owns)
- Records are keyed by `process-id` - a `stop` from *any* client stops the record with
  that id, and a new `start` under the same id replaces it. This is how clean handover
  to/from the GUI works.

## Actions

| action | notes |
| --- | --- |
| `client-hello` | handshake frame, sent first in every burst |
| `get-privilege` | daemon privilege/report frame |
| `list` | returns running records: `process-id`, pid, state, executable |
| `stop` / `kill` | stop a record by `process-id` (cross-client) |
| `start` | fields: `process-id`, `executable`, `arguments`, `working-dir`, `auto-restart`, `max-restart-attempts`, `restart-delay-ms`; replies `status=started` |
| `stdin` | pushes data to the record's stdin. **xray.exe runs with no arguments and reads its full config from stdin** (`status=success`) |
| `close-stdin` | closes the record's stdin stream (part of the normal xray start sequence) |
| `heartbeat` | keep-alive, no burst restriction |
| `start-tun` | spawns the system-wide TUN: `process-id` `sing-box-tun`, executable `tun\sing-box.exe`, `arguments` `["-c","%LOCALAPPDATA%\Happ\config.json"]`, plus `address` `172.18.0.1/30`, `address-v6`, `iface` `happ-tun`, `tun-dns-override` `1.1.1.1`, auto-restart fields |

## Core + TUN layout

- `core\xray.exe` - runs argument-less, config via `stdin`, forwards everything (TUN
  inbound `tun-in` -> internal `proxy` outbound). Its socks listener is `127.0.0.1:10808`.
- `tun\sing-box.exe -c %LOCALAPPDATA%\Happ\config.json` - the system-wide tunnel. The
  config file is sing-box-style: TUN inbound (`happ-tun`, `172.18.0.1/30`, mtu 1500,
  `auto_route`/`strict_route`, stack `mixed`) with a socks outbound to `127.0.0.1:10808`.
  The adapter (`happ-default-tun` / `happ-xray`) is daemon-managed; DNS on the adapter is
  overridden with `1.1.1.1`.
- The GUI's own start sequence is `stop` -> `start` -> `stdin` -> `close-stdin` ->
  `start-tun`, plus cosmetic housekeeping (`start-process-explorer`, proxy-restore
  registry guards) that the watchdog intentionally does not replicate.

## Where the watchdog gets its pieces

- **Current server**: registry `HKCU:\Software\Happ\OrganizationDefaults\Preferences`
  (`lastServer*` values).
- **Per-server configs**: the GUI process holds the *live* xray config template and
  per-server outbound parameters (address/port/credentials) in memory as JSON
  fragments. The watchdog scans Happ.exe memory read-only (C# `ReadProcessMemory`,
  ~150 hits in a couple of seconds), extracts each candidate server's outbound block,
  and rebuilds a full config by swapping the outbound of the current template.
  Templates are cached per `host_port` under `configs/`.
- **Fallback kill**: a GUI-owned record cannot always be stopped via the pipe; the
  watchdog OS-kills `xray.exe` (requires elevation) before spawning its own.

## Runtime artifacts

- `configs/*.json` contain connection credentials - treat as secrets.
- `state.json` tracks used servers (LRU rotation), prompted sessions (fresh-failure
  aware), exit-IP history, and a connection-loss processing cursor.

All of this was verified against one Happ build in October 2026; deltas should show up
in `failover.log` quickly since the watchdog logs every daemon response.

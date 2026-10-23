# OpenCode Happ Watchdog

An autonomous recovery watchdog for [OpenCode](https://opencode.ai) running behind the
[Happ](https://happ.su) proxy client on Windows. When the provider misbehaves - rate
limits, free-usage quota, dead connections, failed endpoints, a collapsed tunnel - the
watchdog rotates Happ to a random unused server, fully restarts the OpenCode desktop
app, and sends `continue` to every affected top-level session.

```
15:47:17 3 connection-loss failures within 180s - switching server
15:47:17 connection-loss burst (ECONNRESET); current server leaddemo (203.0.113.10:443) marked used
15:47:19 affected sessions: ses_1111111111aa, ses_2222222222bb, ses_3333333333cc
15:47:22 switching to 203.0.113.129:443 via daemon pipe (burst mode)...
15:47:39 TUN adapter up: happ-default-tun (Up)
15:47:41 SWITCH OK -> 203.0.113.129:443 (core exit IP: 203.0.113.129; system route: 203.0.113.129)
15:47:42 opencode desktop healthy after 1s (pid 9828)
15:47:49 continue -> ses_1111111111aa
15:47:49 failover complete
```

> **Status:** battle-tested nightly on one machine (TUN mode, xray core, PowerShell 5.1).
> The Happ daemon protocol findings are reverse-engineered - documented in
> [PROTOCOL.md](PROTOCOL.md). Not affiliated with Happ/FlyFrogLLC or OpenCode.

## What it does

1. **Watches** the OpenCode log (`~/.local/share/opencode/log/opencode.log`) for
   `Rate limit exceeded`, `Too many requests`, and free-usage errors
   (`Free usage limit reached`, `Free usage exceeded`), and the OpenCode session API
   for `Endpoint is unavailable` and connection-loss (`ECONNRESET`) failures
   (connection resets never reach the server log).
2. **Switches the Happ proxy server** to a **random** previously *unused*, *unbanned*
   server from your subscription. It talks to the Happ daemon (`happd`) over its named
   pipe using the app's own JSON protocol:
   - `client-hello` handshake, `list`, `stop`, `start`, `stdin` (config feed),
     `close-stdin`, `heartbeat`
   - after starting the core it re-issues the daemon's `start-tun` action so the
     system-wide tunnel (`happ-tun` via sing-box) is owned and restored by the
     watchdog, not just the socks port
   - the new xray config is rebuilt from the currently-running config template plus
     the outbound (connection params) of the target server, both extracted from the
     Happ GUI process memory
   - every attempt is verified by an exit-IP test through the local socks port
     (`127.0.0.1:10808`) plus a plain system-route check; dead/broken servers are
     skipped automatically
3. **Fully restarts the OpenCode desktop app**: it is stopped *before* the Happ server
   changes, so no stale HTTP/SSE connections survive the switch, then started again
   after the new server is verified. The watchdog waits for its API to become healthy.
4. **Sends a `continue` prompt** to every top-level OpenCode session whose latest
   visible event is a provider failure. Subagent sessions are skipped; they get
   re-spawned by their parent flow. Sessions already prompted are skipped only while
   their failure predates the last prompt, so a *new* failure always re-flags them.

State (active server, used servers, prompted sessions) is kept in `state.json`, so
"previously unused" is tracked across watchdog restarts. Banned servers live in a
separate `bans.json`; clearing the used list never un-bans anything.

### Failure classes and triggers

| class | detection source | reaction |
| --- | --- | --- |
| rate | opencode.log tail (`Rate limit exceeded`, `Too many requests`, `Free usage limit reached`, `Free usage exceeded`) + session API | immediate failover |
| endpoint | session API (`Endpoint is unavailable`) | same-server `continue` retry after ~60s; switch after 2 failed rounds |
| connreset | session API (`ECONNRESET` / `Connection lost while reading the response`) | **3 failures within 3 minutes -> failover** |
| tunnel-dead | plain system-route probes (two URLs, 30s cadence) | route dead twice in a row (~60s) -> failover; a vanished TUN adapter is restored directly |

Notable behaviors:

- **Idle-marker masking fix** - a session whose newest records are `idle`/system markers
  no longer masks an older provider failure underneath it; only a person-authored
  follow-up (a real user message) marks a session as "moved on".
- **Fresh-failure dedup** - once-prompted sessions are skipped only while their failure
  predates the last prompt; a *new* failure re-flags them.
- **Boot recovery** - booting into an already-dead network (e.g. the previous watchdog
  exited while owning the tunnel) recovers on the first health tick, no cooldown wait.
- **Resize-proof pinned dashboard** - the console re-renders from an in-memory event
  ring; the status header always stays on top and log volume or window resizes can
  never scroll it away.

Free-usage errors are OpenCode's free-model quota. The watchdog treats them like any
other rate limit and rotates immediately. If the quota is tied to the public exit IP,
another subscription server can bring a fresh window. Subscription pool IPs may be
shared with other users, so a freshly selected IP can already be partially burned; if
rotation keeps landing on exhausted IPs, the quota window itself is the remaining wait.

### Server exhaustion / rotation

When every eligible cached server has been used once, the watchdog starts **rotation
cycle 2**: the used-list resets (except the currently active server) and candidates are
retried in **random order**. Banned servers are not part of this pool and are never
re-introduced by a rotation reset. The event appears in the dashboard as
`rotation reset: all N unbanned cached servers used - cycling again in random order`.

### Bans

Bans are deliberately different from the used-list:

- `state.json` records **used** servers; clearing them (`C`) makes them candidates again.
- `bans.json` records **banned** servers; they are *never* selected, including during
  rotation cycle 2. The only way back into the pool is to unban them explicitly.
- The dashboard shows a banned count and marks the current server as `[BANNED]` if it
  was banned while connected.

```powershell
# ban a server permanently (host:port; host_port and "current" are also accepted)
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -BanServer 203.0.113.10:443
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -BanServer current

# remove a ban again
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -UnbanServer 203.0.113.10:443

# show the banned list
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ListBanned
```

In the interactive dashboard, `B` bans the server currently in use and immediately
switches away from it. `L` opens the bans/server editor: every known cached, active,
used, or banned server is listed with its cached name, banned entries first and in red.
Use `Up`/`Down` (plus `PgUp`/`PgDn`, `Home`/`End`) to move and press `Enter` to
ban/unban the selected server. `R` rescans the cache, and `Esc` or `L` closes the
editor. The selection follows the server if toggling moves it between the banned and
unbanned groups. The editor runs as a fast modal loop (25 ms input polling) so movement
stays responsive; automatic watchdog polling pauses while it is open and resumes on
close (the daemon heartbeat continues).

Happ sometimes exposes several names for the same `host:port` (or a memory capture is
malformed). The editor lists those names as separate alias rows marked `~`; they share
one cache template and one endpoint ban. Distinct credentials/transports that happen to
use the same `host:port` are stored as **profile** rows marked `@`
(`configs/<host>_<port>__<hash>.json`, key `host:port#hash`); they are independently
selectable and bannable. An endpoint ban (`host:port`) remains a wildcard covering every
profile on that endpoint; a profile ban (`host:port#hash`) affects only that profile.
The header counts `host:port` endpoints separately from profile rows.

The editor is not a browser for the whole Happ subscription: only endpoints/profiles
whose full xray config has been captured (or that are active, used, or banned) can
appear. See the capture workflow below to add missing servers.

### Capturing all servers / duplicate endpoints

Happ keeps generated xray configs in its GUI memory. The most reliable ways to expose
them are:

1. **Start the capture loop first.** Happ keeps probe configs only temporarily and may
   free them as soon as the ping-all operation finishes, so do not wait until afterward
   to scan:

   ```powershell
   # terminal A - persistent snapshot loop (writes each complete config immediately)
   python capture-happ-memory.py --seconds 120 --interval 0.3
   ```

2. While that is running, open the Happ `...` menu and click **`Пинг всех`**. The
   scanner polls Happ/xray memory and writes every full config it sees to
   `captures/`; deduplication means repeated scans are safe. It cannot stop Happ from
   unloading memory, but the files are already on disk, so unload no longer matters.
3. Let it run for the full window (or until the process exits), then import the
   snapshots:

   ```powershell
   python import-happ-profiles.py --captures captures --dry-run
   python import-happ-profiles.py --captures captures
   ```

4. For a specific server that `Пинг всех` did not materialize, type its name in the
   Happ search box, right-click the row, choose **`Копировать JSON`**, and save the
   clipboard contents into `captures/`. This is the authoritative fallback and works
   even when another profile already owns the same `host:port`.

`R` in the watchdog is still useful for configs that are already in Happ's UTF-8
memory; it imports new `host:port` cache files and name aliases. It is not a substitute
for the capture loop when Happ has already discarded a transient probe config.

The importer creates `configs/<host>_<port>__<hash>.json` for every captured
single-server outbound whose credentials/transport differ from the endpoint's primary
config. It never overwrites an existing cache file. Multi-outbound group captures are
skipped because they represent a routing group rather than one server; their display
name is still imported as a normal `~` alias by the watchdog's memory rescan.
Placeholder hosts such as `auto-wifi.local`, `0.0.0.0`, and loopback addresses are
ignored because they cannot be used as a concrete proxy endpoint.

Two examples from a real subscription: India and Portugal share
`185.147.27.235:443` with different UUIDs, and Kazakhstan, Italy, and Australia share
`82.40.62.208:443`. Before profile support one name on each endpoint silently used the
other's credentials. Now each has its own key and is independently selectable/bannable.

Do not publish captured configs or `configs/*.json`: they contain connection
credentials. The importer is safe to keep in the repository; the cache is not.

### Active server tracking

The Happ registry only changes when the Happ GUI itself changes server; a pipe-based
switch does not update it. The watchdog therefore records the real active
endpoint/profile in `state.json` and the dashboard shows **that** value. It adopts the
registry again when its `host:port` **or profile name** changes (meaning you selected
another server in the Happ UI), and resolves the name to a captured profile when one
exists. This matters because two profiles can share `host:port` and differ only by name.
The displayed server name is read from the cached config's `remarks` field. If both the
state and the registry are blank (for example right after an upgrade), the watchdog
identifies the server from the core's dominant established connection to a cached
endpoint and records that once (profile identity cannot be inferred from the socket
alone, so it falls back to the endpoint).

This is also why the dashboard can show a different server than the Happ window after a
failover - the watchdog is right about the traffic path, and the GUI is still showing
its stale selection until you reconnect there.

New servers appear in the cache automatically as the Happ app generates their configs
(observatory probes, selections), so the pool grows over time. Use `Пинг всех` + `R`
and the profile importer (above) to seed it more completely.

## Requirements

- Windows 10/11, PowerShell 5.1
- Happ desktop client **running** and connected to your subscription (TUN mode with the
  xray core; `core\xray.exe`, `tun\sing-box.exe`)
- OpenCode with the background service and sessions in an OpenCode project (pass
  `-ProjectDir` or launch from the project directory)
- Elevation: OS-level killing of the GUI-owned core requires admin - the launcher
  self-elevates (one UAC prompt)

## Quick start

```powershell
git clone https://github.com/bloomstick/opencode-happ-watchdog.git
cd opencode-happ-watchdog
powershell -ExecutionPolicy Bypass -File .\create-shortcut.ps1   # desktop shortcut
```

Launch via the shortcut (or run `.\start-happ-failover.ps1`). The dashboard stays pinned
on top.

OpenCode project context defaults to the directory the watchdog is launched from. To
heal sessions in a specific project when launching the script directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -Watch -Interactive `
  -ProjectDir C:\path\to\your\project
```

## Dashboard and hotkeys

The dashboard shows live status: Happ GUI/core state, the active server, the number of
eligible servers for the next random pick, cache/used/banned stats, last failover, and a
rolling event log. Window resizes are debounced: the watchdog waits for the drag to
settle, re-applies the pinned buffer at the top-left, then redraws.

| key | action |
| --- | --- |
| `T` | switch to a random unused, unbanned server now (same flow as automatic failover) |
| `B` | ban the current server and switch away from it immediately |
| `L` | open the bans/server editor (banned first; arrows move, `Enter` toggles, `R` rescans, `Esc`/`L` closes) |
| `R` | rescan the Happ GUI memory for new server configs **and** re-prompt every session whose latest event is a failure |
| `C` | clear the used-server list; bans are unchanged |
| `Q` | quit (releases the owned core and tunnel; reconnect via the Happ GUI) |

## Diagnostics (no automatic switches)

```powershell
# state, active server, core, and fill the server cache
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestInit

# list sessions with current provider failures
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestSessions

# end-to-end continue-prompt probe on a throwaway session
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestProbe

# one manual random switch; verifies the new server but does not restart the app
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestSwitch
```

## Auto-start (optional)

```powershell
$tool = Join-Path $PWD.Path 'happ-failover.ps1'
$project = 'C:\path\to\your\project'
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
  '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Watch -ProjectDir "{1}"' -f $tool, $project
)
Register-ScheduledTask -TaskName 'opencode-happ-watchdog' -Action $act `
  -Trigger (New-ScheduledTaskTrigger -AtLogon) -RunLevel Limited
```

## Configuration

Top of `happ-failover.ps1`, the `$Script:Cfg` block (see the file for descriptions):

- `PollSeconds`, `CooldownSec` - loop cadence and the minimum pause between failovers
- `ContinueText` - prompt sent to stuck sessions (default `continue`)
- `ContinueDelaySec` - settle wait after the OpenCode restart before prompting
- `RestartOpenCode` - stop the desktop app before a switch and start it afterwards
  (default `$true`; when the app is not running, the background service is restarted)
- `OpenCodeExe`, `OpenCodeStopSec`, `OpenCodeStartSec` - desktop app path and timeouts
- `BansPath` - persistent ban list, separate from `state.json` (default `bans.json`)
- `TopLevelOnly` - skip subagent sessions when continuing (default `$true`)
- `MaxSwitchAttempts` - maximum candidate-selection passes per failover; each pass tries
  every eligible server in random order
- `RateLimitPattern`, `EndpointPattern`, `ConnResetPattern` - error classifiers
- `ConnResetWindowSec` / `ConnResetMinCount` / `ConnResetScanSec` - burst thresholds
- `TunnelScanSec`, `ProbeUrl2`, `ProbeTimeoutSec` - route-health probe settings

`-ProjectDir` overrides the OpenCode project context. `-PollSeconds` and `-CooldownSec`
are command-line overrides for the loop.

## Files created at runtime (gitignored)

- `state.json` - active server, used servers, prompted sessions, route/deadline markers,
  exit IP history
- `bans.json` - permanently banned servers; never cleared by the used-list reset
- `failover.log` - rolling transcript of everything the watchdog does
- `configs/*.json` - cached per-server xray config templates extracted from the Happ GUI
  process memory. **These contain your subscription's connection credentials - keep them
  private and never commit them.**
- `configs/<host>_<port>__<hash>.json` - profile-keyed config for a distinct
  credential/transport on a shared endpoint (also contains credentials; private).
- `captures/` - persistent raw snapshots from `capture-happ-memory.py`; **credentials,
  gitignored/private**.
- `capture-happ-memory.py` - continuous Happ/xray memory scanner. Start it before
  `Пинг всех`; it saves each complete config immediately so unloading cannot lose it.
- `import-happ-profiles.py` - converts full captured Happ/xray JSON files into profile
  cache entries; it skips groups and existing files and is safe to keep in the repo.

## Caveats

- The pipe switch restarts the xray core, so all traffic through Happ blips for a few
  seconds on every switch/revert.
- Every failover closes and relaunches the OpenCode desktop window. Run the watchdog
  from its desktop shortcut, not from a terminal inside OpenCode, otherwise the restart
  can take its own console down with the app.
- Stopping the GUI-owned core requires an OS-level kill (xray runs as SYSTEM), so either
  run the watchdog **elevated** (recommended) or accept one UAC prompt per switch.
- After a watchdog switch the Happ GUI keeps displaying the old server (the app's state
  is not notified). Traffic flows through the new server, as verified by the exit-IP and
  system-route checks. The dashboard tracks and shows the real active endpoint;
  reconnecting in the Happ UI hands the core back to the app.
- Exit while the watchdog owns the core+TUN (after a switch) and the daemon kills those
  records: the network drops until the next launch auto-recovers (~1 min; instant on
  later boots thanks to the persisted `tunSeen` marker).
- Template extraction depends on the GUI holding the live config in memory; a Happ
  update that changes the memory layout can break the scanner. The protocol notes in
  [PROTOCOL.md](PROTOCOL.md) make diagnosing that tractable.
- `Пинг всех` and targeted `Копировать JSON` are Happ UI actions; if Happ is not
  running there is nothing to capture. The watchdog's `R` scanner reads xray-style UTF-8
  configs; profile import reads the JSON files you captured. Some names exist only in
  Happ's UTF-16 UI model, so targeted copy/paste is the authoritative fallback.
- Only TUN mode with the xray core is wired up; proxy-only mode is not exercised by
  this tool.

## License

[MIT](LICENSE)

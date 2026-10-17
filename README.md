# OpenCode Happ Watchdog

An autonomous recovery watchdog for [OpenCode](https://opencode.ai) running behind the
[Happ](https://happ.su) proxy client on Windows. When your proxy provider misbehaves
(rate limits, dead connections, failed endpoints, a collapsed tunnel), the watchdog:

1. **detects** the failure class from OpenCode's log, its session API, and plain-route
   network probes,
2. **rotates** Happ to a previously **unused** server from your subscription — via the
   Happ daemon's own named-pipe protocol, no GUI automation,
3. **rebuilds** the xray core and the system-wide TUN (owned and verified),
4. **restarts** the OpenCode background service and
5. **sends `continue`** to every top-level session whose latest event is a failure,
   so work resumes where it stopped.

```
15:47:17 3 connection-loss failures within 180s - switching server
15:47:17 connection-loss burst (ECONNRESET); current server leaddemo (203.0.113.10:443) marked used
15:47:19 affected sessions: ses_1111111111aa, ses_2222222222bb, ses_3333333333cc
15:47:22 switching to 203.0.113.129:443 via daemon pipe (burst mode)...
15:47:39 TUN adapter up: happ-default-tun (Up)
15:47:41 SWITCH OK -> 203.0.113.129:443 (core exit IP: 203.0.113.129; system route: 203.0.113.129)
15:47:42 opencode service healthy after 1s (pid 9828)
15:47:49 continue -> ses_1111111111aa
15:47:49 failover complete
```

> **Status:** battle-tested nightly on one machine (TUN mode, xray core, PowerShell 5.1).
> The Happ daemon protocol findings are reverse-engineered - documented in
> [PROTOCOL.md](PROTOCOL.md). Not affiliated with Happ/FlyFrogLLC or OpenCode.

## Failure classes

| class | detection source | reaction |
| --- | --- | --- |
| rate | opencode.log tail (`Rate limit exceeded`, `Too many requests`) + session API | immediate failover |
| endpoint | session API (`Endpoint is unavailable`) | same-server `continue` retry after ~60s; switch after 2 failed rounds |
| connreset | session API (`ECONNRESET` / `Connection lost while reading the response`) | **>= 3 failures within 3 minutes -> failover** |
| tunnel-dead | plain system-route probes (two URLs, 30s cadence) | route dead twice in a row (~60s) -> failover; a vanished TUN adapter is restored directly |

Notable behaviors:

- **Idle-marker masking fix** - a session whose newest records are `idle`/system markers
  no longer masks an older provider failure underneath it; only a person-authored
  follow-up (a real user message) marks a session as "moved on".
- **Fresh-failure dedup** - once-prompted sessions are skipped only while their failure
  predates the last prompt; a *new* failure re-flags them.
- **LRU rotation** - when every cached server has been used once, the used-list resets
  (keeping the active server) and candidates retry least-recently-used first, so the
  pool never exhausts.
- **Boot recovery** - booting into an already-dead network (e.g. the previous watchdog
  exited while owning the tunnel) recovers on the first health tick, no cooldown wait.
- **Resize-proof pinned dashboard** - the console re-renders from an in-memory event
  ring; the status header always stays on top and log volume or window resizes can
  never scroll it away.

## Requirements

- Windows 10/11, PowerShell 5.1
- Happ desktop client **running** and connected to your subscription (TUN mode with the
  xray core; `core\xray.exe`, `tun\sing-box.exe`)
- OpenCode with the background service (`opencode service restart` is used) and sessions
  that live in an OpenCode project (pass `-ProjectDir` or launch from one)
- Elevation: OS-level killing of the GUI-owned core requires admin - the launcher
  self-elevates (one UAC prompt)

## Quick start

```powershell
git clone https://github.com/bloomstick/opencode-happ-watchdog.git
cd opencode-happ-watchdog
powershell -ExecutionPolicy Bypass -File .\create-shortcut.ps1   # desktop shortcut
```

Launch via the shortcut (or `powershell -ExecutionPolicy Bypass -File .\start-happ-failover.ps1`).
The dashboard stays pinned on top; keys:

| key | action |
| --- | --- |
| `T` | switch to a previously unused server now |
| `R` | rescan the Happ GUI memory for new server configs **and** re-prompt every failed session |
| `C` | clear the used-server list |
| `Q` | quit (releases the owned core + TUN - see caveats) |

OpenCode project context defaults to the directory the watchdog is launched from;
pass `-ProjectDir C:\path\to\your\project` to override.

## Diagnostics (no switches fired)

```powershell
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestInit       # state, server, core, fill cache
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestSessions   # list sessions with provider failures
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestProbe      # end-to-end continue-prompt probe on a throwaway session
```

## Configuration

Top of `happ-failover.ps1`, the `$Script:Cfg` block (see the file for descriptions):

- `PollSeconds`, `CooldownSec` - loop cadence and the minimum pause between failovers
- `ContinueText` - prompt sent to stuck sessions (default `continue`)
- `ContinueDelaySec` - settle wait after the OpenCode restart before prompting
- `RestartOpenCode`, `TopLevelOnly`, `MaxSwitchAttempts`
- `RateLimitPattern`, `EndpointPattern`, `ConnResetPattern` - error classifiers
- `ConnResetWindowSec` / `ConnResetMinCount` / `ConnResetScanSec` - burst thresholds
- `TunnelScanSec`, `ProbeUrl2`, `ProbeTimeoutSec` - route-health probe settings

## Files created at runtime (gitignored)

- `state.json` - used servers, prompted sessions, route/deadline markers, exit IP history
- `failover.log` - rolling transcript of everything the watchdog does
- `configs/*.json` - cached per-server xray config templates extracted from the Happ GUI
  process memory. **These contain your subscription's connection credentials - keep them
  private and never commit them.**

## Caveats

- Exit while the watchdog owns the core+TUN (after a switch) means the daemon kills
  those records: the network drops until the next launch auto-recovers (~1 min; instant
  on later boots thanks to the persisted `tunSeen` marker).
- After a watchdog switch the Happ GUI keeps displaying the old server (the app's state
  is not notified) - traffic flows through the new server, as verified by the exit-IP
  and system-route checks.
- Template extraction depends on the GUI holding the live config in memory; a Happ
  update that changes memory layout can break the scanner (protocol notes in
  [PROTOCOL.md](PROTOCOL.md) make diagnosing that tractable).
- Only TUN mode with the xray core is wired up; proxy-only mode exists but is not
  exercised by this tool.

## License

[MIT](LICENSE)

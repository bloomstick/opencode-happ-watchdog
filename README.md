# OpenCode Happ Watchdog

An autonomous recovery watchdog for [OpenCode](https://opencode.ai) running behind the
[Happ](https://happ.su) proxy client on Windows. When the provider misbehaves - rate
limits, free-usage quota, dead connections, failed endpoints, a collapsed tunnel - the
watchdog rotates Happ to a random unused server, restarts the OpenCode background
service (a full desktop-app restart is available as an option), and resumes every
affected top-level session **in a fork** so the flagged session is never reused on the
new exit IP.

```
15:47:17 3 connection-loss failures within 180s - switching server
15:47:17 connection-loss burst (ECONNRESET); current server leaddemo (203.0.113.10:443) marked used
15:47:19 affected sessions: ses_1111111111aa, ses_2222222222bb, ses_3333333333cc
15:47:22 switching to 203.0.113.129:443 via daemon pipe (burst mode)...
15:47:39 TUN adapter up: happ-default-tun (Up)
15:47:41 SWITCH OK -> 203.0.113.129:443 (core exit IP: 203.0.113.129; system route: 203.0.113.129)
15:47:42 opencode desktop healthy after 1s (pid 9828)
15:47:49 session ses_1111111111aa burned by rate errors - forked to ses_4444444444dd ...
15:47:49 continue -> ses_4444444444dd
15:47:49 failover complete
```

> **Status:** battle-tested nightly on one machine (TUN mode, xray core, PowerShell 5.1).
> The Happ daemon protocol findings are reverse-engineered - documented in
> [PROTOCOL.md](PROTOCOL.md). Not affiliated with Happ/FlyFrogLLC or OpenCode.
>
> **Single source:** this repo's `happ-failover.ps1` is the one file maintained; a
> machine that runs it keeps a plain copy next to its runtime state (state.json,
> bans.json, logs) and launches the watchdog via a tiny wrapper that pins
> `-ProjectDir` to that machine's project root. CLI one-shot commands accept
> `-ProjectDir` too (otherwise the launch directory is used).

## What it does

1. **Watches** the OpenCode log (`~/.local/share/opencode/log/opencode.log`) for
   `Rate limit exceeded`, `Too many requests`, and free-usage errors
   (`Free usage limit reached`, `Free usage exceeded`), and the OpenCode session API
   for `Endpoint is unavailable`, connection-loss (`ECONNRESET`), and provider
   `Timed out waiting for response data` failures (neither resets nor timeouts reach
   the server log). An exact `Free usage limit reached.
   Subscribe to OpenCode Go to keep going: https://opencode.ai/go` error automatically
   bans the current server, as does an `Endpoint is unavailable` failure that arrives
   immediately after a failover `continue`. Automatic bans are shown in **orange** in
   the bans editor and listed first; manual bans stay red. Generic `Rate limit
   exceeded`/`Too many requests` failures only mark the server used (no ban).
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
   - every attempt is verified by an exit-IP test through the local socks port the
     TUN config forwards to (`127.0.0.1:10808` by default, read from `TunConfigPath`)
     plus a plain system-route check; dead/broken servers are skipped automatically.
     Generated configs - including the one restored after a failed switch - are
     normalized to that same port, so a captured template that used another port
     (for example `11231`) cannot leave the tunnel pointing at a dead socks listener
3. **Restarts the OpenCode background service**: by default the desktop app stays open
   and only the service is reloaded after the switch. `RestartOpenCodeApp` switches to
   the older full restart: the desktop app is stopped *before* the Happ server changes,
   so no stale HTTP/SSE connections survive the switch, then started again after the
   new server is verified (the watchdog waits for its API to become healthy).
4. **Sends a `continue` prompt** to every top-level OpenCode session whose latest
   visible event is a provider failure. Subagent sessions are skipped; they get
   re-spawned by their parent flow. Sessions already prompted are skipped only while
   their failure predates the last prompt, so a *new* failure always re-flags them.
5. **Captures the whole subscription on demand**: the dashboard's `U` button starts a
   continuous memory scan, you click Happ -> `...` -> `Пинг всех`, and `U` again stops
   the scan, imports the captured profiles, refreshes the cache, and makes every server
   available for rotation. `-CaptureAll` does the same from the command line.
6. **Lets you choose a failed session by name**: press `S` for a paginated list of every
   failed session (all ages) and choose `C` to fork/continue or `I` to ignore that
   session forever. The same menu is available from the command line as `-SessionMenu`.

State (active server, used servers, prompted sessions) is kept in `state.json`, so
"previously unused" is tracked across watchdog restarts. Banned servers live in a
separate `bans.json`; clearing the used list never un-bans anything.

Automatic failures use a **fast path**: no cache rescan when the cache is already
populated, no pre-switch session scan (the post-reload scan still runs), a short
OpenCode close grace, shorter daemon/TUN waits, two 4-second exit checks instead of
the full verify, and no plain-route probe. If another failure arrives within 180
seconds of a switch, the next switch may start after only **8 seconds** instead of
the normal two-minute cooldown. Quota errors bypass the cooldown entirely. Manual
`T`/`B` actions keep the thorough path.

### Failure classes and triggers

| class | detection source | reaction |
| --- | --- | --- |
| rate | opencode.log tail (`Rate limit exceeded`, `Too many requests`, `Free usage limit reached`, `Free usage exceeded`) + session API | fast failover; **marks the server used, no ban**; 8s cooldown after a recent switch |
| quota | exact `Free usage limit reached. Subscribe to OpenCode Go to keep going: https://opencode.ai/go` in the log | **auto-ban current server (orange)** + immediate fast failover, bypassing cooldown |
| endpoint | session errors (`Endpoint is unavailable`) | **auto-ban when it arrives immediately after a `continue` from the latest failover**; otherwise same-server `continue` retry after ~60s, switch after 2 failed rounds (used, no ban) |
| connreset | session API (`ECONNRESET` / `Connection lost while reading the response`) | **3 failures within 3 minutes -> failover** |
| timeout | session API (`Timed out waiting for response data`, `TimeoutError`, `ETIMEDOUT`) | failover; **auto-ban only when the timeout follows a `continue` from the latest failover within 120s** (fresh server, first request). A timeout after the server worked for a while - or after a revive/endpoint-retry `continue` - only marks it **used**, no ban |
| tunnel-dead | plain system-route probes (two URLs, 30s cadence) | route dead twice in a row (~60s) -> failover; a vanished TUN adapter is restored directly |

Notable behaviors:

- **Idle-marker masking fix** - a session whose newest records are `idle`/system markers
  no longer masks an older provider failure underneath it; only a person-authored
  follow-up (a real user message) marks a session as "moved on".
- **Fresh-failure dedup** - once-prompted sessions are skipped only while their failure
  predates the last prompt; a *new* failure re-flags them.
- **Fresh-resume window** - automatic post-switch resumes only consider failures at
  most `SessionResumeFreshMin` minutes old (default 15), using the error timestamp
  rather than the session's updated time; abandoned test sessions are left alone.
  `-ResumeStale` and the manual `R` revive use the wider `AffectedWindowMin`;
  `-ResumeSession ses_id` can force one failed session of any age.
- **Boot recovery** - booting into an already-dead network (e.g. the previous watchdog
  exited while owning the tunnel) recovers on the first health tick, no cooldown wait.
- **Resize-proof pinned dashboard** - the console re-renders from an in-memory event
  ring; the status header always stays on top and log volume or window resizes can
  never scroll it away.

Free-usage errors are OpenCode's free-model quota. The watchdog rotates immediately,
and the exact OpenCode Go free-usage message automatically bans the exhausted server.
If the quota is tied to the public exit IP, another subscription server can bring a
fresh window. Subscription pool IPs may be shared with other users, so a freshly
selected IP can already be partially burned; if rotation keeps landing on exhausted
IPs, the quota window itself is the remaining wait.

Automatic bans come from two sources: the exact OpenCode Go free-usage message, and
an `Endpoint is unavailable` failure that arrives **immediately after a `continue`
sent during the latest failover**. Generic `Rate limit exceeded`/`Too many requests`
errors still switch servers but only mark the server used; they never create a ban.
Endpoint failures that are not immediate take the soft path: a same-server `continue`
retry after ~60s, a second retry if a new endpoint error appears, then a switch
(used, no ban). A retry with no new endpoint error clears the state.
Automatic bans are stored as objects in `bans.json`
(`source: automatic`, `kind: auto`, `reason`, `at`); old timestamp-string bans remain
manual. An existing manual ban is never rewritten by the automatic path.

Provider timeouts are treated more carefully because they also occur on healthy
servers. A timeout auto-bans the current server only when it arrives **immediately
after a `continue` sent during the latest failover** (within `TimeoutInstantSec`,
default 120s) - the connect -> continue -> timeout pattern of a server that cannot
sustain the first request. If the server had been working for some time before the
timeout, or the timeout follows a later revive/endpoint-retry `continue`, the server
is only marked **used** and rotated away; it is not banned.

### Server exhaustion / rotation

When every eligible cached server has been used once, the watchdog starts **rotation
cycle 2**: the used-list resets (except the currently active server) and candidates are
retried in **random order**. Banned servers are not part of this pool and are never
re-introduced by a rotation reset. The event appears in the dashboard as
`rotation reset: all N unbanned cached servers used - cycling again in random order`.

### Session poisoning and automatic forks

Provider quota flags follow a session, not only an exit IP: prompting a flagged session
again from a freshly switched server can flag the new IP with its first request. After a
switch the watchdog therefore **forks** every session it is about to resume
(`POST /api/session/<id>/fork` - a local copy of the projected transcript, no provider
request and no quota use), tags the old session `[burned]`, and sends `continue` to the
fork. Burned sessions are never scanned or prompted again; their fork carries the work.

If a fork is flagged later it is forked again. `SessionForkMaxDepth` (default 15) caps the
chain per root session and `SessionForkMaxPerHour` (default 30) caps total forks to stop
a switch/fork runaway. Manual forks (session menu `F`, `-ForkSession`) ignore the depth
cap; the hourly valve still applies. A deleted fork is recreated on the next resume. The
mapping is kept in `state.json.sessions`; the dashboard shows a `burned` count.

Before any fork is made, every failover with rate-kind failures runs a canary gate: a
`.` prompt is sent to a brand-new session and its first response is checked. A canary
that **instantly hits the rate limit incriminates its server**: the watchdog auto-bans
it and fails over to the next candidate (up to `RateCanaryMaxAttempts` canary rounds
per failover), and the fork/continue phase only runs on a server whose canary came out
ok. If the canary hits the limit on every round, the failover aborts without forking
(the limit is account-wide) and the affected sessions stay flagged for the next scan.
The probe session is recorded as ignored (`rate-canary`) so the watchdog never scans,
resumes, forks, or continues the canary itself.

Automatic post-switch resumes only consider failures at most
`SessionResumeFreshMin` minutes old (default 15). The error timestamp is the deciding
clock, so opening an old session (which refreshes `updated`) does not make it eligible.
`-ResumeStale` and the manual `R` revive still scan `AffectedWindowMin` (default
120 min) and deliberately ignore the freshness cutoff. `-ResumeSession ses_...`
targets one failed session regardless of age. Both commands bypass the prompted-set
dedup, so they can retry a session that was prompted before.

### Failed-session menu

Press `S` in the dashboard (or run `-SessionMenu`) for a paginated list of every
session whose latest visible event is a provider failure, at any age. Each row shows
the session title, failure kind (`rate`, `quota`, `endpoint`, `timeout`, `connreset`),
and failure age. Select a number, then:

- `C` - fork the session and send `continue`, exactly like automatic recovery. The old
  session is burned and the fork becomes the live continuation.
- `F` - fork a fresh chain from the session, **ignoring the depth cap**, and send it a
  continue prompt. Use this when a chain hit `SessionForkMaxDepth` and you still want a
  manual continuation.
- `I` - ignore the session forever. The ignore is stored in `state.json.sessions`;
  automatic resume, the `R` revive, and the endpoint/timeout scan all skip it. The
  session is not deleted or modified.
- `B` - go back to the list; `Q` - quit; `N`/`P` - page.

The menu scans all ages, not just `AffectedWindowMin`, so old failed sessions are
reachable without knowing their ids. `-ListIgnored` shows ignored sessions and
`-UnignoreSession ses_...` clears one, so it can appear in the menu and be scanned
again; the prompted-set dedup still applies to automatic resumes. Explicit
`-ResumeSession ses_...` still works on an ignored session and leaves the ignore
record in place.

Restart the watchdog after updating the script so the dashboard loads the `S` key and
the ignore-aware scans. A standalone `-SessionMenu` saves the ignore immediately, but
a watchdog process started before the update will not honor it until restarted.

### Bans

Bans are deliberately different from the used-list:

- `state.json` records **used** servers; clearing them (`C`) makes them candidates again.
- `bans.json` records **banned** servers; they are *never* selected, including during
  rotation cycle 2. The only way back into the pool is to unban them explicitly.
- **Manual** bans (timestamp strings, `B`, command line, editor) render **red**.
- **Automatic** bans (objects with `kind: auto`: quota, or an endpoint/timeout failure
  immediately after a failover `continue`) render **orange** and are marked `[AUTO]`;
  the header shows their count. They are grouped first in the editor, before manual
  bans, and persist across restarts until unbanning.
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
used, or banned server is listed with its cached name, **automatic bans first (orange),
then manual bans (red), then available servers**. Use `Up`/`Down` (plus
`PgUp`/`PgDn`, `Home`/`End`) to move and press `Enter` to ban/unban the selected
server. `R` rescans the cache, and `Esc` or `L` closes the editor. The selection follows
the server if toggling moves it between the banned and unbanned groups. Automatic bans
use a 256-color ANSI orange when the terminal supports virtual-terminal colors; older
consoles fall back to dark yellow. The editor runs
as a fast modal loop (25 ms input polling) so movement stays responsive; automatic
watchdog polling pauses while it is open and resumes on close (the daemon heartbeat
continues). The server-name index is built once at watchdog startup and cached until
the config directory changes, so opening the editor does not block on parsing every
captured config.

Happ sometimes exposes several names for the same `host:port` (or a memory capture is
malformed). The editor lists those names as separate alias rows marked `~`; they share
one cache template and one endpoint ban. Distinct credentials/transports that happen to
use the same `host:port` are stored as **profile** rows marked `@`
(`configs/<host>_<port>__<hash>.json`, key `host:port#hash`); they are independently
selectable and bannable. An endpoint ban (`host:port`) remains a wildcard covering every
profile on that endpoint; a profile ban (`host:port#hash`) affects only that profile.
The header counts `host:port` endpoints separately from profile rows. Its first line
shows the total row count together with the number of cached files and endpoints; the
second line shows `showing X-Y of N`, because only the rows that fit in the window are
visible and the rest are reached by scrolling. If a profile has
its own exact ban **and** is also covered by an endpoint wildcard, `Enter` removes the
exact ban first and leaves the endpoint's separate ban in place; unban the endpoint row
to clear the wildcard.

The editor is not a browser for the whole Happ subscription: only endpoints/profiles
whose full xray config has been captured (or that are active, used, or banned) can
appear. See the capture workflow below to add missing servers.

### Continuous server update (`[U]` / `-CaptureAll`)

The dashboard now has a built-in update mode, so the capture workflow does not need a
second terminal. The watchdog starts the memory scanner as a child process, tails its
`CAPTURE` events into the dashboard log, and imports the snapshots when you stop it.

1. In the watchdog dashboard, press **`U`**. The header changes to
   `Capture: ON ...` and the event log says `continuous capture ON`.
2. Immediately open the Happ `...` menu and click **`Пинг всех`**. The scanner is already
   running; you do not have to race the first probe.
3. Let the ping run. Every materialized config appears as a `[capture] CAPTURE ...`
   event, and the file is written to `captures/` immediately.
4. Press **`U`** again. The watchdog stops the scanner, imports new profiles, rescans
   Happ memory for endpoint files and name aliases, and logs the refreshed cache count.
   Press **`L`** to see the full server list, or run `-ListServers` (below).

The tool cannot click `Пинг всех` for you: that is a Happ UI action and the daemon
protocol has no equivalent. The button only guarantees that capture is running before
the probes start and handles the import afterward.

The same flow is available without the interactive dashboard:

```powershell
# start capture, wait 180s for you to run Ping all, import, print the server list
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -CaptureAll -CaptureSeconds 180

# print the cached server list (endpoints + profiles, with active/used/banned tags)
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ListServers
```

`[U]` uses `CaptureWindowSec` (default 1800s) as a safety limit; pressing `U` again
stops earlier. `[U]` and `-CaptureAll` need Python 3 (`python` or `py -3`) because they
run the bundled `capture-happ-memory.py` scanner. Without Python, `R` still rescans
whatever configs are currently in Happ memory, but it cannot catch transient probe
configs after Happ unloads them.

### Manual capture (advanced)

Happ keeps generated xray configs in its GUI memory. The underlying manual workflow is
still useful for debugging or for a machine without Python integration:

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
ignored because they cannot be used as a concrete proxy endpoint. The watchdog and
importer understand VLESS, VMess, Trojan, and Hysteria2 outbounds, including the
Hysteria2 `settings.address`/`settings.port` form.

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
alone, so it falls back to the endpoint). Cached domain endpoints are resolved to
their A records for this comparison. If saved state exists but the core has been
running on a different endpoint for more than a minute, the watchdog corrects the
saved active server instead of continuing to trust stale state. When state and the
registry disagree but both endpoints have connections, the endpoint with the live
xray connections wins; this repairs state written by older builds that recorded the
registry snapshot without adopting its server. If the active server was selected in
Happ but its config was never captured, failover uses a valid cached full config as
the inbound/routing skeleton and replaces all server outbounds with the target; it
never reverts to that fallback server on a failed attempt.

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
- Python 3 **optional** - required for the `[U]` continuous update mode and
  `-CaptureAll` (the bundled `capture-happ-memory.py` / `import-happ-profiles.py`);
  the watchdog itself and `R` rescans work without it
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
eligible servers for the next random pick, cache/used/banned/burned stats, last failover,
and a rolling event log. Window resizes are debounced: the watchdog waits for the drag to
settle, re-applies the pinned buffer at the top-left, then redraws.

| key | action |
| --- | --- |
| `T` | switch to a random unused, unbanned server now (manual/thorough flow) |
| `B` | ban the current server and switch away from it immediately (manual ban = red) |
| `L` | open the bans/server editor (automatic bans first, then manual; arrows move, `Enter` toggles, `R` rescans, `Esc`/`L` closes) |
| `S` | open the failed-session menu (all ages; select a session to continue in a fork or ignore forever) |
| `R` | rescan the Happ GUI memory for new server configs **and** re-prompt every session whose latest event is a failure (manual revive; ignores the automatic `SessionResumeFreshMin` cutoff) |
| `U` | start/stop continuous server update; while it runs, click Happ -> `...` -> `Пинг всех`, then press `U` again to import and refresh the list |
| `C` | clear the used-server list; bans are unchanged |
| `Q` | quit (releases the owned core and tunnel; reconnect via the Happ GUI) |

## Diagnostics (no automatic switches)

```powershell
# continuous update: capture while you run Happ -> ... -> Пинг всех, then import
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -CaptureAll -CaptureSeconds 180

# list every cached endpoint/profile (active/used/banned tags included)
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ListServers

# state, active server, core, and fill the server cache
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestInit

# list sessions with current provider failures and the failure age
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestSessions

# end-to-end continue-prompt probe on a throwaway session
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestProbe

# one manual random switch; verifies the new server but does not restart the app
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -TestSwitch

# session recovery: force stale work, fork by hand, inspect, or clear the mapping
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ResumeStale
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ResumeSession ses_...
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -SessionMenu
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ForkSession ses_...
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ListBurned
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -UnburnSession ses_...
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ListIgnored
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -UnignoreSession ses_...
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
- `FastRetrySec` / `ConsecutiveWindowSec` - after a switch, a follow-up automatic
  failure within the window may switch again after only 8s (defaults 8 / 180)
- `FastVerifyTries` / `FastVerifyTimeoutSec` - fast-path exit checks (default 2 tries,
  4s each; quota errors bypass the cooldown)
- `QuotaBanPattern` - exact OpenCode Go free-usage message that triggers an automatic
  ban (orange)
- `ContinueText` - prompt sent to stuck sessions (default `continue`)
- `ContinueDelaySec` - settle wait after the OpenCode restart before prompting
- `RestartOpenCode` - restart opencode after a server switch (default `$true`)
- `RestartOpenCodeApp` - `$true` = the full restart: stop the desktop app before the
  switch and start it afterwards (old behaviour); `$false` (default) = leave the desktop
  app running and restart only the opencode background service
- `OpenCodeExe`, `OpenCodeStopSec`, `OpenCodeStartSec` - desktop app path and timeouts
- `BansPath` - persistent ban list, separate from `state.json` (default `bans.json`)
- `TopLevelOnly` - skip subagent sessions when continuing (default `$true`)
- `SessionForkEnabled` - fork a failed session before resuming it after a switch; the
  source is tagged `[burned]` and never prompted again (default `$true`)
- `SessionForkMaxDepth` / `SessionForkMaxPerHour` - fork-chain and total-per-hour caps
  (defaults 15 / 30); manual forks from the session menu and `-ForkSession` override the
  depth cap
- `RateCanaryText` / `RateCanaryWaitSec` - the `.` canary prompt sent to a brand-new
  session before each rate-affected failover's prompt phase, and how long to wait for
  its response (defaults `.` / 20)
- `RateCanaryMaxAttempts` - canary rounds per failover; each instant HIT auto-bans its
  server and switches to the next candidate before any fork is made (default 3)
- `SessionResumeFreshMin` - post-switch automatic resume ignores failures older than
  this many minutes (default 15); `-ResumeStale` and the manual `R` revive still use
  the wider `AffectedWindowMin` (default 120), while `-ResumeSession` can target one
  failed session of any age
- `MaxSwitchAttempts` - maximum candidate-selection passes per failover; each pass tries
  every eligible server in random order
- `RateLimitPattern`, `EndpointPattern`, `ConnResetPattern`, `TimeoutPattern` - error classifiers
- `ConnResetWindowSec` / `ConnResetMinCount` / `ConnResetScanSec` - burst thresholds
  and session-API scan cadence (the scan also collects endpoint failures)
- `TimeoutInstantSec` - a provider timeout or endpoint-unavailable error within this
  many seconds of a `continue` sent during the same failover auto-bans the freshly
  selected server (default 120s); later failures only mark it used
- `TunnelScanSec`, `ProbeUrl2`, `ProbeTimeoutSec` - route-health probe settings
- `CaptureWindowSec` / `CaptureIntervalSec` - `[U]` capture window (default 1800s,
  `U` stops earlier) and pause between memory scans (default 0.3s)
- `SocksPort` - fallback local socks port (`10808`) used only when the TUN config
  cannot be read; the real port is taken from `TunConfigPath` and every generated
  config's socks inbound is rewritten to it

`-ProjectDir` overrides the OpenCode project context. `-PollSeconds` and `-CooldownSec`
are command-line overrides for the loop.

## Files created at runtime (gitignored)

- `state.json` - active server, used servers, prompted sessions, session-to-fork burn
  mappings, forever-ignored sessions, route/deadline markers, exit IP history
- `bans.json` - permanently banned servers; never cleared by the used-list reset.
  Timestamp strings are manual (red); objects with `kind: auto` are automatic bans
  (orange: quota, or endpoint/timeout immediately after a failover continue)
- `failover.log` - rolling transcript of everything the watchdog does
- `configs/*.json` - cached per-server xray config templates extracted from the Happ GUI
  process memory. **These contain your subscription's connection credentials - keep them
  private and never commit them.**
- `configs/<host>_<port>__<hash>.json` - profile-keyed config for a distinct
  credential/transport on a shared endpoint (also contains credentials; private).
- `captures/` - persistent raw snapshots from `capture-happ-memory.py`; **credentials,
  gitignored/private**. `[U]`/`-CaptureAll` also write `capture-run.out.log` and
  `capture-run.err.log` there so the dashboard can tail scanner output.
- `capture-happ-memory.py` - continuous Happ/xray memory scanner. `[U]` starts it
  automatically; it saves each complete config immediately so unloading cannot lose it.
- `import-happ-profiles.py` - converts full captured Happ/xray JSON files into profile
  cache entries; it skips groups and existing files and is safe to keep in the repo.

## Caveats

- The pipe switch restarts the xray core, so all traffic through Happ blips for a few
  seconds on every switch/revert.
- Every failover closes and relaunches the OpenCode desktop window. Run the watchdog
  from its desktop shortcut, not from a terminal inside OpenCode, otherwise the restart
  can take its own console down with the app.
- After a failover the desktop app may reopen the burned session. The real continuation
  is the fork whose title ends with `(fork #N)`; the burned original is tagged
  `[burned]` and is never prompted by the watchdog again.
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

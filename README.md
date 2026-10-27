# OpenCode Happ Watchdog

An autonomous recovery watchdog for [OpenCode](https://opencode.ai) running behind the
[Happ](https://happ.su) proxy client on Windows. When the provider misbehaves - rate
limits, free-usage quota, dead connections, failed endpoints, a collapsed tunnel - the
watchdog rotates Happ to a random unused server, restarts the OpenCode background
service (a full desktop-app restart is available as an option), and resumes every
affected top-level session **in a fork** cut immediately before the failure. The fork
keeps all earlier work, receives the `continue` prompt, and the burned source is deleted
only after that prompt is accepted. The replacement fork is then opened in the desktop
app.

```
15:47:17 3 connection-loss failures within 180s - switching server
15:47:17 connection-loss burst (ECONNRESET); current server leaddemo (203.0.113.10:443) marked used
15:47:19 affected sessions: ses_1111111111aa, ses_2222222222bb, ses_3333333333cc
15:47:22 switching to 203.0.113.129:443 via daemon pipe (burst mode)...
15:47:39 TUN adapter up: happ-default-tun (Up)
15:47:41 SWITCH OK -> 203.0.113.129:443 (core exit IP: 203.0.113.129; system route: 203.0.113.129)
15:47:42 opencode desktop healthy after 1s (pid 9828)
15:47:49 session ses_1111111111aa burned by rate errors - forked to ses_4444444444dd ...
         (before msg_1111111111ee); the old session will not be prompted again
15:47:49 continue -> ses_4444444444dd
15:47:50 removed burned source ses_1111111111aa after fork ses_4444444444dd accepted the continue prompt
15:47:51 opened fork ses_4444444444dd in the opencode desktop
15:47:51 failover complete
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
   the server log). Only genuine `level=ERROR ... cause="AI.Error: ..."` records count;
   OpenCode's INFO `spawning process` lines (which echo shell command arguments) are
   ignored, so a tool or diagnostic command that merely mentions a rate-limit phrase
   cannot trigger a failover. Free-usage errors rotate to a fresh exit IP; the canary
   gate auto-bans a freshly selected server that instantly hits the quota and switches
   further before any fork. The current server is marked used, not banned. An
   `Endpoint is unavailable` failure that arrives immediately after a failover
   `continue` does auto-ban. Automatic bans are shown in **orange** in the bans editor
   and listed first; manual bans stay red. Generic `Rate limit exceeded`/`Too many
   requests` failures only mark the server used (no ban).
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
4. **Forks, continues, and cleans up** every top-level OpenCode session whose latest
   visible event is a provider failure. The fork is cut immediately before the oldest
   recognized error in that turn, so all earlier work survives and the failing record
   does not. The fork gets a `continue` prompt; only after that prompt is accepted is
   the burned source deleted, and the fork is opened in the desktop app. Subagent
   sessions are skipped; they get re-spawned by their parent flow. Sessions already
   prompted are skipped only while their failure predates the last prompt, so a *new*
   failure always re-flags them.
5. **Captures the whole subscription on demand**: the dashboard's `U` button starts a
   continuous memory scan, you click Happ -> `...` -> `Пинг всех`, and `U` again stops
   the scan, imports the captured profiles, refreshes the cache, and makes every server
   available for rotation. `-CaptureAll` does the same from the command line.
6. **Lets you choose a failed session by name**: press `S` for a paginated list of every
   failed session (all ages) and choose `C` to fork/continue, `F` to force a fresh chain
   past the depth cap, `R` to reset that chain's fork counter, `O` to open the session in
   the desktop, or `I` to ignore the session forever. `C` and `F` use the same boundary
   fork, post-prompt cleanup, and desktop opening as automatic recovery. The same menu is
   available from the command line as `-SessionMenu`.

State (active server, used servers, prompted sessions, and session-to-fork mappings) is
kept in `state.json`, so "previously unused" is tracked across watchdog restarts.
Banned servers live in a separate `bans.json`; clearing the used list never un-bans
anything.

Automatic failures use a **fast path**: no cache rescan when the cache is already
populated, no pre-switch session scan (the post-reload scan still runs), a short
OpenCode close grace, shorter daemon/TUN waits, two 4-second exit checks instead of
the full verify, and no plain-route probe. If another failure arrives within 180
seconds of a switch, the next switch may start after only **8 seconds** instead of
the normal two-minute cooldown. Quota errors also bypass the cooldown. Manual `T`/`B`
actions keep the thorough path.

### Failure classes and triggers

| class | detection source | reaction |
| --- | --- | --- |
| rate | opencode.log tail (`Rate limit exceeded`, `Too many requests`) + session API | fast failover; **marks the server used, no ban**; 8s cooldown after a recent switch |
| quota | opencode.log tail (`Free usage limit reached` / `Free usage exceeded`, current or older wording) | fast switch to a fresh exit IP; **marks the current server used, no ban**; a canary quota hit **auto-bans the freshly selected target** and switches further with no round cap by default (optional `RateCanaryMaxAttempts`) |
| switch-verify | post-switch socks exit check | target marked used + reliability failure; **auto-ban once the original config or a later candidate verifies the tunnel**, so a dead server cannot return through the used-list rotation |
| endpoint | session errors (`Endpoint is unavailable`) | **auto-ban when it arrives immediately after a `continue` from the latest failover**; otherwise same-server `continue` retry after ~60s, switch after 2 failed rounds (used, no ban) |
| connreset | session API (`ECONNRESET` / `Connection lost while reading the response`) | **3 failures within 3 minutes -> failover**; the first failure within `StartupConnResetGraceSec` of launch gets one same-server `continue` retry first |
| timeout | session API (`Timed out waiting for response data`, `TimeoutError`, `ETIMEDOUT`) | failover; **auto-ban only when the timeout follows a `continue` from the latest failover within 120s** (fresh server, first request). A timeout after the server worked for a while - or after a revive/endpoint-retry `continue` - only marks it **used**, no ban |
| tunnel-dead | plain system-route probes (two URLs, 30s cadence) | route dead twice in a row (~60s) -> failover; within `StartupConnResetGraceSec` of launch, **restart the current server once before switching**; a vanished TUN adapter is restored directly |

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
- **Boot grace** - closing the watchdog can drop the owned tunnel and give the active
  session an `ECONNRESET` while the VPN reconnects. On the next launch, within
  `StartupConnResetGraceSec` (default 300s):
  - the first connection-loss failure, including one recorded just before launch
    within `StartupConnResetLookbackMin` (default 15 min), gets **one** same-server
    `continue` retry (no new fork); the retry waits until the tunnel probe succeeds;
  - the first dead system route gets **one** current-server core/TUN restart before
    any switch. If the rebuilt config fails but the original config verifies, the
    current server is kept. After a verified restart the OpenCode background service
    is reloaded once (the desktop stays open), so the first message after launch
    uses a fresh provider connection instead of hitting a stale `ECONNRESET`.

  Press `N` for the same current-server recovery on demand: restart the current
  server, reload the OpenCode background service, and continue recent
  `ECONNRESET`/timeout sessions in place without creating a new fork. `N` never
  switches, bans, or marks the server used.

  A server switch during the grace cancels the remaining retries. If a retry fails,
  normal connection-loss or tunnel rules apply.
- **Resize-proof pinned dashboard** - the console re-renders from an in-memory event
  ring; the status header always stays on top and log volume or window resizes can
  never scroll it away.

Free-usage errors are OpenCode's free-model quota. The watchdog rotates immediately,
and the canary gate auto-bans a freshly selected server that instantly hits the quota,
switching further before any fork. With the default `RateCanaryMaxAttempts = 0` there
is no canary round cap: it keeps trying until a clean server is found or no unbanned
candidate is left. If the quota is tied to the public exit IP, another subscription
server can bring a fresh window. Subscription pool IPs may be shared with other users,
so a freshly selected IP can already be partially burned; if rotation keeps landing on
exhausted IPs, the gate keeps switching until the candidate pool is exhausted, and the
quota window itself is the remaining wait. The current server is marked used, not
banned.

Automatic bans include an `Endpoint is unavailable` failure that arrives **immediately
after a `continue` sent during the latest failover**, a switch target whose post-switch
exit check fails once the restored original or a later candidate proves the local tunnel
works, and the instant rate/timeout checks described below. A canary hit on a freshly
selected server - whether a generic rate limit or the free-usage quota - auto-bans that
server and switches further. A failed exit check is initially only used and
reliability-demoted; it is not banned while the whole network may be down, because
there is no evidence that the target itself is bad. Generic `Rate limit
exceeded`/`Too many requests` errors on the current server still switch but only mark
it used; they never create a ban.
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
re-introduced by a rotation reset. A target that fails its post-switch exit check is
auto-banned once a restore or a later switch proves the local tunnel works, so dead
servers do not keep coming back through cycle 2. If the whole local network is down,
nothing is banned because no working path exists to compare against. The event appears
in the dashboard as `rotation reset: all N unbanned cached servers used - cycling again
in random order`.

### Session poisoning, boundary forks, and cleanup

Provider quota flags follow a session, not only an exit IP: prompting a flagged session
again from a freshly switched server can flag the new IP with its first request. After a
switch the watchdog therefore **forks** every session it is about to resume
(`POST /api/session/<id>/fork` - a local copy of the projected transcript, no provider
request and no quota use), tags the old session `[burned]`, and sends `continue` to the
fork. Burned sessions are never scanned or prompted again; their fork carries the work.

The fork is cut at a **boundary immediately before the failure**, not at the end of the
transcript. The watchdog passes `{"before":"<message-id>"}` using the oldest recognized
error in the newest failure turn. The copied transcript therefore keeps every earlier
user prompt, assistant reply, tool call, and previous `continue`, but excludes the
poisoned assistant record (and the idle record that duplicates it). If the server rejects
the boundary, the watchdog logs a warning and falls back to a full-transcript fork rather
than losing the recovery. This keeps the work that led to the failure while preventing
the replacement from inheriting the failure record itself.

After the replacement fork **accepts** the `continue` prompt, the watchdog deletes the
burned source. The fork is linked through its `fork` field, not through `parentID`, so
deleting the source does not cascade into the replacement (the source's own subagent
children are removed with it). If the prompt is not accepted, the source and its mapping
stay in place so the next resume can retry. Cleanup is best-effort and recorded as
`deleted`, `gone`, or `failed` in `state.json.sessions`; set `SessionRemoveBurned =
$false` to keep the `[burned]` source instead.

If a fork is flagged later it is forked again. `SessionForkMaxDepth` (default 15) caps the
chain per root session and `SessionForkMaxPerHour` (default 30) caps total forks to stop
a switch/fork runaway. Manual forks (session menu `F`, `-ForkSession`) ignore the depth
cap; the hourly valve still applies. A deleted fork is recreated on the next resume. The
mapping is kept in `state.json.sessions`; the dashboard shows a `burned` count.

When a chain reaches the depth cap, automatic recovery stops forking that session.
Reset the per-session depth counter to zero with `-ResetForkCount ses_...` or `R` in the
failed-session action screen; automatic recovery can fork it again on the next pass. If
a burned source is named, the reset follows its recorded fork links to the live tip.
This does **not** clear the global hourly fork valve.

On success the watchdog also brings the desktop app to the front and opens the fork
through its command palette. UI Automation focuses the palette search box directly and
verifies that focus before typing the session id and pressing Enter. A missing palette,
missing UI Automation, or lost focus fails safe: the id is never sent to the chat
composer. `OpenForkInDesktop` (default `$true`) enables this, and
`OpenForkSearchDelayMs` tunes the wait after typing. Opening is best-effort; if it fails,
the fork remains available through the session menu.

Before any fork is made, every failover with rate-kind failures runs a canary gate: a
brand-new probe session is created in a temp sandbox (`RateCanaryDir`) with
session-level permissions that deny every tool, and it is asked to reply with exactly
`CANARY_OK` and not use tools, read files, or run commands. Its first response is
checked. The probe cannot read or modify the project. It is interrupted as soon as the
verdict is known or the wait expires, so a timed-out probe cannot keep working in the
background. A canary that **instantly hits a rate limit or the free-usage quota
incriminates its server**: the watchdog auto-bans it and fails over to the next
candidate. `RateCanaryMaxAttempts` defaults to `0` (no round cap), so the gate keeps
switching until a clean server is found or no unbanned candidate remains; a positive
value restores an optional hard round cap. The fork/continue phase only runs on a
server whose canary came out ok. If the candidate pool is exhausted, the failover ends
without forking and the affected sessions stay flagged for the next scan. The watchdog
also ignores rate/quota log lines written by its own canary sessions and by
already-burned sources, so a probe cannot trigger a second failover after the gate has
already decided.
A canary blocked by a provider-account credit error (OpenRouter: "This request
requires more credits, or fewer max_tokens... adjust the key's total limit", matched
via `CreditsErrorPattern`) is neither a rate limit nor evidence against the server: it
ends the failover quietly without banning or re-switching, while those sessions stay
tracked as rate-kind and auto-resume once the key's credit limit is raised.
The canary also verifies the responding assistant's model against `RateCanaryModel`:
a stale "model" default in `opencode.json` makes fresh sessions silently fall back to
another provider (seen: a paid `openrouter/...` key that credits-blocks every
request), so a mismatch yields the `wrong-model` verdict - the same
skip-without-bans handling plus a clear hint to fix the default model. The probe
session is recorded as ignored (`rate-canary`) so the watchdog never scans,
resumes, forks, or continues the canary itself.

Automatic post-switch resumes only consider failures at most
`SessionResumeFreshMin` minutes old (default 15). The error timestamp is the deciding
clock, so opening an old session (which refreshes `updated`) does not make it eligible.
`-ResumeStale` and the manual `R` revive still scan `AffectedWindowMin` (default
120 min) and deliberately ignore the freshness cutoff. `-ResumeSession ses_...`
targets one failed session regardless of age. Both commands bypass the prompted-set
dedup, so they can retry a session that was prompted before. Every path that forks and
sends a prompt - automatic recovery, `-ResumeStale`, `-ResumeSession`, and menu `C`/`F` -
uses the same failure boundary, post-prompt source cleanup, and desktop opening.
`-ForkSession` stops after creating and opening the fork: it sends no prompt, so it
deliberately leaves the source in place.

### Failed-session menu

Press `S` in the dashboard (or run `-SessionMenu`) for a paginated list of every
session whose latest visible event is a provider failure, at any age. Each row shows
the session title, failure kind (`rate`, `quota`, `endpoint`, `timeout`, `connreset`),
and failure age. Select a number, then:

- `C` - fork the session at the failure boundary and send `continue`, exactly like
  automatic recovery. The old session is burned; after the fork accepts the prompt the
  source is deleted, and the fork is opened in the desktop app.
- `F` - fork a fresh chain from the session, **ignoring the depth cap**, and send it a
  continue prompt. It uses the same boundary, post-prompt cleanup, and desktop opening.
  Use this when a chain hit `SessionForkMaxDepth` and you still want a manual
  continuation.
- `R` - reset the per-session fork-depth counter. The screen shows `N/<cap> forks used`;
  when it is at or over the cap, automatic resume can fork the session again after the reset.
  This does not send a prompt and does not clear the global hourly fork valve.
- `O` - open the selected session in the desktop app through its command palette. Use this
  when the automatic fork opening failed or you only need to bring the session forward.
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
- **Automatic** bans (objects with `kind: auto`: an endpoint/timeout failure
  immediately after a failover `continue`, an instant canary rate/quota hit, or a
  failed switch target confirmed by a restored/later server) render **orange** and are
  marked `[AUTO]`; the header shows
  their count. They are grouped first in the editor, before manual bans, and persist
  across restarts until unbanning.
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
| `S` | open the failed-session menu (all ages; select a session to continue in a fork, reset its fork counter, open it in the desktop, or ignore forever) |
| `R` | rescan the Happ GUI memory for new server configs **and** re-prompt every session whose latest event is a failure (manual revive; ignores the automatic `SessionResumeFreshMin` cutoff) |
| `N` | reconnect now: restart the current server once, reload the OpenCode background service, and continue recent `ECONNRESET`/timeout sessions in place without creating a new fork; never switches, bans, or marks the server used |
| `U` | start/stop continuous server update; while it runs, click Happ -> `...` -> `Пинг всех`, then press `U` again to import and refresh the list |
| `C` | clear the used-server list; bans are unchanged |
| `Q` | quit (releases the owned core and tunnel; reconnect via the Happ GUI). The next launch gives the first ECONNRESET one same-server retry and a dead route one current-server restart before switching |

While a failover is running, `L` stays usable so you can inspect or edit bans during the
long network waits. Other dashboard hotkeys pressed during a failover are ignored (the
reason is logged) instead of being replayed in a batch after it finishes; `Ctrl+C` still
exits immediately. The bans editor caches its server list, so only the first open after
startup or after the cache, bans, used list, or active server changes rebuilds it.

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

# session recovery: force stale work, inspect, or clear the mapping
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ResumeStale
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ResumeSession ses_...
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -SessionMenu

# manual boundary fork: opens the fork in the desktop but sends no prompt and
# deliberately keeps the source (no continue was accepted, so nothing is deleted)
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ForkSession ses_...

# burn mappings and cleanup state; the boundary is shown as "before msg_..."
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ListBurned

# close desktop tabs left behind for sessions already recorded as deleted/gone;
# also runs automatically every StaleTabSweepSec (live session titles are protected)
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -CloseStaleTabs

# restore a [burned] source title and clear its mapping; if the source was already
# deleted after a successful prompt, only the stale mapping is cleared
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -UnburnSession ses_...

# open an existing session in the desktop; useful when automatic fork opening failed
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -OpenSession ses_...

# retry cleanup of a burned source whose replacement fork already accepted the
# continue prompt; verifies the fork exists and refuses a pre-prompt delete
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -CleanupBurnedSession ses_...

# reset the per-session fork depth so automatic recovery can fork the chain again
# (alias: -ResetForkDepth); follows a burned source to its live fork tip
powershell -ExecutionPolicy Bypass -File .\happ-failover.ps1 -ResetForkCount ses_...

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
  4s each)
- `AutoBanFailedSwitch` - auto-ban a switch target whose post-switch exit check failed,
  once the restored original or a later candidate proves the tunnel works (default
  `$true`). This removes dead servers from future rotation cycles without mass-banning
  the pool during a local/global outage. Set `$false` to keep failures used-only
- `QuotaBanPattern` - free-usage quota classifier. A canary quota hit auto-bans the
  freshly selected server and switches further, like a generic rate-limit hit. The
  default matches the current and older OpenCode free-usage wordings
- `ContinueText` - prompt sent to stuck sessions (default `continue`)
- `ContinueDelaySec` - settle wait after the OpenCode restart before prompting
- `RestartOpenCode` - restart opencode after a server switch (default `$true`)
- `RestartOpenCodeApp` - `$true` = the full restart: stop the desktop app before the
  switch and start it afterwards (old behaviour); `$false` (default) = leave the desktop
  app running and restart only the opencode background service
- `OpenCodeCli` - explicit CLI path; empty (default) resolves the CLI bundled with the
  desktop app (`resources\opencode-cli.exe`) or the newest staged copy under
  `%APPDATA%\ai.opencode.desktop\cli`. The npm `opencode` on PATH is only a fallback:
  an older npm CLI can spawn a mismatched second service that races the app's own
  supervisor and can drop the GUI
- `RecoverOpenCodeApp` - relaunch the desktop app if it disappears during a service
  restart and was running before the failover (default `$true`)
- `OpenCodeExe`, `OpenCodeStopSec`, `OpenCodeStartSec` - desktop app path and timeouts
- `BansPath` - persistent ban list, separate from `state.json` (default `bans.json`)
- `TopLevelOnly` - skip subagent sessions when continuing (default `$true`)
- `SessionForkEnabled` - fork a failed session at the newest failure boundary before
  resuming it after a switch; the source is tagged `[burned]` and never prompted again
  (default `$true`)
- `SessionForkMaxDepth` / `SessionForkMaxPerHour` - fork-chain and total-per-hour caps
  (defaults 15 / 30); manual forks from the session menu and `-ForkSession` override the
  depth cap. `-ResetForkCount ses_...` or menu `R` resets a chain's depth counter so
  automatic recovery can fork it again; the hourly valve is global and is not reset
- `SessionRemoveBurned` - after the replacement fork accepts its `continue` prompt,
  open it, then delete the burned source and close its desktop tab (default `$true`).
  Tab titles are normalized for status prefixes such as `D ` and `L `; a periodic sweep
  catches tabs left behind by an earlier cleanup or an app that did not refresh the tab
  title. Set `$false` to keep the `[burned]` session and its mapping. The fork is not a
  `parentID` child, so it survives; the source's own subagent children are deleted with
  it. The outcome is stored as `cleanup` in `state.json.sessions`; retry a failed cleanup
  with `-CleanupBurnedSession ses_...` (the command requires a recorded accepted prompt)
- `OpenForkInDesktop` - bring the desktop app forward and open the replacement fork in
  its command palette (default `$true`). UI Automation focuses a shell button (not the
  chat composer), verifies the palette and keyboard focus before the session id is typed,
  and falls back to the alternate `Ctrl+Shift+P` binding. A missing palette cannot send
  the id as a chat prompt; if UI Automation is unavailable, opening fails safe. Opening
  is best-effort; retry manually with `-OpenSession ses_...` or menu `O`
- `OpenForkSearchDelayMs` - wait after typing the session id before pressing Enter
  (default 1200 ms)
- `StaleTabSweepSec` - every N seconds (default 300) scan the desktop tab strip for tabs
  belonging to sessions recorded as deleted/gone and close them. This is a backstop for
  cleanup races and leftovers; it normalizes status prefixes such as `D ` and skips any
  title that still belongs to a live session, so it cannot close the active fork. Set `0`
  to disable. `-CloseStaleTabs` runs one sweep immediately
- `RateCanaryText` / `RateCanaryWaitSec` - the fixed canary prompt sent to a brand-new
  sandboxed session before each rate-affected failover's prompt phase, and how long to
  wait for its response. The default asks for exactly `CANARY_OK` and forbids tool use
  (default wait 15s)
- `RateCanaryDir` - temp sandbox for the canary session (default
  `%TEMP%\opencode-happ-canary`). Every probe is created there with session-level
  permissions denying all tools, and is interrupted after the verdict or timeout. It
  never runs in the project directory
- `RateCanaryMaxAttempts` - canary rounds per failover; each instant HIT auto-bans its
  server and switches to the next candidate before any fork is made. `0` (default)
  means no round cap: keep switching until a clean server or no unbanned candidate is
  left. A positive value is an optional hard safety cap.
- `SessionResumeFreshMin` - post-switch automatic resume ignores failures older than
  this many minutes (default 15); `-ResumeStale` and the manual `R` revive still use
  the wider `AffectedWindowMin` (default 120), while `-ResumeSession` can target one
  failed session of any age
- `MaxSwitchAttempts` - maximum candidate-selection passes per failover; each pass tries
  every eligible server in random order
- `RateLimitPattern`, `EndpointPattern`, `ConnResetPattern`, `TimeoutPattern` - error classifiers
- `ConnResetWindowSec` / `ConnResetMinCount` / `ConnResetScanSec` - burst thresholds
  and session-API scan cadence (the scan also collects endpoint failures)
- `StartupConnResetGraceSec` - after launch, within this many seconds (default 300),
  the first connection-loss failure gets one same-server `continue` retry and the
  first dead system route gets one current-server core/TUN restart before a switch;
  set `0` to disable both. `StartupConnResetLookbackMin` (default 15) also includes
  a connection-loss failure recorded just before launch, such as when closing the
  previous watchdog dropped the tunnel
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
  mappings (including the fork boundary, source-cleanup result, and last fork-counter
  reset), forever-ignored sessions, route/deadline markers, exit IP history
- `bans.json` - permanently banned servers; never cleared by the used-list reset.
  Timestamp strings are manual (red); objects with `kind: auto` are automatic bans
  (orange: endpoint/timeout immediately after a failover continue, an instant canary
  rate/quota hit, or a failed switch target confirmed by a restored/later server)
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
- By default a failover restarts only the OpenCode background service; the desktop
  window stays open (`RestartOpenCodeApp = $false`). If the desktop process
  disappears during that restart (it was running before the failover), the watchdog
  relaunches it automatically (`RecoverOpenCodeApp`). Run the watchdog from its
  desktop shortcut, not from a terminal inside OpenCode, otherwise a full restart
  can take its own console down with the app.
- After a successful resume the replacement fork is opened in the desktop first, then
  the burned source is deleted and its desktop tab is closed. If the tab title carries a
  status prefix (seen: `D `) or the app did not refresh it, the periodic
  `StaleTabSweepSec` sweep or `-CloseStaleTabs` closes it later; the sweep skips any
  title that still belongs to a live session. Opening before deletion
  matters: deleting the active source switches the app to the “session cannot be found”
  screen, where the palette shortcut is unreliable. The fork is the live continuation and
  usually has a `(fork #N)` title; the short-lived source was tagged `[burned]` before deletion. If
  source cleanup fails, the log records the reason and the mapping stays visible in
  `-ListBurned`; retry with `-CleanupBurnedSession ses_...`. If opening the fork fails
  (desktop not running, UI Automation is unavailable, the palette was not found, or focus
  was lost), nothing was typed into the chat; open it manually with `-OpenSession ses_...`
  or menu `O`.
- Deleting the burned source also deletes its subagent child sessions, but not the
  replacement fork. Use `SessionRemoveBurned = $false` if those children must be kept.
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

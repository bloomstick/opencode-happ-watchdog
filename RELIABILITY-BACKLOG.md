# Reliability backlog

Date: 2026-10-26 (updated 2026-10-27)

This file records the 23:25:46 canary stop and the reliability changes that were
discussed but **not** approved/implemented. The canary round-cap removal and canary
isolation are in the current watchdog.

## Implemented now (approved)

- `RateCanaryMaxAttempts` is now `0` by default. `0` means no round cap: after an
  instant canary HIT the watchdog auto-bans that server and keeps switching to the
  next candidate until a clean server is found or no unbanned candidate is left.
- A positive `RateCanaryMaxAttempts` still works as an optional hard safety cap.
- The canary probe is now isolated: it is created in a temp sandbox
  (`RateCanaryDir`) with session-level permissions denying every tool, asks for a
  fixed `CANARY_OK` response, pins `RateCanaryModel`, and is interrupted after the
  verdict or timeout. It cannot read or modify the project.
- Bans remain permanent. The user explicitly chose to keep permanent bans.
- The running watchdog must be relaunched to load these changes. It is not restarted
  automatically.

## Why it stopped at 23:25:46

The failover did not crash. `RateCanaryMaxAttempts = 3` was reached after three
canary HITs, so `Invoke-Failover` logged "skipping the fork/continue phase" and
returned to idle. The affected session stayed flagged, and because it produced no
new rate log line the main loop had no new trigger. A manual `[T]` was needed.

With the new default the gate continues through further candidates instead of
stopping at three.

## Deferred changes (need explicit approval)

### 1. Auto-retry incomplete failovers

Today these paths return to idle and wait for a new log line or manual `T`/`B`:

- no alternative unbanned candidate,
- OpenCode did not come back,
- desktop could not be stopped,
- an optional positive canary cap was reached,
- the active server could not be read for banning.

Proposed implementation: `Invoke-Failover` tracks whether it reached
`failover complete`. On an incomplete attempt it schedules a retry with exponential
backoff (for example 30s, 60s, 120s, ... capped at 15 minutes), and the main watch
loop fires it when due. A successful failover resets the backoff. Provider-account
credit / wrong-model errors would not auto-retry because switching servers cannot
fix them.

### 2. Launcher crash supervisor

The current `start-happ-failover.ps1` runs the watchdog once; on a nonzero exit it
prints the code and waits for ENTER. Proposed: a loop that restarts the watchdog
after a short backoff when it exits with an error, while a clean `Q` (exit code 0)
still closes the console. Write restart events to `supervisor.log`.

Limitation: this cannot survive closing the console window or a reboot. For that,
a logon scheduled task (or service) would be needed.

### 3. Multi-day process persistence

The watchdog process currently exits without a `Q` line in many historical runs.
A logon-triggered scheduled task with "restart on failure" would keep it alive
across console closes/reboots. It needs a decision about whether the dashboard
should remain interactive (hotkeys `T`/`B`/`L`/`Q`) or run hidden.

### 4. Canary-ban TTL

As of 2026-10-26 the ban list had 191 entries: about 102 exit-check failures,
34 canary rate hits, 6 instant-rate hits, and 49 legacy/manual string bans. They
are permanent by user decision. If multi-day switching exhausts the unbanned pool,
revisit a TTL for canary-hit bans only (manual and exit-check bans stay permanent).
Do not auto-unban anything without approval.

### 5. Ban audit

Many exit-check failures may be false positives from local tunnel/network outages.
The `[L]` editor can audit them. Do not clear existing bans without approval.

## Operational notes

- Source: `C:\my\projects\local-ai\publish\opencode-happ-watchdog\`
- Deployed: `C:\my\projects\local-ai\tools\happ-failover\`
- Log: `C:\my\projects\local-ai\tools\happ-failover\failover.log`
- To load this change: press `Q` in the watchdog console, then launch the desktop
  shortcut again. Do not launch a second copy while the old one is still running;
  the single-instance mutex will make it exit.
- No commit or push has been made.

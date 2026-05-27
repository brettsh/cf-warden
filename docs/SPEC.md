# cf-warden

A lightweight Python daemon that monitors server health signals and automatically
switches Cloudflare's security mode via the Cloudflare API. Runs as a cron job
every minute.

## Problem

DDoS attacks cause high server load, but high load alone is not a reliable trigger
for Cloudflare's Under Attack Mode. Heavy legitimate tasks (e.g. PDF generation)
also spike CPU without a corresponding spike in incoming requests. A single-signal
trigger produces false positives.

## Solution

A multi-signal points-based scoring system. Each signal contributes points toward
a trigger threshold. No single signal can trigger attack mode on its own unless it
is extreme. This discriminates between legitimate load and actual attacks.

## Signals

### 1. CPU Load Average (1 minute)
- Read from /proc/loadavg
- Reflects server-wide CPU pressure
- Fast to read, no log parsing required

### 2. Request Rate (last 60 seconds)
- Count of requests in the last 60 seconds from the web server access log
- Supports nginx and Apache — timestamp extracted by regex matching
  [DD/Mon/YYYY:HH:MM:SS ±HHMM] regardless of surrounding field layout
- Read efficiently using Python reverse-read (seek from end, read backwards in
  chunks) — stops as soon as lines fall outside the 60-second window
- Reflects incoming traffic volume independent of CPU
- If the log file is unreadable, scores 0 for that signal, logs a WARNING, and
  sends one alert email subject to ALERT_COOLDOWN_SEC (same rate-limit as attack
  alerts) — daemon continues running with degraded signal
- Known gap: scores 0 during log rotation (1–2 runs max); acceptable because
  SCORE_CONFIRM_COUNT resets only if score genuinely drops, and load signal
  remains elevated during real attacks

## Behaviour

### Turning ON (attack mode)
- Score is calculated each run
- If score >= SCORE_TRIGGER for SCORE_CONFIRM_COUNT consecutive runs, switch to
  CF_ATTACK_MODE
- Consecutive count resets if score drops below threshold between runs

### Turning OFF (normal mode)
- Only switches off if currently in attack mode
- Uses 5-minute load average (LOAD_LOW_THRESHOLD) as the off signal — slower and
  more stable than 1-minute average
- Cooldown period (COOLDOWN_SEC) must have elapsed since last mode switch
- Both conditions must be true simultaneously

### First Run
- On first run (no state files), cf-warden reads the current security level from
  the CF API to initialise local state — ensuring deployment is non-destructive
  regardless of the zone's current state
- After initialisation, local state files are the source of truth for all runs

### API Failure Handling
- On a failed API call to switch modes, local state is NOT updated
- An alert is sent, the error is logged, and the next cron run retries naturally
- Optimistic state updates are never used — local state must reflect confirmed reality

### Cloudflare Ownership
- cf-warden is the sole owner of the zone's security level once deployed
- Local state files are the source of truth — the CF API is never read during
  normal runs (except `status`, which shows live CF mode for drift detection)
- Manual dashboard changes will be silently overwritten on the next auto transition

### Manual override
- Script accepts `enable` and `disable` arguments for manual control
- Manual override bypasses cooldown in both directions — always succeeds
  regardless of current state or time since last switch
- After a manual override the state machine resumes normally from the new state;
  cooldown timer resets so auto-off does not fire immediately after manual enable
- `status` prints a full snapshot: 1-min and 5-min load, request rate, score vs
  threshold, consecutive run count, local mode, live CF mode (read from API,
  shows "[in sync]" or "[DRIFT DETECTED]"), last switch time, cooldown remaining,
  and last alert time. If the API call fails, live CF mode shows "unknown (API error)"

## Email Alerts
- SMTP mode is auto-detected from port: 465 → SSL (`SMTP_SSL`), 587 → STARTTLS
  (`SMTP` + `starttls()`), all other ports → plain (`SMTP`, no encryption)
- SITE_NAME setting used in subject lines; defaults to CF_ZONE_ID if not set
- Alert templates:
  - Attack on:      "[cf-warden] Attack mode activated — {SITE_NAME}"
                    Body: load, score, request rate, switch time
  - Attack off:     "[cf-warden] Normal mode restored — {SITE_NAME}"
                    Body: load, switch time, attack duration
  - Switch failure: "[cf-warden] FAILED to switch mode — {SITE_NAME}"
                    Body: attempted mode, API error message, current local state
  - API/log error:  "[cf-warden] Error — {SITE_NAME}"
                    Body: error description and message
- Repeat alerts during sustained attack suppressed by ALERT_COOLDOWN_SEC
- Sent on: mode change, mode change failure, API read error
- Attack alerts suppressed during sustained attack via ALERT_COOLDOWN_SEC to avoid
  inbox flooding
- If SMTP_HOST is omitted, sends via the local `sendmail` binary; otherwise uses SMTP with auto-detected mode (465=SSL, 587=STARTTLS, other=plain)

## Concurrency
- A lockfile in STATE_DIR is acquired with an exclusive flock on startup
- If the lock is already held (previous run still executing), exit immediately
  with a log message — no work is done
- Lock is released automatically on process exit, including on crash

## State Files
- Stored in STATE_DIR
- Tracks: current mode, last switch timestamp, consecutive high-score count,
  last alert timestamp

## Logging
- Writes to LOG_FILE with timestamp prefix
- Configurable log level (INFO / DEBUG)
- Built-in size-based rotation via Python's RotatingFileHandler (stdlib)
- Defaults: 10MB max size, 3 backup files kept (LOG_MAX_BYTES, LOG_BACKUP_COUNT)

## Configuration Format
- Settings file uses simple KEY=VALUE pairs, one per line
- Comments with `#`, blank lines ignored
- No sections, no shell variable syntax
- Parsed with stdlib only (no configparser)

## Config Validation
- All required settings are validated at startup before any work is done
- Missing config file or missing required key exits immediately with a clear
  error message to stderr and a non-zero exit code
- CF_ATTACK_MODE and CF_NORMAL_MODE are validated against the known set of
  Cloudflare security levels: off, essentially_off, low, medium, high, under_attack
- No silent failures — a broken config must be visible in cron output

## Deployment
- Single Python file, no third-party dependencies (stdlib only)
- Runs via cron every minute
- Config loaded from external settings.conf (not committed to repo)
- Credentials never in code

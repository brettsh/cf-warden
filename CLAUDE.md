# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cf-warden is a single-file Python daemon that monitors server health signals and automatically switches Cloudflare's security level via the Cloudflare API. It runs as a cron job every minute. **No third-party dependencies — stdlib only.**

## Running / Testing

The main script is invoked directly:

```bash
python cf_warden.py              # normal cron run
python cf_warden.py status       # print current load, request rate, score, CF mode
python cf_warden.py enable       # manually activate attack mode
python cf_warden.py disable      # manually restore normal mode
```

There is no build step, no package manager, and no test framework defined yet.

## Configuration

Config lives in `settings.conf` (gitignored). Copy `settings.conf.example` and fill in values. See `docs/SETTINGS.md` for the full reference.

Key sections: Cloudflare credentials, SMTP for email alerts, scoring thresholds, state/log paths.

## Architecture

Everything lives in a single Python file (`cf_warden.py`). The key subsystems:

**Signals** — two inputs read each run:
- CPU load: read from `/proc/loadavg` (1-minute average for ON trigger, 5-minute for OFF)
- Nginx request rate: count lines in the last 60 seconds of the access log using `tac` (reverse read, stops early once outside the window)

**Scoring** — each signal earns base points if above its threshold, plus bonus points if above a higher threshold. Total score is compared against `SCORE_TRIGGER`. See `docs/SCORING.md` for the points table and example scenarios.

**State machine** — state is persisted to files in `STATE_DIR`:
- Tracks: current mode, last switch timestamp, consecutive high-score count, last alert timestamp
- ON: score >= `SCORE_TRIGGER` for `SCORE_CONFIRM_COUNT` consecutive runs
- OFF: 5-min load below `LOAD_LOW_THRESHOLD` AND `COOLDOWN_SEC` elapsed since last switch

**Cloudflare API** — sets `security_level` on the zone via REST API using `CF_API_TOKEN`.

**Email alerts** — sent on mode change, mode change failure, or API read error. Repeat alerts during sustained attacks are suppressed by `ALERT_COOLDOWN_SEC`.

## Key Design Constraints

- A single signal at base threshold must NOT be able to trigger attack mode alone (requires combined signals or extreme bonus-point values)
- CPU-only spikes (e.g. PDF generation) must score too low to trigger
- Turning OFF uses the slower 5-minute load average to avoid premature deactivation
- No third-party libraries — everything must use Python stdlib

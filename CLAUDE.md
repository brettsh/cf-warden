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

There is no build step and no package manager. Tests use stdlib `unittest`:

```bash
python3 -m unittest discover -s tests -v
```

## Configuration

Config lives in `settings.conf` (gitignored). Copy `settings.conf.example` and fill in values. See `docs/SETTINGS.md` for the full reference.

Key sections: Cloudflare credentials, SMTP for email alerts, scoring thresholds, state/log paths.

## Architecture

Everything lives in a single Python file (`cf_warden.py`). The key subsystems:

**Signals** — two inputs read each run:
- CPU load: read from `/proc/loadavg` (1-minute average for ON trigger, 5-minute for OFF)
- Nginx request rate: count lines in the last 60 seconds of the access log using `tac` (reverse read, stops early once outside the window)

**Scoring** — proportional: `score = int(load1 / LOAD_SCORE_DIVISOR) + int(reqs / REQ_SCORE_DIVISOR)`. Total is compared against `SCORE_TRIGGER` (default 100). See `docs/SCORING.md` for example scenarios and calibration data.

**State machine** — state is persisted to files in `STATE_DIR`:
- Tracks: current mode, last switch timestamp, consecutive high-score count, last alert timestamp
- ON: score >= `SCORE_TRIGGER` for `SCORE_CONFIRM_COUNT` consecutive runs
- OFF: 5-min load below `LOAD_LOW_THRESHOLD` AND `COOLDOWN_SEC` elapsed since last switch

**Cloudflare API** — sets `security_level` on the zone via REST API using `CF_API_TOKEN`.

**Email alerts** — sent on mode change, mode change failure, or API read error. Repeat alerts during sustained attacks are suppressed by `ALERT_COOLDOWN_SEC`.

## Key Design Constraints

- Combined moderate signals (e.g. load=18 + 877 req/min) trigger attack mode
- Extreme single-signal values CAN trigger alone (e.g. load=28 or 2500 req/min)
- CPU-only spikes from legitimate tasks (e.g. PDF generation) must score too low to trigger
- High traffic with low load (legitimate busy periods) must not trigger
- Turning OFF uses the slower 5-minute load average to avoid premature deactivation
- No third-party libraries — everything must use Python stdlib

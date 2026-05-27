# cf-warden

A lightweight Python daemon that monitors server health signals and automatically
switches Cloudflare's security mode via the Cloudflare API. Runs as a cron job
every minute. No third-party dependencies — stdlib only.

## Why

DDoS attacks drive up both CPU load and request rate simultaneously. Legitimate
tasks (e.g. PDF generation) spike CPU without a request surge; legitimate busy
periods spike requests without stressing the CPU. A single-signal trigger
produces too many false positives.

cf-warden uses a proportional two-signal scoring system. Combined moderate
signals trigger attack mode; extreme values of a single signal also trigger.
This discriminates between legitimate load and real attacks.

## How it works

Each cron run:

1. Reads the 1-minute CPU load average from `/proc/loadavg`
2. Counts requests in the last 60 seconds from the nginx/Apache access log
3. Scores each signal proportionally: `int(load1 / LOAD_SCORE_DIVISOR) + int(reqs / REQ_SCORE_DIVISOR)`
4. If the total score reaches the trigger threshold for N consecutive runs,
   switches Cloudflare to `under_attack` mode via the API
5. Switches back to normal once the 5-minute load drops below the low threshold
   and the cooldown period has elapsed

See `docs/SCORING.md` for the full points table and `docs/SPEC.md` for
detailed behaviour.

## Requirements

- Python 3.6+
- A Cloudflare account with API token access to your zone
- nginx or Apache with a standard combined-format access log
- A cron daemon

## Installation

```bash
git clone https://github.com/brettsh/cf-warden.git
cd cf-warden
cp settings.conf.example settings.conf
```

Edit `settings.conf` with your Cloudflare credentials and thresholds. See
`docs/SETTINGS.md` for the full reference.

Add a cron entry to run every minute:

```
* * * * * /usr/bin/python3 /path/to/cf-warden/cf_warden.py >> /dev/null 2>&1
```

## Usage

```bash
python cf_warden.py              # normal cron run
python cf_warden.py status       # print current load, request rate, score, CF mode
python cf_warden.py enable       # manually activate attack mode
python cf_warden.py disable      # manually restore normal mode
```

`status` shows a full snapshot including local state, live Cloudflare mode
(with drift detection), cooldown remaining, and last alert time.

Manual `enable`/`disable` bypass the cooldown and scoring — they always succeed
regardless of current state. The state machine resumes normally from the new state.

## Configuration

All settings live in `settings.conf`. Key options:

| Setting | Description |
|---|---|
| `CF_ZONE_ID` | Cloudflare zone ID |
| `CF_API_TOKEN` | Cloudflare API token with zone edit permission |
| `CF_ATTACK_MODE` | CF security level to activate (default: `under_attack`) |
| `CF_NORMAL_MODE` | CF security level to restore (default: `medium`) |
| `SCORE_TRIGGER` | Score needed to activate attack mode (default: 100) |
| `SCORE_CONFIRM_COUNT` | Consecutive runs above threshold before switching (default: 1) |
| `COOLDOWN_SEC` | Minimum seconds between mode switches (default: 900) |
| `EMAIL_ENABLED` | Send email alerts on mode changes (true/false) |
| `DRY_RUN` | Simulate switches without calling the CF API (true/false) |

See `docs/SETTINGS.md` for all settings and their defaults.

## Email alerts

When `EMAIL_ENABLED=true`, cf-warden sends alerts on:

- Attack mode activated
- Normal mode restored
- Failed API call
- Access log read error

Repeat alerts during a sustained attack are suppressed by `ALERT_COOLDOWN_SEC`.
SMTP credentials are optional — if omitted, mail is sent via the local
`sendmail` binary.

## State and logging

State is persisted to files in `STATE_DIR` (default: `/var/tmp/cf-warden`).
Logs are written to `LOG_FILE` with automatic size-based rotation.

On first run, cf-warden reads the current security level from the Cloudflare API
to initialise local state, so deployment is non-destructive regardless of the
zone's existing configuration.

## License

MIT — see [LICENSE](LICENSE).

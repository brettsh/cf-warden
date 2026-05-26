# Settings Reference

All configuration lives in settings.conf (gitignored).
Copy settings.conf.example and fill in your values.

## Mode

| Setting | Example | Description |
|---------|---------|-------------|
| DRY_RUN | false   | Set to `true` to simulate mode switches without calling the CF API. State, scoring, and alerts behave normally — only the API call is skipped. |

## Cloudflare

| Setting         | Example              | Description                                      |
|-----------------|----------------------|--------------------------------------------------|
| CF_ZONE_ID      | abc123               | Cloudflare Zone ID for your domain               |
| CF_API_TOKEN    | your-token           | Cloudflare API token with Zone.Settings.Edit     |
| CF_ATTACK_MODE  | under_attack         | Security level to set during an attack           |
| CF_NORMAL_MODE  | medium               | Security level to restore after attack subsides  |

## Email Alerts

| Setting           | Example                    | Description                                  |
|-------------------|----------------------------|----------------------------------------------|
| EMAIL_ENABLED     | true                       | Enable or disable email alerts               |
| EMAIL_TO          | you@example.com            | Alert recipient                              |
| EMAIL_FROM        | alerts@example.com         | From address                                 |
| SMTP_HOST         | smtp.example.com           | SMTP server hostname                         |
| SMTP_PORT         | 587                        | SMTP port — auto-detects mode: 465=SSL, 587=STARTTLS, other=plain |
| SMTP_USERNAME     | user@example.com           | SMTP login username                          |
| SMTP_PASSWORD     | yourpassword               | SMTP login password                          |
| SITE_NAME         | example.com                | Site name used in alert email subjects; defaults to CF_ZONE_ID |

## Scoring — CPU Load

| Setting                   | Example | Description                                      |
|---------------------------|---------|--------------------------------------------------|
| LOAD_HIGH_THRESHOLD       | 12      | 1-min load above this scores LOAD_HIGH_POINTS    |
| LOAD_HIGH_POINTS          | 2       | Points awarded at base high load                 |
| LOAD_HIGH_BONUS_THRESHOLD | 20      | 1-min load above this adds LOAD_HIGH_BONUS_POINTS|
| LOAD_HIGH_BONUS_POINTS    | 2       | Bonus points for severe load                     |
| LOAD_LOW_THRESHOLD        | 6       | 5-min load below this allows turning OFF         |

## Scoring — Request Rate

| Setting                  | Example | Description                                         |
|--------------------------|---------|-----------------------------------------------------|
| REQ_HIGH_THRESHOLD       | 400     | Requests/60s above this scores REQ_HIGH_POINTS      |
| REQ_HIGH_POINTS          | 2       | Points awarded at base high request rate            |
| REQ_HIGH_BONUS_THRESHOLD | 800     | Requests/60s above this adds REQ_HIGH_BONUS_POINTS  |
| REQ_HIGH_BONUS_POINTS    | 2       | Bonus points for extreme request rate               |
| ACCESS_LOG_PATH          | /var/log/nginx/access.log | Path to web server access log (nginx or Apache) |
| ACCESS_LOG_WINDOW_SEC    | 60      | Seconds of log history to count requests from       |

## Trigger Behaviour

| Setting             | Example | Description                                            |
|---------------------|---------|--------------------------------------------------------|
| SCORE_TRIGGER       | 4       | Score must reach this to potentially trigger           |
| SCORE_CONFIRM_COUNT | 2       | Consecutive runs above SCORE_TRIGGER before switching  |
| COOLDOWN_SEC        | 900     | Seconds to wait after switching before switching back  |
| ALERT_COOLDOWN_SEC  | 900     | Seconds between repeat alert emails during an attack   |

## Paths and Logging

| Setting          | Example                | Description                                        |
|------------------|------------------------|----------------------------------------------------|
| STATE_DIR        | /var/tmp/cf-warden     | Directory for state files                          |
| LOG_FILE         | /var/log/cf-warden.log | Path to log file                                   |
| LOG_LEVEL        | INFO                   | INFO or DEBUG                                      |
| LOG_MAX_BYTES    | 10485760               | Rotate log when it reaches this size (default 10MB)|
| LOG_BACKUP_COUNT | 3                      | Number of rotated log files to keep                |

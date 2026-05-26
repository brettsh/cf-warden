# cf-warden — Domain Glossary

## Access Log
The web server's request log file. Used to measure the Request Rate signal.
Supports nginx and Apache: timestamp is extracted by regex matching
`[DD/Mon/YYYY:HH:MM:SS ±HHMM]` regardless of surrounding field layout.
Configured via `ACCESS_LOG_PATH`.

## Attack Mode
The Cloudflare security level active during a detected attack. Configured via
`CF_ATTACK_MODE` (default: `under_attack`). cf-warden owns this state once
deployed — manual dashboard changes will be overwritten on the next transition.

## Consecutive Run Count
The number of consecutive cron runs on which the Score has met or exceeded the
Score Trigger. Resets to zero if the score drops below the trigger between runs.
When it reaches `SCORE_CONFIRM_COUNT`, the ON transition fires.

## Cooldown
A mandatory waiting period (`COOLDOWN_SEC`) after any mode switch before the
auto-off condition can fire. Prevents rapid oscillation between modes. Does NOT
apply to Manual Override.

## Local State
The source of truth for cf-warden's current mode and timing. Stored as files in
`STATE_DIR`. Never reconciled against the live Cloudflare zone during normal
runs — cf-warden trusts its own state exclusively.

## Manual Override
Direct invocation of cf-warden with `enable` or `disable` arguments. Bypasses
Cooldown in both directions and always succeeds regardless of current state.
After a manual override, the state machine resumes normally and the cooldown
timer resets.

## Normal Mode
The Cloudflare security level when no attack is detected. Configured via
`CF_NORMAL_MODE` (default: `medium`).

## Request Rate Signal
Count of HTTP requests in the last `ACCESS_LOG_WINDOW_SEC` seconds, read from
the Access Log using Python's reverse-read (seek from end, no external binaries).
Scores zero if the log is unreadable; an alert is sent subject to Alert Cooldown.

## Score
An integer computed each run by summing points from all active signals. Compared
against the Score Trigger to determine whether to increment the Consecutive Run
Count.

## Score Trigger
The minimum Score that must be reached to increment the Consecutive Run Count
(`SCORE_TRIGGER`). A single signal at its base threshold cannot reach this value
alone — combined signals or extreme bonus values are required.

## Signal
A measurable server health input. cf-warden has two: CPU Load (from
`/proc/loadavg`) and Request Rate (from the Access Log). Each signal earns base
points if above its threshold, plus bonus points if above a higher threshold.

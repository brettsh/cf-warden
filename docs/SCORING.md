# Scoring System

cf-warden uses a points-based scoring system to determine whether to activate
Cloudflare Under Attack Mode. Multiple signals must confirm an attack before
the mode switches.

## Design Goals

- No single metric triggers attack mode at its base level
- Extreme values of a single metric CAN trigger alone (bonus points)
- CPU-only spikes (e.g. PDF generation) score too low to trigger
- Request-rate-only spikes score higher but still require confirmation runs
- Combined moderate signals trigger reliably

## Signals and Points

### CPU Load (1-minute average)

| Condition                        | Points |
|----------------------------------|--------|
| Load > LOAD_HIGH_THRESHOLD       | LOAD_HIGH_POINTS |
| Load > LOAD_HIGH_BONUS_THRESHOLD | + LOAD_HIGH_BONUS_POINTS (additive) |

### Nginx Request Rate (last 60 seconds)

| Condition                       | Points |
|---------------------------------|--------|
| Requests > REQ_HIGH_THRESHOLD   | REQ_HIGH_POINTS |
| Requests > REQ_HIGH_BONUS_THRESHOLD | + REQ_HIGH_BONUS_POINTS (additive) |

## Trigger

- Total score >= SCORE_TRIGGER for SCORE_CONFIRM_COUNT consecutive runs
  → switch to attack mode
- Score resets consecutive count if it drops below SCORE_TRIGGER between runs

## Example Configuration (suggested defaults)

| Setting                    | Value | Rationale                              |
|----------------------------|-------|----------------------------------------|
| LOAD_HIGH_THRESHOLD        | 12    | Verified high load                     |
| LOAD_HIGH_POINTS           | 2     | Base CPU signal                        |
| LOAD_HIGH_BONUS_THRESHOLD  | 20    | Severe load                            |
| LOAD_HIGH_BONUS_POINTS     | 2     | Alone still only 4 — needs req signal  |
| REQ_HIGH_THRESHOLD         | 400   | Above 99th percentile normal traffic   |
| REQ_HIGH_POINTS            | 2     | Base request signal                    |
| REQ_HIGH_BONUS_THRESHOLD   | 800   | Clear anomaly                          |
| REQ_HIGH_BONUS_POINTS      | 2     | Alone scores 4 — triggers at 800+      |
| SCORE_TRIGGER              | 4     | Require 2 strong signals               |
| SCORE_CONFIRM_COUNT        | 2     | Two consecutive runs before switching  |

## Example Scenarios

| Scenario                        | Load pts | Req pts | Total | Triggers? |
|---------------------------------|----------|---------|-------|-----------|
| PDF generation (CPU only)       | 2        | 0       | 2     | No        |
| Genuine traffic spike (req only)| 0        | 2       | 2     | No        |
| Moderate attack (both signals)  | 2        | 2       | 4     | Yes (x2)  |
| Severe attack (reqs only)       | 0        | 4       | 4     | Yes (x2)  |
| Extreme load + high reqs        | 4        | 2       | 6     | Yes (x2)  |

## Traffic Baseline (from log analysis)

| Metric          | Requests/min |
|-----------------|-------------|
| Mean            | ~125        |
| Median          | 99          |
| 95th percentile | 265         |
| 99th percentile | 434         |
| Maximum         | 3,100       |

Known attack pattern: 215 → 504 → 1145 → 3100 req/min over 4 minutes.
Note: Genuine spikes above 500 req/min are not uncommon — request rate alone
must not trigger attack mode at base threshold.

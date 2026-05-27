# Scoring System

cf-warden uses a proportional scoring system to determine whether to activate
Cloudflare Under Attack Mode. Each signal contributes points proportional to
its measured value; the total is compared against SCORE_TRIGGER.

## Design Goals

- Moderate signals from both sources together trigger attack mode
- Extreme values of a single signal CAN trigger alone
- CPU-only spikes (e.g. PDF generation) score too low to trigger
- Score scales continuously — 1500 req/60s outscores 1000 req/60s

## Formula

```
score = int(load1 / LOAD_SCORE_DIVISOR) + int(reqs / REQ_SCORE_DIVISOR)
```

### CPU Load (1-minute average)

| load1 | Score (LOAD_SCORE_DIVISOR=0.15) |
|-------|---------------------------------|
| 3     | 20                              |
| 6     | 40                              |
| 10    | 66                              |
| 15    | 100 ← triggers alone            |

### Nginx Request Rate (last 60 seconds)

| req/60s | Score (REQ_SCORE_DIVISOR=10) |
|---------|------------------------------|
| 125     | 12                           |
| 400     | 40                           |
| 800     | 80                           |
| 1000    | 100 ← triggers alone         |

## Trigger

- Total score >= SCORE_TRIGGER for SCORE_CONFIRM_COUNT consecutive runs
  → switch to attack mode
- Score resets consecutive count if it drops below SCORE_TRIGGER between runs

## Example Scenarios (suggested defaults, SCORE_TRIGGER=100)

| Scenario                            | Load pts | Req pts | Total | Triggers? |
|-------------------------------------|----------|---------|-------|-----------|
| Idle (load=1, reqs=50)              | 6        | 5       | 11    | No        |
| PDF generation (load=10, reqs=50)   | 66       | 5       | 71    | No        |
| Traffic spike only (load=2, reqs=600)| 13      | 60      | 73    | No        |
| Moderate attack (load=6, reqs=600)  | 40       | 60      | 100   | Yes       |
| Heavy attack (load=8, reqs=800)     | 53       | 80      | 133   | Yes       |
| Extreme req spike only (reqs=1000)  | 0        | 100     | 100   | Yes       |
| Extreme load only (load=15)         | 100      | 0       | 100   | Yes       |

## Traffic Baseline (from log analysis)

| Metric          | Requests/min |
|-----------------|-------------|
| Mean            | ~125        |
| Median          | 99          |
| 95th percentile | 265         |
| 99th percentile | 434         |
| Maximum         | 3,100       |

Known attack pattern: 215 → 504 → 1145 → 3100 req/min over 4 minutes.

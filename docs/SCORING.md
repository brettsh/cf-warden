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

### CPU Load (1-minute average, 8 Core Processor)

| load1 | Score (LOAD_SCORE_DIVISOR=0.27) |
| ----- | ------------------------------- |
| 3     | 11                              |
| 10    | 37                              |
| 17    | 62                              |
| 25    | 92                              |
| 28    | 103 ← triggers alone            |

### Nginx Request Rate (last 60 seconds)

| req/60s | Score (REQ_SCORE_DIVISOR=25) |
| ------- | ---------------------------- |
| 125     | 5                            |
| 500     | 20                           |
| 1000    | 40                           |
| 2500    | 100 ← triggers alone         |

## Trigger

- Total score >= SCORE_TRIGGER for SCORE_CONFIRM_COUNT consecutive runs  
→ switch to attack mode
- Score resets consecutive count if it drops below SCORE_TRIGGER between runs

## Example Scenarios (LOAD_SCORE_DIVISOR=0.27, REQ_SCORE_DIVISOR=25, SCORE_TRIGGER=100)

| Scenario                                   | Load pts | Req pts | Total | Triggers? |
| ------------------------------------------ | -------- | ------- | ----- | --------- |
| Idle (load=1, reqs=50)                     | 3        | 2       | 5     | No        |
| PDF generation (load=10, reqs=50)          | 37       | 2       | 39    | No        |
| High traffic, low load (load=3, reqs=1405) | 11       | 56      | 67    | No        |
| Transient load spike (load=25, reqs=50)    | 92       | 2       | 94    | No        |
| Moderate attack (load=17, reqs=877)        | 63       | 35      | 98    | No*       |
| Real attack (load=18, reqs=877)            | 66       | 35      | 101   | Yes       |
| Heavy attack (load=36, reqs=1138)          | 133      | 45      | 178   | Yes       |
| Extreme load only (load=28)                | 103      | 0       | 103   | Yes       |
| Extreme reqs only (reqs=2500)              | 0        | 100     | 100   | Yes       |

## Traffic Baseline (from log analysis)

| Metric          | Requests/min |
| --------------- | ------------ |
| Mean            | ~125         |
| Median          | 99           |
| 95th percentile | 265          |
| 99th percentile | 434          |
| Maximum         | 3,100        |

Known attack pattern: 215 → 504 → 1145 → 3100 req/min over 4 minutes.

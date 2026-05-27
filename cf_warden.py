#!/usr/bin/env python3
"""cf-warden: monitors server signals and switches Cloudflare security level."""

import fcntl
import json
import logging
import logging.handlers
import os
import re
import smtplib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path


VALID_CF_MODES = frozenset({'off', 'essentially_off', 'low', 'medium', 'high', 'under_attack'})
CF_API_BASE = 'https://api.cloudflare.com/client/v4'
LOG_TS_RE = re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]')
LOG_TS_FMT = '%d/%b/%Y:%H:%M:%S %z'
CONFIG_PATH = Path(__file__).parent / 'settings.conf'
CHUNK = 8192

REQUIRED = [
    'CF_ZONE_ID', 'CF_API_TOKEN', 'CF_ATTACK_MODE', 'CF_NORMAL_MODE',
    'EMAIL_ENABLED',
    'LOAD_SCORE_DIVISOR', 'LOAD_LOW_THRESHOLD',
    'REQ_SCORE_DIVISOR',
    'ACCESS_LOG_PATH', 'ACCESS_LOG_WINDOW_SEC',
    'SCORE_TRIGGER', 'SCORE_CONFIRM_COUNT',
    'COOLDOWN_SEC', 'ALERT_COOLDOWN_SEC',
    'STATE_DIR', 'LOG_FILE', 'LOG_LEVEL',
]
EMAIL_REQUIRED = ['EMAIL_TO', 'EMAIL_FROM']


# ── Config ────────────────────────────────────────────────────────────────────

def load_config():
    if not CONFIG_PATH.exists():
        _die(f"config file not found: {CONFIG_PATH}")

    cfg = {}
    with open(CONFIG_PATH) as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                _die(f"invalid config line {n}: {line!r}")
            k, _, v = line.partition('=')
            cfg[k.strip()] = v.strip()

    missing = [k for k in REQUIRED if k not in cfg]
    if missing:
        _die(f"missing required settings: {', '.join(missing)}")

    if cfg['EMAIL_ENABLED'].lower() == 'true':
        missing_e = [k for k in EMAIL_REQUIRED if k not in cfg]
        if missing_e:
            _die(f"EMAIL_ENABLED=true but missing: {', '.join(missing_e)}")

    for key in ('CF_ATTACK_MODE', 'CF_NORMAL_MODE'):
        if cfg[key] not in VALID_CF_MODES:
            _die(f"{key}={cfg[key]!r} is not a valid Cloudflare security level. "
                 f"Valid values: {', '.join(sorted(VALID_CF_MODES))}")

    cfg.setdefault('SITE_NAME', cfg['CF_ZONE_ID'])
    cfg.setdefault('LOG_MAX_BYTES', '10485760')
    cfg.setdefault('LOG_BACKUP_COUNT', '3')

    _INT_KEYS = [
        'REQ_SCORE_DIVISOR',
        'ACCESS_LOG_WINDOW_SEC', 'SCORE_TRIGGER', 'SCORE_CONFIRM_COUNT',
        'COOLDOWN_SEC', 'ALERT_COOLDOWN_SEC', 'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT',
    ]
    _FLOAT_KEYS = ['LOAD_SCORE_DIVISOR', 'LOAD_LOW_THRESHOLD']

    errors = []
    for k in _INT_KEYS:
        try:
            int(cfg[k])
        except (ValueError, KeyError):
            errors.append(f"{k} must be an integer (got {cfg.get(k)!r})")
    for k in _FLOAT_KEYS:
        try:
            float(cfg[k])
        except (ValueError, KeyError):
            errors.append(f"{k} must be a number (got {cfg.get(k)!r})")
    if 'SMTP_PORT' in cfg:
        try:
            int(cfg['SMTP_PORT'])
        except ValueError:
            errors.append(f"SMTP_PORT must be an integer (got {cfg['SMTP_PORT']!r})")

    if not errors:
        if float(cfg['LOAD_SCORE_DIVISOR']) <= 0:
            errors.append("LOAD_SCORE_DIVISOR must be greater than 0")
        if int(cfg['REQ_SCORE_DIVISOR']) <= 0:
            errors.append("REQ_SCORE_DIVISOR must be greater than 0")
        if cfg.get('SMTP_HOST') and cfg.get('SMTP_USERNAME') and 'SMTP_PASSWORD' not in cfg:
            errors.append("SMTP_USERNAME is set but SMTP_PASSWORD is missing")

    if errors:
        _die("config errors:\n  " + "\n  ".join(errors))

    return cfg


def _die(msg):
    print(f"cf-warden: {msg}", file=sys.stderr)
    sys.exit(1)


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(cfg):
    level = logging.DEBUG if cfg['LOG_LEVEL'].upper() == 'DEBUG' else logging.INFO
    h = logging.handlers.RotatingFileHandler(
        cfg['LOG_FILE'],
        maxBytes=int(cfg['LOG_MAX_BYTES']),
        backupCount=int(cfg['LOG_BACKUP_COUNT']),
    )
    h.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(h)


# ── State ─────────────────────────────────────────────────────────────────────

_DEFAULT_STATE = {'mode': 'normal', 'last_switch': 0.0, 'consecutive_count': 0, 'last_alert': 0.0}


def load_state(cfg):
    p = Path(cfg['STATE_DIR']) / 'state.json'
    if not p.exists():
        return None, False
    try:
        data = json.loads(p.read_text())
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        return data, False
    except Exception as exc:
        bad = p.with_suffix(f'.corrupt.{int(time.time())}')
        try:
            p.rename(bad)
            logging.warning("State file corrupt (%s) — saved as %s, bootstrapping from CF API", exc, bad.name)
        except OSError:
            logging.warning("State file corrupt (%s) — could not preserve, bootstrapping from CF API", exc)
        return None, True


def save_state(cfg, state):
    p = Path(cfg['STATE_DIR']) / 'state.json'
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(state))
    tmp.rename(p)


# ── Lock ──────────────────────────────────────────────────────────────────────

def acquire_lock(cfg):
    path = Path(cfg['STATE_DIR']) / 'cf-warden.lock'
    fd = None
    try:
        fd = open(path, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except PermissionError as exc:
        if fd is not None:
            fd.close()
        import pwd
        user = pwd.getpwuid(os.getuid()).pw_name
        _die(f"cannot acquire lockfile {path}: {exc}\n"
             f"Fix with: sudo chown {user} {path}")
    except OSError:
        if fd is not None:
            fd.close()
        return None


# ── Signals ───────────────────────────────────────────────────────────────────

def read_cpu_load():
    with open('/proc/loadavg') as fh:
        parts = fh.read().split()
    return float(parts[0]), float(parts[1])  # 1-min, 5-min


def _reverse_lines(path):
    with open(path, 'rb') as fh:
        fh.seek(0, 2)
        pos = fh.tell()
        pending = b''
        while pos > 0:
            n = min(CHUNK, pos)
            pos -= n
            fh.seek(pos)
            chunk = fh.read(n) + pending
            pending = b''
            lines = chunk.split(b'\n')
            if pos > 0:
                pending = lines[0]
                lines = lines[1:]
            for line in reversed(lines):
                if line:
                    yield line.decode('utf-8', errors='replace')


def count_requests(cfg):
    cutoff = time.time() - int(cfg['ACCESS_LOG_WINDOW_SEC'])
    count = 0
    for line in _reverse_lines(cfg['ACCESS_LOG_PATH']):
        m = LOG_TS_RE.search(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1), LOG_TS_FMT).timestamp()
        except ValueError:
            continue
        if ts < cutoff:
            break
        count += 1
    return count


# ── Scoring ───────────────────────────────────────────────────────────────────

def compute_score(cfg, load1, reqs):
    load_score = int(load1 / float(cfg['LOAD_SCORE_DIVISOR']))
    req_score = int(reqs / int(cfg['REQ_SCORE_DIVISOR']))
    return load_score + req_score


# ── CF API ────────────────────────────────────────────────────────────────────

def _cf_request(cfg, method, endpoint, body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        f"{CF_API_BASE}{endpoint}",
        data=data,
        method=method,
        headers={
            'Authorization': f"Bearer {cfg['CF_API_TOKEN']}",
            'Content-Type': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
        if not result.get('success'):
            raise RuntimeError(f"CF API error: {result.get('errors')}")
        return result
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode(errors='replace')}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(str(e.reason)) from e


def cf_get_mode(cfg):
    r = _cf_request(cfg, 'GET', f"/zones/{cfg['CF_ZONE_ID']}/settings/security_level")
    return r['result']['value']


def cf_set_mode(cfg, mode):
    if cfg.get('DRY_RUN', 'false').lower() == 'true':
        logging.info("DRY RUN: would set CF security level to %s (no API call made)", mode)
        return
    _cf_request(cfg, 'PATCH', f"/zones/{cfg['CF_ZONE_ID']}/settings/security_level", {'value': mode})


# ── Alerts ────────────────────────────────────────────────────────────────────

def _send_email(cfg, subject, body):
    if cfg['EMAIL_ENABLED'].lower() != 'true':
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = cfg['EMAIL_FROM']
    msg['To'] = cfg['EMAIL_TO']
    try:
        if not cfg.get('SMTP_HOST'):
            proc = subprocess.run(
                ['sendmail', '-t', '-oi'],
                input=msg.as_string().encode(),
                capture_output=True,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.decode(errors='replace').strip())
        else:
            host = cfg['SMTP_HOST']
            port = int(cfg.get('SMTP_PORT', '25'))
            if port == 465:
                smtp = smtplib.SMTP_SSL(host, port)
            else:
                smtp = smtplib.SMTP(host, port)
            with smtp as s:
                if port == 587:
                    s.ehlo()
                    s.starttls()
                    s.ehlo()
                if cfg.get('SMTP_USERNAME'):
                    s.login(cfg['SMTP_USERNAME'], cfg['SMTP_PASSWORD'])
                s.send_message(msg)
    except Exception as exc:
        logging.error("Email failed: %s", exc)


def _site(cfg):
    return cfg.get('SITE_NAME') or cfg['CF_ZONE_ID']


def alert(cfg, state, subject, body, rate_limit=True):
    now = time.time()
    if rate_limit and now - state.get('last_alert', 0) < int(cfg['ALERT_COOLDOWN_SEC']):
        logging.debug("Alert suppressed (cooldown): %s", subject)
        return
    _send_email(cfg, subject, body)
    state['last_alert'] = now


# ── Cron run ──────────────────────────────────────────────────────────────────

def run_cron(cfg, state):
    now = time.time()
    load1, load5 = read_cpu_load()

    reqs = 0
    try:
        reqs = count_requests(cfg)
    except Exception as exc:
        logging.warning("Access log unreadable: %s", exc)
        alert(cfg, state,
              f"[cf-warden] Error — {_site(cfg)}",
              f"Access log unreadable: {exc}\nRequest rate signal scoring 0.")

    score = compute_score(cfg, load1, reqs)
    trigger = int(cfg['SCORE_TRIGGER'])
    confirm = int(cfg['SCORE_CONFIRM_COUNT'])
    mode = state.get('mode', 'normal')

    logging.info("load1=%.2f load5=%.2f reqs=%d score=%d/%d mode=%s",
                 load1, load5, reqs, score, trigger, mode)

    if mode == 'normal':
        if score >= trigger:
            state['consecutive_count'] = state.get('consecutive_count', 0) + 1
            logging.info("High score %d/%d (run %d/%d)",
                         score, trigger, state['consecutive_count'], confirm)
            if state['consecutive_count'] >= confirm:
                try:
                    cf_set_mode(cfg, cfg['CF_ATTACK_MODE'])
                    state.update(mode='attack', last_switch=now, consecutive_count=0)
                    logging.info("Attack mode activated")
                    alert(cfg, state,
                          f"[cf-warden] Attack mode activated — {_site(cfg)}",
                          f"CPU Load: {load1:.2f}\n"
                          f"Requests: {reqs}/{cfg['ACCESS_LOG_WINDOW_SEC']}s\n"
                          f"Score: {score} (threshold: {trigger})\n"
                          f"Activated: {_ts(now)}",
                          rate_limit=False)
                except Exception as exc:
                    logging.error("Failed to activate attack mode: %s", exc)
                    alert(cfg, state,
                          f"[cf-warden] FAILED to switch mode — {_site(cfg)}",
                          f"Attempted: {cfg['CF_ATTACK_MODE']}\n"
                          f"Error: {exc}\n"
                          f"Local state unchanged: {mode}")
        else:
            if state.get('consecutive_count', 0):
                logging.debug("Score %d below trigger, resetting consecutive count", score)
            state['consecutive_count'] = 0

    elif mode == 'attack':
        elapsed = now - state.get('last_switch', now)
        cooldown = int(cfg['COOLDOWN_SEC'])
        load5_threshold = float(cfg['LOAD_LOW_THRESHOLD'])

        if load5 < load5_threshold and elapsed >= cooldown:
            try:
                cf_set_mode(cfg, cfg['CF_NORMAL_MODE'])
                state.update(mode='normal', last_switch=now, consecutive_count=0)
                logging.info("Normal mode restored (load5=%.2f elapsed=%.0fs)", load5, elapsed)
                alert(cfg, state,
                      f"[cf-warden] Normal mode restored — {_site(cfg)}",
                      f"Load (5-min): {load5:.2f}\n"
                      f"Restored: {_ts(now)}\n"
                      f"Attack duration: {_dur(elapsed)}",
                      rate_limit=False)
            except Exception as exc:
                logging.error("Failed to restore normal mode: %s", exc)
                alert(cfg, state,
                      f"[cf-warden] FAILED to switch mode — {_site(cfg)}",
                      f"Attempted: {cfg['CF_NORMAL_MODE']}\n"
                      f"Error: {exc}\n"
                      f"Local state unchanged: {mode}")
        else:
            reasons = []
            if load5 >= load5_threshold:
                reasons.append(f"load5={load5:.2f} >= {load5_threshold}")
            if elapsed < cooldown:
                reasons.append(f"cooldown {_dur(cooldown - elapsed)} remaining")
            logging.debug("Staying in attack mode: %s", ', '.join(reasons))

    save_state(cfg, state)


# ── Status ────────────────────────────────────────────────────────────────────

def cmd_status(cfg, state):
    load1, load5 = read_cpu_load()

    try:
        reqs = count_requests(cfg)
        reqs_display = f"{reqs} req/{cfg['ACCESS_LOG_WINDOW_SEC']}s"
    except Exception as exc:
        reqs = 0
        reqs_display = f"error: {exc}"

    score = compute_score(cfg, load1, reqs)
    trigger = int(cfg['SCORE_TRIGGER'])
    confirm = int(cfg['SCORE_CONFIRM_COUNT'])
    now = time.time()
    mode = state.get('mode', 'normal')
    expected_cf = cfg['CF_ATTACK_MODE'] if mode == 'attack' else cfg['CF_NORMAL_MODE']

    try:
        live_cf = cf_get_mode(cfg)
        sync = '[in sync]' if live_cf == expected_cf else '[DRIFT DETECTED]'
        cf_display = f"{live_cf}  {sync}"
    except Exception as exc:
        cf_display = f"unknown (API error: {exc})"

    last_switch = state.get('last_switch', 0)
    elapsed = now - last_switch if last_switch else None
    cooldown = int(cfg['COOLDOWN_SEC'])
    last_alert = state.get('last_alert', 0)

    print(f"Load (1min/5min):  {load1:.2f} / {load5:.2f}")
    print(f"Request rate:      {reqs_display}")
    print(f"Score:             {score}  (threshold: {trigger})")
    print(f"Consecutive runs:  {state.get('consecutive_count', 0)} / {confirm}")
    print(f"Local mode:        {mode}")
    print(f"CF live mode:      {cf_display}")
    if elapsed is not None:
        print(f"Last switch:       {_elapsed(elapsed)} ago  ({_ts(last_switch)})")
        if mode == 'attack':
            remaining = cooldown - elapsed
            if remaining > 0:
                print(f"Cooldown:          active, {_dur(remaining)} remaining")
            else:
                print(f"Cooldown:          elapsed")
    else:
        print(f"Last switch:       never")
    print(f"Last alert:        {_elapsed(now - last_alert) + ' ago' if last_alert else 'never'}")


# ── Manual override ───────────────────────────────────────────────────────────

def cmd_enable(cfg, state):
    target = cfg['CF_ATTACK_MODE']
    print(f"Activating {target}...")
    try:
        cf_set_mode(cfg, target)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        logging.error("Manual enable failed: %s", exc)
        alert(cfg, state,
              f"[cf-warden] FAILED to switch mode — {_site(cfg)}",
              f"Manual enable failed.\nAttempted: {target}\nError: {exc}",
              rate_limit=False)
        save_state(cfg, state)
        sys.exit(1)
    now = time.time()
    state.update(mode='attack', last_switch=now, consecutive_count=0)
    alert(cfg, state,
          f"[cf-warden] Attack mode activated — {_site(cfg)}",
          f"Manually activated.\nActivated: {_ts(now)}",
          rate_limit=False)
    save_state(cfg, state)
    print("Done.")


def cmd_disable(cfg, state):
    target = cfg['CF_NORMAL_MODE']
    print(f"Restoring {target}...")
    try:
        cf_set_mode(cfg, target)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        logging.error("Manual disable failed: %s", exc)
        alert(cfg, state,
              f"[cf-warden] FAILED to switch mode — {_site(cfg)}",
              f"Manual disable failed.\nAttempted: {target}\nError: {exc}",
              rate_limit=False)
        save_state(cfg, state)
        sys.exit(1)
    now = time.time()
    prior_mode = state.get('mode', 'normal')
    prior_switch = state.get('last_switch', 0)
    duration = now - prior_switch if prior_mode == 'attack' and prior_switch else None
    state.update(mode='normal', last_switch=now, consecutive_count=0)
    body = f"Manually restored.\nRestored: {_ts(now)}"
    if duration is not None:
        body += f"\nAttack duration: {_dur(duration)}"
    alert(cfg, state,
          f"[cf-warden] Normal mode restored — {_site(cfg)}",
          body, rate_limit=False)
    save_state(cfg, state)
    print("Done.")


# ── Formatting ────────────────────────────────────────────────────────────────

def _ts(epoch):
    return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')


def _elapsed(seconds):
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _dur(seconds):
    return _elapsed(seconds)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'run'
    if cmd not in ('run', 'status', 'enable', 'disable'):
        print(f"Usage: cf_warden.py [run|status|enable|disable]", file=sys.stderr)
        sys.exit(1)

    cfg = load_config()

    try:
        Path(cfg['STATE_DIR']).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _die(f"cannot create STATE_DIR {cfg['STATE_DIR']!r}: {exc}")

    if cmd == 'status':
        logging.basicConfig(level=logging.WARNING, handlers=[logging.NullHandler()])
        state, _ = load_state(cfg)
        state = state or dict(_DEFAULT_STATE)
        cmd_status(cfg, state)
        return

    try:
        setup_logging(cfg)
    except OSError as exc:
        _die(f"cannot open LOG_FILE {cfg['LOG_FILE']!r}: {exc}")

    lock_fd = acquire_lock(cfg)
    if lock_fd is None:
        logging.info("Another instance is running, exiting")
        sys.exit(0)

    try:
        state, was_corrupt = load_state(cfg)

        if state is None:
            logging.info("%s: bootstrapping state from CF API",
                         "Corrupt state file" if was_corrupt else "First run")
            try:
                live = cf_get_mode(cfg)
                initial = 'attack' if live == cfg['CF_ATTACK_MODE'] else 'normal'
                logging.info("CF live mode=%s → initial local mode=%s", live, initial)
            except Exception as exc:
                logging.warning("Bootstrap CF API read failed (%s) — assuming normal", exc)
                initial = 'normal'
            state = dict(_DEFAULT_STATE)
            state['mode'] = initial
            if initial == 'attack':
                state['last_switch'] = time.time()
            save_state(cfg, state)
            if was_corrupt:
                alert(cfg, state,
                      f"[cf-warden] State file corrupt — {_site(cfg)}",
                      f"State file was corrupt and could not be parsed.\n"
                      f"Bootstrapped from Cloudflare API: local mode set to {initial}.",
                      rate_limit=False)

        if cmd == 'run':
            run_cron(cfg, state)
        elif cmd == 'enable':
            cmd_enable(cfg, state)
        elif cmd == 'disable':
            cmd_disable(cfg, state)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


if __name__ == '__main__':
    main()

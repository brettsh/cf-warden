import io
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import cf_warden


def _cfg(load_divisor=0.27, req_divisor=25):
    return {'LOAD_SCORE_DIVISOR': str(load_divisor), 'REQ_SCORE_DIVISOR': str(req_divisor)}


class TestComputeScore(unittest.TestCase):

    # ── Formula ───────────────────────────────────────────────────────────────

    def test_zero_signals_score_zero(self):
        self.assertEqual(cf_warden.compute_score(_cfg(), 0.0, 0), 0)

    def test_load_only(self):
        # int(10.0 / 0.27) = 37
        self.assertEqual(cf_warden.compute_score(_cfg(), 10.0, 0), 37)

    def test_reqs_only(self):
        # int(500 / 25) = 20
        self.assertEqual(cf_warden.compute_score(_cfg(), 0.0, 500), 20)

    def test_combined(self):
        # int(17.05 / 0.27) + int(1145 / 25) = 63 + 45 = 108
        self.assertEqual(cf_warden.compute_score(_cfg(), 17.05, 1145), 108)

    # ── Real attacks — must score >= 100 ──────────────────────────────────────

    def test_may16_attack(self):
        score = cf_warden.compute_score(_cfg(), 17.05, 1145)
        self.assertGreaterEqual(score, 100, f"May 16 attack scored {score}, expected >= 100")

    def test_may19_attack_cpu_heavy(self):
        score = cf_warden.compute_score(_cfg(), 48.56, 449)
        self.assertGreaterEqual(score, 100, f"May 19 05:22 attack scored {score}, expected >= 100")

    def test_may19_attack_combined(self):
        score = cf_warden.compute_score(_cfg(), 51.38, 931)
        self.assertGreaterEqual(score, 100, f"May 19 08:46 attack scored {score}, expected >= 100")

    def test_may20_attack(self):
        score = cf_warden.compute_score(_cfg(), 17.99, 877)
        self.assertGreaterEqual(score, 100, f"May 20 attack scored {score}, expected >= 100")

    def test_may25_attack(self):
        score = cf_warden.compute_score(_cfg(), 25.07, 1192)
        self.assertGreaterEqual(score, 100, f"May 25 attack scored {score}, expected >= 100")

    # ── False positives — must score < 100 ───────────────────────────────────

    def test_fp_may6_transient_load_spike(self):
        score = cf_warden.compute_score(_cfg(), 24.89, 50)
        self.assertLess(score, 100, f"May 6 transient spike scored {score}, expected < 100")

    def test_fp_may20_0916_transient(self):
        score = cf_warden.compute_score(_cfg(), 25.15, 100)
        self.assertLess(score, 100, f"May 20 09:16 transient scored {score}, expected < 100")

    def test_fp_may21_high_traffic_low_load(self):
        score = cf_warden.compute_score(_cfg(), 3.4, 1405)
        self.assertLess(score, 100, f"May 21 high-traffic/low-load scored {score}, expected < 100")

    def test_fp_may19_blip(self):
        score = cf_warden.compute_score(_cfg(), 12.8, 100)
        self.assertLess(score, 100, f"May 19 blip scored {score}, expected < 100")


class TestConfigValidation(unittest.TestCase):

    _BASE_CFG = {
        'CF_ZONE_ID': 'zone123',
        'CF_API_TOKEN': 'token123',
        'CF_ATTACK_MODE': 'under_attack',
        'CF_NORMAL_MODE': 'medium',
        'EMAIL_ENABLED': 'false',
        'LOAD_SCORE_DIVISOR': '0.27',
        'LOAD_LOW_THRESHOLD': '4',
        'REQ_SCORE_DIVISOR': '25',
        'ACCESS_LOG_PATH': '/var/log/nginx/access.log',
        'ACCESS_LOG_WINDOW_SEC': '60',
        'SCORE_TRIGGER': '100',
        'SCORE_CONFIRM_COUNT': '1',
        'COOLDOWN_SEC': '600',
        'ALERT_COOLDOWN_SEC': '600',
        'STATE_DIR': '/tmp/cf-warden-test',
        'LOG_FILE': '/tmp/cf-warden-test.log',
        'LOG_LEVEL': 'INFO',
    }

    def setUp(self):
        self._tmp = Path(tempfile.mktemp(suffix='.conf'))
        self.addCleanup(self._tmp.unlink, missing_ok=True)

    def _write(self, overrides=None, omit=None):
        cfg = dict(self._BASE_CFG)
        if overrides:
            cfg.update(overrides)
        for k in (omit or []):
            cfg.pop(k, None)
        self._tmp.write_text('\n'.join(f'{k}={v}' for k, v in cfg.items()))

    def _load(self):
        with unittest.mock.patch('cf_warden.CONFIG_PATH', self._tmp):
            return cf_warden.load_config()

    def _assert_fails(self):
        with self.assertRaises(SystemExit), unittest.mock.patch('sys.stderr', io.StringIO()):
            self._load()

    def test_valid_config_loads(self):
        self._write()
        cfg = self._load()
        self.assertEqual(cfg['CF_ATTACK_MODE'], 'under_attack')

    def test_missing_required_key_rejected(self):
        self._write(omit=['CF_API_TOKEN'])
        self._assert_fails()

    def test_invalid_attack_mode_rejected(self):
        self._write(overrides={'CF_ATTACK_MODE': 'nuclear'})
        self._assert_fails()

    def test_invalid_normal_mode_rejected(self):
        self._write(overrides={'CF_NORMAL_MODE': 'normal'})
        self._assert_fails()

    def test_load_score_divisor_zero_rejected(self):
        self._write(overrides={'LOAD_SCORE_DIVISOR': '0'})
        self._assert_fails()

    def test_req_score_divisor_zero_rejected(self):
        self._write(overrides={'REQ_SCORE_DIVISOR': '0'})
        self._assert_fails()

    def test_non_numeric_load_divisor_rejected(self):
        self._write(overrides={'LOAD_SCORE_DIVISOR': 'fast'})
        self._assert_fails()


class TestStateMachineDrift(unittest.TestCase):

    def _cfg(self, state_dir, confirm='1'):
        return {
            'CF_ZONE_ID': 'zone123',
            'CF_API_TOKEN': 'token123',
            'CF_ATTACK_MODE': 'under_attack',
            'CF_NORMAL_MODE': 'medium',
            'EMAIL_ENABLED': 'false',
            'LOAD_SCORE_DIVISOR': '0.27',
            'LOAD_LOW_THRESHOLD': '4',
            'REQ_SCORE_DIVISOR': '25',
            'ACCESS_LOG_PATH': '/var/log/nginx/access.log',
            'ACCESS_LOG_WINDOW_SEC': '60',
            'SCORE_TRIGGER': '100',
            'SCORE_CONFIRM_COUNT': confirm,
            'COOLDOWN_SEC': '600',
            'ALERT_COOLDOWN_SEC': '600',
            'STATE_DIR': str(state_dir),
            'LOG_FILE': str(state_dir / 'cf-warden.log'),
            'LOG_LEVEL': 'INFO',
        }

    def _run(self, cfg, state, load=(1.0, 1.0), reqs=0, live='medium'):
        patches = [
            unittest.mock.patch('cf_warden.read_cpu_load', return_value=load),
            unittest.mock.patch('cf_warden.count_requests', return_value=reqs),
            unittest.mock.patch('cf_warden.cf_get_mode', return_value=live),
            unittest.mock.patch('cf_warden.alert'),
        ]
        with patches[0], patches[1], patches[2], patches[3]:
            with unittest.mock.patch('cf_warden.cf_set_mode') as set_mode:
                cf_warden.run_cron(cfg, state)
                return set_mode

    def test_normal_mode_restores_any_non_normal_drift_below_trigger(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(Path(d))
            state = dict(cf_warden._DEFAULT_STATE)
            set_mode = self._run(cfg, state, load=(1.0, 1.0), reqs=0, live='high')
            set_mode.assert_called_once_with(cfg, 'medium')
            self.assertEqual(state['mode'], 'normal')

    def test_normal_mode_restores_drift_while_confirmation_pending(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(Path(d), confirm='2')
            state = dict(cf_warden._DEFAULT_STATE)
            set_mode = self._run(cfg, state, load=(18.0, 1.0), reqs=877, live='high')
            set_mode.assert_called_once_with(cfg, 'medium')
            self.assertEqual(state['mode'], 'normal')
            self.assertEqual(state['consecutive_count'], 1)

    def test_normal_mode_adopts_live_attack_during_high_score_run(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(Path(d), confirm='2')
            state = dict(cf_warden._DEFAULT_STATE)
            set_mode = self._run(cfg, state, load=(18.0, 1.0), reqs=877, live='under_attack')
            set_mode.assert_not_called()
            self.assertEqual(state['mode'], 'attack')
            self.assertEqual(state['consecutive_count'], 0)

    def test_status_state_read_does_not_rename_corrupt_state(self):
        with tempfile.TemporaryDirectory() as d:
            state_path = Path(d) / 'state.json'
            state_path.write_text('{not json')
            cfg = self._cfg(Path(d))
            state, was_corrupt = cf_warden.load_state(cfg, preserve_corrupt=False)
            self.assertIsNone(state)
            self.assertTrue(was_corrupt)
            self.assertTrue(state_path.exists())
            self.assertFalse(list(Path(d).glob('state.corrupt.*')))


if __name__ == '__main__':
    unittest.main()

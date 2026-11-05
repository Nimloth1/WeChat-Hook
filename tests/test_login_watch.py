from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('login_watch', Path(__file__).parents[1] / 'tools/watch_login_pm.py')
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class LoginWatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        watch.LOG = Path(self.tmp.name) / 'login-watch.log'

    def report(self, **changes):
        return dict(version=1, computer='VW12', session=2, process_count=5,
                    observed_utc=datetime.fromtimestamp(1000, timezone.utc).isoformat(),
                    classes=[], ocr=[{'readable': True}], **changes)

    def test_main_is_not_login_proof(self):
        self.assertEqual(watch.classify(self.report(), 1001), 'no_login_prompt_observed')

    def test_security_precedes_main(self):
        r = self.report(); r['ocr'].append({'security_relogin': True})
        self.assertEqual(watch.classify(r, 1001), 'security_relogin_prompt')

    def test_login_signals(self):
        for flags in ({'qr_login': True}, {'confirm_login': True}):
            r = self.report(); r['ocr'] = [flags]
            self.assertEqual(watch.classify(r, 1001), 'login_prompt')
        r['ocr'] = []; r['classes'] = [{'provider': 'mmui::LoginWindow'}]
        self.assertEqual(watch.classify(r, 1001), 'login_prompt')

    def test_unknown_and_stale(self):
        for changes in ({'computer':'VW11'}, {'session':0}, {'ocr':[]}, {'observed_utc':'bad'}):
            r = self.report(); r.update(changes)
            self.assertEqual(watch.classify(r, 1001), 'unobservable')
        self.assertEqual(watch.classify(self.report(), 1721), 'unobservable')
        self.assertEqual(watch.classify(self.report(), 900), 'unobservable')

    def test_no_process(self):
        r = self.report(); r['process_count'] = 0
        self.assertEqual(watch.classify(r, 1001), 'client_not_running')

    def test_no_spam_or_noop_writes(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'state.json'; calls = []
            send = lambda title, body: calls.append((title, body)) or True
            watch.update(p, 'no_login_prompt_observed', send)
            self.assertEqual(calls, [])
            for state in ['security_relogin_prompt'] * 2 + ['no_login_prompt_observed'] * 2:
                watch.update(p, state, send)
            self.assertEqual(len(calls), 2)
            stamp = p.stat().st_mtime_ns
            watch.update(p, 'no_login_prompt_observed', send)
            self.assertEqual(p.stat().st_mtime_ns, stamp)

    def test_notification_failure_stays_reported_without_retry(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'state.json'; calls = []
            send = lambda *args: calls.append(args) or False
            self.assertTrue(watch.update(p, 'login_prompt', send))
            self.assertTrue(watch.update(p, 'login_prompt', send))
            self.assertEqual(len(calls), 1)
            self.assertTrue(json.loads(p.read_text())['notification_failed'])

    def run_states(self, states, rounds=2):
        p = Path(self.tmp.name) / 'state.json'; calls = []
        send = lambda title, body: calls.append(title) or True
        for state in states:
            watch.update(p, state, send, rounds)
        return p, calls

    def test_single_unobservable_jitter_is_silent_both_ways(self):
        ok = 'no_login_prompt_observed'
        p, calls = self.run_states([ok, 'unobservable', ok, 'unobservable', ok])
        self.assertEqual(calls, [])
        self.assertEqual(json.loads(p.read_text()), {'status': ok, 'notification_failed': False})
        self.assertIn('jitter unobservable 1/2', watch.LOG.read_text())

    def test_consecutive_unobservable_alerts_then_recovers(self):
        ok = 'no_login_prompt_observed'
        _, calls = self.run_states([ok, 'unobservable', 'unobservable', 'unobservable', ok])
        self.assertEqual(calls, [watch.ALERTS['unobservable'][0], 'VW12：登录提示已消失'])

    def test_rounds_one_keeps_immediate_alert(self):
        _, calls = self.run_states(['no_login_prompt_observed', 'unobservable'], rounds=1)
        self.assertEqual(len(calls), 1)

    def test_login_prompt_not_debounced_and_jitter_does_not_clear_it(self):
        _, calls = self.run_states(['no_login_prompt_observed', 'login_prompt',
                                    'unobservable', 'login_prompt'])
        self.assertEqual(calls, [watch.ALERTS['login_prompt'][0]])


if __name__ == '__main__':
    unittest.main()

"""School entry restrictions are distinct from passwords and uncertain delivery."""
import copy
import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_workflows as f
from dashboard_helpers import WebCase
from test_submission_diagnostics import DiagnosticTransport
from moonuestc.runner import account_key, run_account
from moonuestc.state import State

MESSAGE = '请从微信小程序重新进入打卡应用后提交'


class SchoolClientRequirement(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('MOON_TEST_TMP'))
        self.root = Path(self.temp.name)
        self.state = State(self.root)
        self.transport = DiagnosticTransport()

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def run_mode(self, account=None):
        return run_account(copy.deepcopy(account or f.ACCOUNT), 'checkin', self.state,
                           self.root, clock=lambda: self.transport.instant,
                           sleep=lambda _: None, transport_factory=lambda *a: self.transport)

    def reject(self, code=46001):
        self.transport.failure = (200, code, MESSAGE, False)
        return self.run_mode()

    def test_explicit_school_entry_rejection_is_not_unknown_or_password_failure(self):
        result = self.reject()
        self.assertEqual(result['result'], 'submission_rejected')
        self.assertEqual(result['reason'], 'school_client_required')
        self.assertEqual(result['apiCode'], 46001)
        self.assertEqual(result['schoolMessage'], MESSAGE)
        self.assertEqual(result['verification'][0]['status'], 'PENDING')
        self.assertEqual(self.transport.post_count, 1)
        self.assertIsNone(self.state.auth_requirement(account_key(f.ACCOUNT)))

    def test_reopen_next_day_preserves_guard_and_reads_without_new_submission(self):
        original = self.reject()['submission']
        self.state.close()
        self.state = State(self.root)
        self.assertTrue(self.state.school_client_requirement())
        result = self.run_mode()
        self.assertEqual(result['submission'], original)
        self.assertEqual(result['submissionAction'], 'recheck')
        self.transport.instant += dt.timedelta(days=1)
        result = self.run_mode()
        self.assertEqual(result['reason'], 'school_client_required')
        self.assertEqual(self.transport.post_count, 1)
        self.assertFalse(self.state.claimed(account_key(f.ACCOUNT), self.transport.instant.date().isoformat()))

    def test_known_restriction_applies_to_other_accounts_without_an_extra_post(self):
        self.reject()
        other = {**f.ACCOUNT, 'student_id': '202600000002'}
        result = self.run_mode(other)
        self.assertEqual(result['reason'], 'school_client_required')
        self.assertEqual(self.transport.post_count, 1)
        self.assertFalse(self.state.claimed(account_key(other), f.DAY))

    def test_sync_without_school_session_never_sends_saved_password(self):
        self.reject()
        self.transport.session = False
        before = list(self.transport.calls)
        result = self.run_mode()
        self.assertEqual(result['reason'], 'school_sync_login_required')
        self.assertEqual(result['submissionAction'], 'recheck')
        self.assertEqual(self.transport.calls, before)

    def test_server_expired_session_prompts_owner_recovery_without_password_post(self):
        self.reject()
        self.transport.unauthorized = True
        before = sum(stage=='cas_submit' for _,stage in self.transport.calls)
        self.assertEqual(self.run_mode()['reason'], 'school_sync_login_required')
        self.assertEqual(sum(stage=='cas_submit' for _,stage in self.transport.calls), before)
        self.assertEqual(self.transport.post_count, 1)

    def test_official_completion_can_still_be_confirmed_by_readback(self):
        self.reject()
        self.transport.status = 'CHECKED_IN'
        result = self.run_mode()
        self.assertEqual(result['result'], 'confirmed')
        self.assertEqual(self.transport.post_count, 1)
        self.assertTrue(self.state.school_client_requirement())

    def test_timeout_is_still_unknown_and_does_not_latch_client_restriction(self):
        self.transport.network = 'timeout'
        result = self.run_mode()
        self.assertEqual(result['result'], 'submission_unknown')
        self.assertIsNone(self.state.school_client_requirement())
        self.assertEqual(self.run_mode()['result'], 'submission_unknown')
        self.assertEqual(self.transport.post_count, 1)

    def test_server_error_with_same_number_is_not_an_explicit_entry_rejection(self):
        self.transport.failure = (500, 46001, MESSAGE, False)
        self.assertEqual(self.run_mode()['result'], 'submission_unknown')
        self.assertIsNone(self.state.school_client_requirement())

    def test_legacy_rejection_seeds_persistent_guard_without_changing_old_claim(self):
        key = account_key(f.ACCOUNT)
        self.state.claim(key, f.DAY)
        details = {'outcome': 'rejected', 'httpStatus': 200, 'apiCode': 46001,
                   'reason': 'business_error', 'stage': 'checkin_post', 'schoolMessage': MESSAGE}
        with self.state.db:
            self.state.db.execute('INSERT INTO submission_diagnostics VALUES(?,?,?)', (key, f.DAY, json.dumps(details)))
        self.state.close()
        self.state = State(self.root)
        self.assertTrue(self.state.school_client_requirement())
        self.assertEqual(self.state.submission(key, f.DAY), details)
        self.assertEqual(self.state.db.execute('SELECT outcome FROM claims WHERE account=? AND day=?', (key, f.DAY)).fetchone()[0], 'started')
        self.state.authentication_recovered(key, f.DAY)
        self.assertTrue(self.state.school_client_requirement())

    def test_related_school_operation_codes_have_same_required_official_entry(self):
        for code in (46002, 46003):
            self.assertTrue(self.state.require_school_client(code))
        self.assertFalse(self.state.require_school_client(4709))


class ExistingDashboardResults(WebCase):
    def test_legacy_error_is_explained_without_rewriting_historical_record(self):
        account = self.add_account()
        legacy = {'result': 'submission_unknown', 'reason': 'record_not_confirmed', 'retryExhausted': True,
                  'submission': {'outcome': 'rejected', 'httpStatus': 200, 'apiCode': 46001,
                                 'reason': 'business_error', 'stage': 'checkin_post', 'schoolMessage': MESSAGE}}
        jid = self.store.enqueue(self.u1, account['id'], 'checkin')
        with self.store.db(True) as db:
            db.execute("UPDATE web_jobs SET state='failed',result=? WHERE id=?", (json.dumps(legacy), jid))
            db.execute('UPDATE web_accounts SET last_result=? WHERE id=?', (json.dumps(legacy), account['id']))
        state = State(self.root)
        try:
            with state.db:
                state.db.execute('INSERT INTO submission_diagnostics VALUES(?,?,?)', (account_key(f.ACCOUNT), f.DAY, json.dumps(legacy['submission'])))
        finally:
            state.close()
        result = self.store.jobs(self.u1, jid)['result']
        self.assertEqual(result['result'], 'submission_rejected')
        self.assertEqual(result['reason'], 'school_client_required')
        self.assertNotIn('retryExhausted', result)
        current = self.store.accounts(self.u1)[0]
        self.assertTrue(current['school_checkin_required'])
        self.assertEqual(current['last_result']['reason'], 'school_client_required')
        with self.store.db() as db:
            self.assertEqual(json.loads(db.execute('SELECT result FROM web_jobs WHERE id=?', (jid,)).fetchone()[0]), legacy)
        self.assertEqual(self.req(self.c2, self.t2, '/api/jobs/' + jid).status_code, 404)

    def test_scheduler_waits_for_school_entry_without_enqueuing_futile_submissions(self):
        account = self.add_account()
        state = State(self.root)
        try:
            payload = self.store.job_payload({'account_id': account['id']})
            key = account_key(payload)
            state.claim(key, f.DAY)
            state.outcome(key, f.DAY, 'confirmed')
            state.require_school_client(46001)
        finally:
            state.close()
        with self.store.db(True) as db:
            db.execute('UPDATE web_accounts SET automatic=1 WHERE id=?', (account['id'],))
        with patch('moonuestc.web_service.now', return_value=f.INSTANT):
            self.worker.schedule_once()
        self.assertEqual(self.store.jobs(self.admin), [])
        self.assertTrue(self.store.accounts(self.u1)[0]['automatic'])

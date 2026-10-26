"""Successful verified sessions must not exhaust the password retry guard."""
import tempfile
import unittest
from pathlib import Path

import test_workflows as f
from moonuestc.runner import account_key,run_account
from moonuestc.state import State
from moonuestc.errors import ToolError


class LoginSuccessBudget(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.state=State(self.root)
        self.key=account_key(f.ACCOUNT)
    def tearDown(self):self.state.close();self.temp.cleanup()
    def count(self,key=None):
        row=self.state.db.execute('SELECT count FROM logins WHERE account=? AND day=?',(key or self.key,f.DAY)).fetchone()
        return row[0] if row else 0
    def test_successful_school_logins_do_not_accumulate_as_failed_retries(self):
        for _ in range(5):
            transport=f.FakeTransport()
            result=run_account(f.ACCOUNT,'diagnose',self.state,self.root,clock=lambda:f.INSTANT,sleep=lambda _:None,transport_factory=lambda *args:transport)
            self.assertEqual(result['result'],'auth_ready')
            self.assertEqual(transport.calls.count(('POST','cas_submit')),1)
        self.assertEqual(self.count(),5,'Keep the historical total for audit')
        self.assertFalse(self.state.login_exhausted(self.key,f.DAY))
    def test_three_unconfirmed_password_attempts_still_stop(self):
        for _ in range(3):self.state.login_budget(self.key,f.DAY)
        with self.assertRaises(ToolError) as caught:self.state.login_budget(self.key,f.DAY)
        self.assertEqual(caught.exception.reason,'daily_login_limit');self.assertEqual(self.count(),3)
    def test_verified_session_restores_retry_budget_without_deleting_history_or_claims(self):
        for _ in range(3):self.state.login_budget(self.key,f.DAY)
        self.state.require_interactive_auth(self.key,'daily_login_limit');self.state.claim(self.key,f.DAY)
        self.state.background_session_verified(self.key,f.DAY)
        self.assertEqual(self.count(),3);self.assertIsNone(self.state.auth_requirement(self.key))
        self.assertTrue(self.state.claimed(self.key,f.DAY))
        self.state.close();self.state=State(self.root)
        for _ in range(3):self.state.login_budget(self.key,f.DAY)
        with self.assertRaises(ToolError):self.state.login_budget(self.key,f.DAY)
        self.assertEqual(self.count(),6)
    def test_background_success_cannot_clear_school_captcha_mfa_or_rejected_password_guard(self):
        for reason in ('need_manual_captcha','need_manual_mfa','login_rejected'):
            key='synthetic-'+reason
            self.state.require_interactive_auth(key,reason)
            self.state.background_session_verified(key,f.DAY)
            self.assertEqual(self.state.auth_requirement(key),reason)
    def test_interactive_recovery_does_not_leave_an_old_success_checkpoint(self):
        self.state.login_budget(self.key,f.DAY);self.state.background_session_verified(self.key,f.DAY)
        self.state.authentication_recovered(self.key,f.DAY)
        for _ in range(3):self.state.login_budget(self.key,f.DAY)
        with self.assertRaises(ToolError):self.state.login_budget(self.key,f.DAY)
    def test_other_accounts_and_unknown_current_session_are_not_reset(self):
        for key in (self.key,'synthetic-other'):
            for _ in range(3):self.state.login_budget(key,f.DAY)
        self.state.background_session_verified(self.key,f.DAY)
        self.assertFalse(self.state.login_exhausted(self.key,f.DAY));self.assertTrue(self.state.login_exhausted('synthetic-other',f.DAY))
    def test_stale_school_record_does_not_restore_budget(self):
        for _ in range(3):self.state.login_budget(self.key,f.DAY)
        transport=f.FakeTransport();transport.session=True;transport.stale_day=True
        with self.assertRaises(ToolError):
            run_account(f.ACCOUNT,'diagnose',self.state,self.root,clock=lambda:f.INSTANT,sleep=lambda _:None,transport_factory=lambda *args:transport)
        self.assertTrue(self.state.login_exhausted(self.key,f.DAY))
    def test_wechat_business_identity_mismatch_does_not_restore_budget(self):
        from test_yyb_runner import Grant
        for _ in range(3):self.state.login_budget(self.key,f.DAY)
        transport=f.FakeTransport();transport.session=True;grant=Grant()
        def mismatch(school):raise ToolError('wechat_identity_mismatch','wechat_identity')
        grant.check_business=mismatch
        with self.assertRaises(ToolError):
            run_account(f.ACCOUNT,'diagnose',self.state,self.root,clock=lambda:f.INSTANT,sleep=lambda _:None,transport_factory=lambda *args:transport,authorization=grant)
        self.assertTrue(self.state.login_exhausted(self.key,f.DAY))

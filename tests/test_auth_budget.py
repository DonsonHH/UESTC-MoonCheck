"""Interactive onboarding budgets must not inherit the unattended daily guard."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import test_assisted_auth as fixtures
from moonuestc.runner import account_key
from moonuestc.policy import now
from moonuestc.state import State,InteractiveAuthCooldown
from moonuestc.errors import ToolError
from moonuestc.web_errors import WebError

class AuthBudgetRegression(unittest.TestCase):
    setUp=fixtures.AssistedCase.setUp
    tearDown=fixtures.AssistedCase.tearDown
    post=fixtures.AssistedCase.post
    start=fixtures.AssistedCase.start
    def flows(self):
        state=State(self.manager.portal.store.directory)
        try:return state.db.execute('SELECT completed FROM interactive_auth_flows').fetchall()
        finally:state.close()
    def legacy_daily_count(self):
        state=State(self.manager.portal.store.directory)
        try:
            return state.db.execute('SELECT count FROM logins WHERE account=? AND day=?',
                (account_key({'student_id':'202600000001'}),now().date().isoformat())).fetchone()
        finally:state.close()

    def test_stale_unattended_daily_counter_does_not_block_interactive_school_onboarding(self):
        state=State(self.manager.portal.store.directory)
        for _ in range(3):state.login_budget(account_key({'student_id':'202600000001'}),now().date().isoformat())
        state.close()
        response=self.start()
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(self.legacy_daily_count()[0],3)

    def test_one_assisted_login_does_not_consume_daily_background_budget_twice(self):
        started=self.start();self.assertEqual(started.status_code,200)
        self.bridge.ready=True
        response=self.post('finish',{},started.json['onboarding_csrf'])
        self.assertEqual(response.status_code,200,response.json)
        self.assertIsNone(self.legacy_daily_count())
        self.assertEqual(self.flows(),[(1,)])

    def test_browser_service_start_failure_does_not_consume_daily_budget(self):
        original=self.bridge.call
        def failed(action,data):
            if action=='start':raise WebError(503,'browser_unavailable','Synthetic browser infrastructure unavailable')
            return original(action,data)
        self.bridge.call=failed
        self.assertEqual(self.start().status_code,503)
        self.assertIsNone(self.legacy_daily_count())
        self.assertEqual(self.flows(),[])

    def test_ten_flows_have_five_minute_cooldown_and_survive_restart(self):
        with patch('moonuestc.state.time.time',return_value=10000):
            for _ in range(10):self.assertEqual(self.start().status_code,200)
        with patch('moonuestc.state.time.time',return_value=10120):
            response=self.start()
            self.assertEqual(response.status_code,429,response.json)
            self.assertEqual(response.json['error']['code'],'interactive_auth_cooldown')
            self.assertEqual(response.json['error']['retry_after'],180)
            self.assertEqual(response.headers['Retry-After'],'180')
            self.assertIn('本站接入保护',response.json['error']['message'])
            self.assertEqual(len(self.flows()),10)
        with patch('moonuestc.state.time.time',return_value=10300):
            self.assertEqual(self.start().status_code,200)

    def test_begin_failure_refunds_only_proven_unsubmitted_preparations(self):
        original=self.bridge.call
        posts=0
        def fail_begin(action,data):
            if action=='begin':raise WebError(503,'browser_unavailable','Synthetic failure')
            if action=='close':return {'password_posts':posts}
            return original(action,data)
        self.bridge.call=fail_begin
        self.assertEqual(self.start().status_code,503)
        self.assertEqual(self.flows(),[])
        posts=1
        self.assertEqual(self.start().status_code,503)
        self.assertEqual(self.flows(),[(0,)])

    def test_private_permit_is_single_use_and_bound_to_account(self):
        state=State(self.manager.portal.store.directory)
        try:
            permit=state.begin_interactive_login('school-A')
            with self.assertRaises(ToolError):state.complete_interactive_login(permit,'school-B')
            state.complete_interactive_login(permit,'school-A')
            with self.assertRaises(ToolError):state.complete_interactive_login(permit,'school-A')
            state.release_unsubmitted_login(permit,'school-A')
            self.assertEqual(self.flows(),[(1,)])
        finally:state.close()

    def test_final_identity_check_does_not_charge_request_limit_again(self):
        started=self.start();self.bridge.ready=True
        with self.store.db(True) as db:db.execute('UPDATE web_login_limits SET count=1000')
        response=self.post('finish',{},started.json['onboarding_csrf'])
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(self.flows(),[(1,)])

    def test_last_available_flow_cannot_be_reserved_by_two_parallel_requests(self):
        directory=self.manager.portal.store.directory
        state=State(directory)
        for _ in range(9):state.begin_interactive_login('shared')
        state.close()
        def reserve(_):
            state=State(directory)
            try:state.begin_interactive_login('shared');return 'reserved'
            except InteractiveAuthCooldown:return 'cooldown'
            finally:state.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(reserve,range(2))),['reserved','cooldown'])

    def test_automated_daily_guard_is_unchanged(self):
        state=State(self.manager.portal.store.directory)
        try:
            for _ in range(3):state.login_budget('synthetic-background','2026-10-21')
            with self.assertRaises(ToolError) as caught:state.login_budget('synthetic-background','2026-10-21')
            self.assertEqual(caught.exception.reason,'daily_login_limit')
        finally:state.close()

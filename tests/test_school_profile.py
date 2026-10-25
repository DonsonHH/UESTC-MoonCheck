"""Only a helper-observed school profile may name a verified ordinary user."""
import unittest
import test_assisted_auth as fixtures
from moonuestc.web_errors import WebError
class SchoolProfile(unittest.TestCase):
    setUp=fixtures.AssistedCase.setUp
    tearDown=fixtures.AssistedCase.tearDown
    post=fixtures.AssistedCase.post
    start=fixtures.AssistedCase.start
    def test_rejected_primary_credentials_fail_on_start_and_release_browser(self):
        original=self.bridge.call
        def rejected(action,data):
            if action=='begin':raise WebError(401,'school_login_rejected','学号或学校密码不正确。')
            return original(action,data)
        self.bridge.call=rejected
        response=self.start()
        self.assertEqual(response.status_code,401)
        self.assertEqual(self.manager.pending,{})
        self.assertEqual(len(self.store.users()),1)
    def test_helper_school_name_is_saved_only_after_successful_identity_check(self):
        token=self.start().json['onboarding_csrf'];self.bridge.ready=True;original=self.bridge.call
        self.bridge.call=lambda action,data:({**original(action,data),'student_name':'测试同学','student_name_source':'school_mfa_greeting'} if action=='result' else original(action,data))
        response=self.post('finish',{},token)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['user']['display_name'],'测试同学')
        self.assertEqual(self.store.accounts(response.json['user'])[0]['owner_name'],'测试同学')
    def test_missing_or_invalid_name_keeps_existing_user_display(self):
        token=self.start().json['onboarding_csrf'];self.bridge.ready=True;original=self.bridge.call
        self.bridge.call=lambda action,data:({**original(action,data),'student_name':'13800000000','student_name_source':'school_mfa_greeting'} if action=='result' else original(action,data))
        response=self.post('finish',{},token)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['user']['display_name'],'同学 · 0001')
    def test_delayed_rejection_progress_closes_pending_browser(self):
        self.bridge.call=lambda action,data:({'id':'1'} if action=='start' else {'phase':'pending'} if action=='begin' else {} if action=='close' else (_ for _ in ()).throw(WebError(401,'school_login_rejected','学号或学校密码不正确。')))
        response=self.start();self.assertEqual(response.json['phase'],'pending')
        progress=self.client.get('/api/onboarding/progress',base_url=fixtures.ORIGIN)
        self.assertEqual(progress.status_code,401)
        self.assertEqual(self.manager.pending,{})
    def test_untrusted_client_cannot_supply_school_name(self):
        response=self.client.post('/api/portal/login',base_url=fixtures.ORIGIN,json={'student_id':'202600000001','password':fixtures.PASSWORD,'student_name':'伪造姓名'},headers={'Origin':fixtures.ORIGIN})
        self.assertEqual(response.status_code,400)
    def test_rejected_final_check_does_not_save_observed_school_name(self):
        token=self.start().json['onboarding_csrf'];self.bridge.ready=True;original=self.bridge.call
        self.bridge.call=lambda action,data:({**original(action,data),'student_name':'测试同学','student_name_source':'school_mfa_greeting'} if action=='result' else original(action,data))
        self.manager.portal.verifier=lambda data:(_ for _ in ()).throw(__import__('moonuestc.errors',fromlist=['ToolError']).ToolError('login_rejected','cas_submit'))
        self.assertEqual(self.post('finish',{},token).status_code,401)
        self.assertEqual(len(self.store.users()),1)

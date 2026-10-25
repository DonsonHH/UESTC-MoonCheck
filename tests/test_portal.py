"""Student portal trust boundary, using synthetic credentials and a fake school boundary."""
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from argon2 import PasswordHasher
from moonuestc.web_app import create_app
from moonuestc.errors import ToolError

ORIGIN='https://moon.example.test'
SCHOOL_PASSWORD='Synthetic-school-pass-2026!'
FINGERPRINT='0123456789abcdef0123456789abcdef'

class PortalCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.calls=[]
        def school(account):
            self.calls.append(dict(account))
            return []
        self.app=create_app(Path(self.temp.name),ORIGIN,portal_enabled=True,surface='combined',school_verifier=school,
            hasher=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1),registration_enabled=False)
        self.store=self.app.extensions['moon_store']
        self.admin=self.store.create_user(None,{'username':'admin','password':'Synthetic-Admin-Pass-2026!','role':'admin'},bootstrap=True)
        self.client=self.app.test_client()

    def tearDown(self):self.temp.cleanup()

    def login(self,student='202600000001',**changes):
        return self.client.post('/api/portal/login',base_url=ORIGIN,headers={'Origin':ORIGIN},json={
            'student_id':student,'password':SCHOOL_PASSWORD,'browser_fingerprint':FINGERPRINT,
            'user_agent':'Synthetic browser User-Agent for tests',**changes})

    def test_first_login_is_verified_then_creates_one_owned_encrypted_account(self):
        response=self.login()
        self.assertEqual(response.status_code,200,response.get_json())
        self.assertEqual(len(self.calls),1)
        self.assertEqual(response.json['user']['role'],'user')
        me=self.client.get('/api/portal/me',base_url=ORIGIN)
        self.assertEqual(me.status_code,200)
        self.assertEqual(me.json['account']['student_id'],'202600000001')
        self.assertNotIn(SCHOOL_PASSWORD,response.get_data(as_text=True)+me.get_data(as_text=True))
        with self.store.db() as db:db.execute('pragma wal_checkpoint(FULL)')
        self.assertNotIn(SCHOOL_PASSWORD.encode(),self.store.path.read_bytes())
        self.assertNotIn(b'202600000001',self.store.path.read_bytes())

    def request(self,path,method='GET',data=None,csrf=None,client=None):
        return (client or self.client).open(path,base_url=ORIGIN,method=method,json=data,
            headers={'Origin':ORIGIN,**({'X-CSRF-Token':csrf} if csrf else {})})

    def test_unverified_and_mfa_failures_do_not_create_users_or_accounts(self):
        self.app.extensions['moon_portal'].verifier=lambda a: (_ for _ in ()).throw(ToolError('need_manual_mfa','cas_submit'))
        self.assertEqual(self.login().status_code,428)
        self.assertEqual(len(self.store.users()),1)
        self.assertEqual(len(self.store.accounts(self.admin)),0)

    def test_recent_verified_password_uses_hash_and_changed_password_requires_school(self):
        self.assertEqual(self.login().status_code,200)
        self.assertEqual(self.login(browser_fingerprint='',user_agent='').status_code,200)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.login(password='A-new-synthetic-school-pass!').status_code,200)
        self.assertEqual(len(self.calls),2)

    def test_bound_identity_cannot_create_second_account_or_change_student(self):
        login=self.login();csrf=login.json['csrf_token']
        account=self.request('/api/portal/me').json['account']
        self.assertEqual(self.request('/api/accounts','POST',{},csrf).status_code,409)
        self.assertEqual(self.request('/api/accounts/'+account['id'],'PATCH',{'student_id':'202600000002'},csrf).status_code,409)
        self.assertEqual(self.request('/api/accounts/'+account['id'],'PATCH',{'password':'changed'},csrf).status_code,409)
        self.assertEqual(self.request('/api/me/password','POST',{'current_password':SCHOOL_PASSWORD,'new_password':'Different-pass-2026!'},csrf).status_code,409)

    def test_student_cannot_access_admin_or_another_students_data(self):
        self.login();first=self.request('/api/portal/me').json['account']
        self.login('202600000002')
        self.assertEqual(self.request('/admin').status_code,403)
        self.assertEqual(self.request('/api/users').status_code,403)
        self.assertEqual(self.request('/api/accounts/'+first['id']).status_code,404)
        self.assertEqual(len(self.request('/api/accounts').json['accounts']),1)

    def test_existing_operator_account_is_claimed_only_after_verification_and_keeps_history(self):
        account=self.store.save_account(self.admin,{'student_id':'202600000001','password':SCHOOL_PASSWORD,
            'browser_fingerprint':FINGERPRINT,'user_agent':'Synthetic browser User-Agent for tests'})
        job=self.store.enqueue(self.admin,account['id'],'diagnose')
        claimed=self.store.claim_job();self.store.finish_job(claimed,{'result':'auth_ready'})
        self.assertEqual(self.login(browser_fingerprint='',user_agent='').status_code,428)
        self.assertEqual(self.store.accounts(self.admin)[0]['owner_id'],self.admin['id'])
        response=self.login();self.assertEqual(response.status_code,200,response.json)
        current=self.request('/api/portal/me').json['account']
        self.assertEqual(current['id'],account['id'])
        self.assertNotEqual(current['owner_id'],self.admin['id'])
        self.assertEqual(self.request('/api/jobs').json['jobs'][0]['id'],job)

    def test_portal_never_queues_submission_and_failed_origin_cannot_authenticate(self):
        self.assertEqual(self.login().status_code,200)
        self.assertEqual(self.request('/api/jobs').json['jobs'],[])
        response=self.client.post('/api/portal/login',base_url=ORIGIN,headers={'Origin':'https://evil.example'},json={})
        self.assertEqual(response.status_code,403)

    def test_admin_endpoint_rejects_school_user_and_password_change_invalidates_sessions(self):
        response=self.login();user=response.json['user']
        old_token=self.client.get_cookie('moon_dashboard_session',domain='moon.example.test').value
        rejected=self.request('/api/admin/login','POST',{'username':user['username'],'password':SCHOOL_PASSWORD})
        self.assertEqual(rejected.status_code,401)
        self.login(password='Synthetic-new-school-password!')
        self.assertIsNone(self.store.session(old_token))

    def test_verification_rate_limit_and_expired_verification(self):
        self.login()
        with self.store.db(True) as db:db.execute('UPDATE portal_bindings SET verified_at=0')
        self.login()
        self.assertEqual(len(self.calls),2)

    def test_ten_failed_school_attempts_block_further_school_password_posts(self):
        self.app.extensions['moon_portal'].verifier=lambda a: (_ for _ in ()).throw(ToolError('login_rejected','cas_submit'))
        for n in range(10):
            with self.subTest(attempt=n):self.assertEqual(self.login().status_code,401)
        self.assertEqual(self.login().status_code,429)
        self.assertEqual(len(self.store.users()),1)

    def test_real_verifier_forces_fresh_password_auth_and_never_submits(self):
        from moonuestc.portal import verify_school
        from test_workflows import FakeTransport
        transport=FakeTransport()
        transport.jar=[]
        with patch('moonuestc.portal.Transport',return_value=transport):
            verify_school({'student_id':'202600000001','password':SCHOOL_PASSWORD,'browser_fingerprint':FINGERPRINT,'user_agent':'Synthetic Test browser'})
        self.assertEqual(sum(stage=='cas_submit' for _,stage in transport.calls),1)
        self.assertEqual(transport.post_count,0)
        self.assertFalse(transport.saved)

    def test_trusted_proxy_header_does_not_allow_arbitrary_clients_to_spoof_limits(self):
        rejected=self.client.post('/api/admin/login',base_url=ORIGIN,headers={'Origin':ORIGIN,'CF-Connecting-IP':'198.51.100.1'},json={'username':'missing','password':'wrong'})
        self.assertEqual(rejected.status_code,401)
        with self.store.db() as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM web_login_limits WHERE bucket=?',(self.store.vault.digest('login_ip','127.0.0.1'),)).fetchone())

if __name__=='__main__':unittest.main()

"""Explicit operator grants extend the cohort without bypassing school MFA."""
import unittest
from moonuestc.errors import ToolError
from moonuestc.portal import PortalAuth
import test_assisted_auth as fixtures

STUDENT='202600000001'
class Authorizations(unittest.TestCase):
    setUp=fixtures.AssistedCase.setUp
    tearDown=fixtures.AssistedCase.tearDown
    def set_admin(self):
        self.manager.portal.student_prefix='20260000000'
        response=self.client.post('/api/admin/login',base_url=fixtures.ORIGIN,json={'username':'admin','password':'Synthetic-admin-password-2026!'},headers={'Origin':fixtures.ORIGIN})
        return response.json['csrf_token']
    def request(self,method='GET',data=None,csrf='',path='/api/portal/authorizations',client=None):
        return (client or self.client).open(path,method=method,base_url=fixtures.ORIGIN,json=data,headers={'Origin':fixtures.ORIGIN,'X-CSRF-Token':csrf})
    def grant(self,csrf):return self.request('POST',{'student_id':STUDENT},csrf)
    def test_admin_grant_is_persistent_encrypted_idempotent_and_does_not_create_identity(self):
        csrf=self.set_admin();first=self.grant(csrf);self.assertEqual(first.status_code,200,first.json)
        self.assertEqual(self.grant(csrf).status_code,200)
        listed=self.request().json;self.assertEqual(listed['student_prefix'],'20260000000')
        self.assertEqual(len(listed['authorizations']),1);self.assertEqual(listed['authorizations'][0]['student_id'],STUDENT)
        self.assertEqual(self.school,[]);self.assertEqual(len(self.store.users()),1)
        with self.store.db() as db:
            row=db.execute('SELECT * FROM portal_access_grants').fetchone()
            self.assertNotIn(STUDENT.encode(),row['payload'])
            self.assertNotEqual(row['student_digest'],STUDENT)
        fresh=PortalAuth(self.store);fresh.student_prefix='20260000000';fresh.require_allowed(STUDENT)
    def test_only_admin_with_origin_and_csrf_can_change_or_list_grants(self):
        self.assertEqual(self.request().status_code,401)
        csrf=self.set_admin();self.assertEqual(self.grant('').status_code,403)
        for student in ['2026000000000','2026abc','202600000001000000001']:
            self.assertEqual(self.request('POST',{'student_id':student},csrf).status_code,400)
        self.assertEqual(self.client.post('/api/portal/authorizations',base_url=fixtures.ORIGIN,json={'student_id':STUDENT},headers={'Origin':'https://evil.test','X-CSRF-Token':csrf}).status_code,403)
        self.grant(csrf)
        token,_,_=self.manager.portal.login({'student_id':STUDENT,'password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},'127.0.0.1')
        other=self.app.test_client();other.set_cookie('moon_dashboard_session',token,domain='moon.example.test')
        self.assertEqual(self.request(client=other).status_code,403)
    def test_grant_allows_onboarding_but_never_substitutes_for_school_verification(self):
        csrf=self.set_admin();self.grant(csrf)
        response=self.client.post('/api/portal/login',base_url=fixtures.ORIGIN,json={'student_id':STUDENT,'password':fixtures.PASSWORD},headers={'Origin':fixtures.ORIGIN})
        self.assertEqual(response.status_code,428);self.assertEqual(len(self.store.users()),1)
        self.manager.portal.verifier=lambda a:(_ for _ in ()).throw(ToolError('need_manual_mfa','cas_submit'))
        response=self.client.post('/api/portal/login',base_url=fixtures.ORIGIN,json={'student_id':STUDENT,'password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},headers={'Origin':fixtures.ORIGIN})
        self.assertEqual(response.status_code,428);self.assertEqual(len(self.store.users()),1)
        response=self.client.post('/api/onboarding/start',base_url=fixtures.ORIGIN,json={'student_id':STUDENT,'password':fixtures.PASSWORD},headers={'Origin':fixtures.ORIGIN})
        self.assertEqual(response.status_code,200)
    def test_revocation_invalidates_cached_login_and_session_but_keeps_user(self):
        csrf=self.set_admin();record=self.grant(csrf).json['authorization']
        token,_,_=self.manager.portal.login({'student_id':STUDENT,'password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},'127.0.0.1')
        self.assertEqual(self.request('DELETE',csrf=csrf,path='/api/portal/authorizations/'+record['id']).status_code,200)
        other=self.app.test_client();other.set_cookie('moon_dashboard_session',token,domain='moon.example.test')
        self.assertFalse(other.get('/api/session',base_url=fixtures.ORIGIN).json['authenticated'])
        with self.assertRaises(Exception) as denied:self.manager.portal.login({'student_id':STUDENT,'password':fixtures.PASSWORD},'127.0.0.1')
        self.assertEqual(denied.exception.code,'student_not_allowed');self.assertEqual(len(self.store.users()),2)
        self.assertEqual(self.request().json['authorizations'],[])
    def test_revoking_access_pauses_existing_accounts_and_blocks_queued_school_work(self):
        from moonuestc.web_service import WebWorker
        csrf=self.set_admin();record=self.grant(csrf).json['authorization']
        self.manager.portal.login({'student_id':STUDENT,'password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},'127.0.0.1')
        with self.store.db() as db:
            admin=dict(db.execute("SELECT * FROM web_users WHERE role='admin'").fetchone())
            account=db.execute('SELECT * FROM web_accounts').fetchone();before=bytes(account['payload'])
        self.store.enqueue(admin,account['id'],'diagnose')
        calls=[];worker=WebWorker(self.store,runner=lambda *a,**kw:calls.append(True) or {'result':'auth_ready'})
        self.request('DELETE',csrf=csrf,path='/api/portal/authorizations/'+record['id'])
        self.assertTrue(worker.run_one());self.assertEqual(calls,[])
        with self.store.db() as db:
            after=db.execute('SELECT * FROM web_accounts WHERE id=?',(account['id'],)).fetchone()
        self.assertFalse(after['enabled']);self.assertEqual(bytes(after['payload']),before)
        self.assertEqual(after['automatic'],account['automatic']);self.assertEqual(after['run_at'],account['run_at'])
    def test_revocation_during_onboarding_blocks_final_binding(self):
        csrf=self.set_admin();record=self.grant(csrf).json['authorization']
        token,onboarding_csrf=self.manager.start({'student_id':STUDENT,'password':fixtures.PASSWORD},'127.0.0.1')
        self.request('DELETE',csrf=csrf,path='/api/portal/authorizations/'+record['id']);self.bridge.ready=True
        with self.assertRaises(Exception) as denied:self.manager.finish(token,onboarding_csrf)
        self.assertEqual(denied.exception.code,'student_not_allowed');self.assertEqual(len(self.store.users()),1);self.assertEqual(self.school,[])
    def test_revocation_while_school_verifier_runs_blocks_transaction_commit(self):
        csrf=self.set_admin();record=self.grant(csrf).json['authorization']
        with self.store.db() as db:admin=dict(db.execute("SELECT * FROM web_users WHERE role='admin'").fetchone())
        def school(account):
            self.manager.portal.revoke_authorization(admin,record['id'])
            return []
        self.manager.portal.verifier=school
        with self.assertRaises(Exception) as denied:self.manager.portal.login({'student_id':STUDENT,'password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},'127.0.0.1')
        self.assertEqual(denied.exception.code,'student_not_allowed');self.assertEqual(len(self.store.users()),1)

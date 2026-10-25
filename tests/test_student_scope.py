import unittest
import test_assisted_auth as fixtures

class StudentScope(unittest.TestCase):
    setUp=fixtures.AssistedCase.setUp
    tearDown=fixtures.AssistedCase.tearDown
    post=fixtures.AssistedCase.post
    def test_only_exact_prefix_and_two_digits_can_start_authentication(self):
        self.manager.portal.student_prefix='20260000000'
        for student in ['2026000000101','202600000000','20260000000000','20260000000ab','202600000001']:
            response=self.post('start',{'student_id':student,'password':fixtures.PASSWORD})
            self.assertIn(response.status_code,(400,403))
        self.assertEqual(self.bridge.calls,[])
        response=self.post('start',{'student_id':'2026000000000','password':fixtures.PASSWORD})
        self.assertEqual(response.status_code,200,response.json)
    def test_portal_login_checks_scope_before_school_or_cache(self):
        self.manager.portal.student_prefix='20260000000'
        response=self.client.post('/api/portal/login',base_url=fixtures.ORIGIN,json={'student_id':'202600000001','password':fixtures.PASSWORD},headers={'Origin':fixtures.ORIGIN})
        self.assertEqual(response.status_code,403)
        self.assertEqual(response.json['error']['code'],'student_not_allowed')
        self.assertEqual(self.school,[])
    def test_existing_out_of_scope_session_stops_access_without_deleting_user(self):
        _,_,user=self.manager.portal.login({'student_id':'202600000001','password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},'127.0.0.1')
        token,_,_=self.manager.portal.login({'student_id':'202600000001','password':fixtures.PASSWORD},'127.0.0.1')
        self.client.set_cookie('moon_dashboard_session',token,domain='moon.example.test')
        self.manager.portal.student_prefix='20260000000'
        session=self.client.get('/api/session',base_url=fixtures.ORIGIN)
        self.assertEqual(session.status_code,200)
        self.assertFalse(session.json['authenticated'])
        response=self.client.get('/api/accounts',base_url=fixtures.ORIGIN)
        self.assertEqual(response.status_code,401)
        self.assertIsNone(self.store.session(token))
        self.assertEqual(len(self.store.users()),2)
    def test_admin_login_and_management_are_independent_of_student_scope(self):
        self.manager.portal.student_prefix='20260000000'
        response=self.client.post('/api/admin/login',base_url=fixtures.ORIGIN,json={'username':'admin','password':'Synthetic-admin-password-2026!'},headers={'Origin':fixtures.ORIGIN})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.client.get('/api/users',base_url=fixtures.ORIGIN).status_code,200)

import unittest
import test_assisted_auth as fixtures
from moonuestc.notice import VERSION

class Notice(unittest.TestCase):
 setUp=fixtures.AssistedCase.setUp
 tearDown=fixtures.AssistedCase.tearDown
 def test_missing_consent_stops_before_school_or_browser_and_no_user_is_created(self):
  self.manager.portal.require_notice=True
  data={'student_id':'202600000001','password':fixtures.PASSWORD}
  for path in ('/api/portal/login','/api/onboarding/start'):
   r=self.client.post(path,base_url=fixtures.ORIGIN,json=data,headers={'Origin':fixtures.ORIGIN})
   self.assertEqual(r.status_code,428,r.json);self.assertEqual(r.json['error']['code'],'privacy_consent_required')
  self.assertEqual(self.bridge.calls,[]);self.assertEqual(self.school,[]);self.assertEqual(len(self.store.users()),1)
 def test_consent_is_saved_only_after_school_validation_and_bound_to_user(self):
  self.manager.portal.require_notice=True;self.bridge.ready=True
  data={'student_id':'202600000001','password':fixtures.PASSWORD,'consent_version':VERSION}
  start=self.client.post('/api/onboarding/start',base_url=fixtures.ORIGIN,json=data,headers={'Origin':fixtures.ORIGIN})
  self.assertEqual(start.status_code,200,start.json)
  with self.store.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM portal_notices').fetchone()[0],0)
  done=self.client.post('/api/onboarding/finish',base_url=fixtures.ORIGIN,json={},headers={'Origin':fixtures.ORIGIN,'X-Onboarding-CSRF':start.json['onboarding_csrf']})
  self.assertEqual(done.status_code,200,done.json)
  with self.store.db() as db:
   receipt=db.execute('SELECT * FROM portal_notices').fetchone();self.assertEqual(receipt['user_id'],done.json['user']['id']);self.assertEqual(receipt['version'],VERSION)
  response=self.client.get('/api/notice',base_url=fixtures.ORIGIN);self.assertEqual(response.json['notice']['version'],VERSION);self.assertNotIn(fixtures.PASSWORD,response.get_data(as_text=True))
 def test_stale_or_malformed_notice_version_is_rejected(self):
  self.manager.portal.require_notice=True
  for value in ('old',True,{},None):
   data={'student_id':'202600000001','password':fixtures.PASSWORD,'consent_version':value}
   r=self.client.post('/api/onboarding/start',base_url=fixtures.ORIGIN,json=data,headers={'Origin':fixtures.ORIGIN});self.assertEqual(r.status_code,428)
 def test_existing_session_is_prompted_and_work_is_blocked_until_confirmed(self):
  token,csrf,user=self.manager.portal.login({'student_id':'202600000001','password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},'127.0.0.1')
  self.client.set_cookie('moon_dashboard_session',token,domain='moon.example.test');self.manager.portal.require_notice=True;self.store.require_notice=True
  self.assertTrue(self.client.get('/api/session',base_url=fixtures.ORIGIN).json['notice_required'])
  account=self.store.accounts(user)[0]
  response=self.client.post('/api/accounts/'+account['id']+'/jobs',base_url=fixtures.ORIGIN,json={'mode':'diagnose'},headers={'Origin':fixtures.ORIGIN,'X-CSRF-Token':csrf})
  self.assertEqual(response.status_code,428)
  response=self.client.post('/api/notice/accept',base_url=fixtures.ORIGIN,json={'version':VERSION},headers={'Origin':fixtures.ORIGIN,'X-CSRF-Token':csrf})
  self.assertEqual(response.status_code,200);self.assertFalse(self.client.get('/api/session',base_url=fixtures.ORIGIN).json['notice_required'])
 def test_existing_automatic_plan_waits_for_notice_acceptance(self):
  _,_,user=self.manager.portal.login({'student_id':'202600000001','password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic browser'},'127.0.0.1')
  self.store.require_notice=True
  with self.store.db(True) as db:db.execute('UPDATE web_accounts SET automatic=1 WHERE owner_id=?',(user['id'],))
  self.assertEqual(self.store.automatic_accounts(),[])
  self.store.accept_notice(user,VERSION);self.assertEqual(len(self.store.automatic_accounts()),1)

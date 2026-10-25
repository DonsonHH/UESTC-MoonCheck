"""Owner verification is the recovery boundary for unattended authentication."""
import tempfile,unittest,json,time
import test_assisted_auth as fixtures
from test_workflows import ACCOUNT,INSTANT,FakeTransport,response
from moonuestc.errors import ToolError
from moonuestc.runner import run_account,account_key
from moonuestc.policy import now
from moonuestc.state import State

class CaptchaTransport(FakeTransport):
 def request(self,method,url,**kwargs):
  if kwargs['stage']=='cas_submit':
   self.calls.append((method,'cas_submit'));return response(url,text='请输入验证码')
  return super().request(method,url,**kwargs)

class Recovery(unittest.TestCase):
 def test_manual_verification_requirement_survives_restart_and_never_claims_attendance(self):
  with tempfile.TemporaryDirectory() as directory:
   s=State(directory);s.require_interactive_auth(account_key(ACCOUNT),'need_manual_mfa');s.close();s=State(directory)
   try:
    with self.assertRaises(ToolError) as caught:s.login_budget(account_key(ACCOUNT),'2026-10-23')
    self.assertEqual(caught.exception.reason,'need_manual_mfa');self.assertFalse(s.claimed(account_key(ACCOUNT),'2026-10-23'))
   finally:s.close()
 def test_repeated_location_checks_stop_at_captcha_instead_of_exhausting_daily_budget(self):
  with tempfile.TemporaryDirectory() as directory:
   state=State(directory);transport=CaptchaTransport();reasons=[]
   try:
    for _ in range(4):
     try:run_account(ACCOUNT,'prepare',state,directory,clock=lambda:INSTANT,sleep=lambda _:None,transport_factory=lambda *args:transport)
     except ToolError as error:reasons.append(error.reason)
    self.assertEqual(reasons,['need_manual_captcha']*4)
    self.assertEqual(transport.calls.count(('POST','cas_submit')),1)
    self.assertEqual(transport.calls.count(('GET','cas_page')),1)
   finally:state.close()

class RecoveryAPI(unittest.TestCase):
 setUp=fixtures.AssistedCase.setUp
 tearDown=fixtures.AssistedCase.tearDown
 def login(self,student='202600000001'):
  token,csrf,user=self.manager.portal.login({'student_id':student,'password':fixtures.PASSWORD,'browser_fingerprint':fixtures.FINGERPRINT,'user_agent':'Synthetic assisted-school browser'},'127.0.0.1')
  self.client.set_cookie('moon_dashboard_session',token,domain='moon.example.test');self.csrf=csrf;self.actor=user
  return self.store.accounts(user)[0]
 def blocked(self,student='202600000001'):
  s=State(self.temp.name)
  try:
   for _ in range(3):s.login_budget(account_key({'student_id':student}),now().date().isoformat())
   s.require_interactive_auth(account_key({'student_id':student}),'daily_login_limit')
  finally:s.close()
 def begin(self,data=None,csrf=True):
  return self.client.post('/api/portal/reauthenticate',base_url=fixtures.ORIGIN,json=data or {},headers={'Origin':fixtures.ORIGIN,'X-CSRF-Token':self.csrf if csrf else ''})
 def count(self,student='202600000001'):
  s=State(self.temp.name)
  try:
   row=s.db.execute('SELECT count FROM logins WHERE account=? AND day=?',(account_key({'student_id':student}),now().date().isoformat())).fetchone();return row[0] if row else 0
  finally:s.close()
 def test_verified_recovery_clears_only_own_budget_and_keeps_claims_and_preferences(self):
  a=self.login();self.blocked();self.blocked('202600000002');s=State(self.temp.name)
  try:s.claim(account_key({'student_id':'202600000001'}),now().date().isoformat())
  finally:s.close()
  self.assertTrue(self.store.account(self.actor,a['id'])['school_auth_required'])
  started=self.begin();self.assertEqual(started.status_code,200,started.json);self.assertNotIn(fixtures.PASSWORD,started.get_data(as_text=True));self.assertEqual(self.count(),3)
  self.bridge.ready=True;before=len(self.school)
  done=self.client.post('/api/onboarding/finish',base_url=fixtures.ORIGIN,json={},headers={'Origin':fixtures.ORIGIN,'X-Onboarding-CSRF':started.json['onboarding_csrf']})
  self.assertEqual(done.status_code,200,done.json);self.assertEqual(len(self.school),before+1);self.assertEqual(self.count(),0);self.assertEqual(self.count('202600000002'),3)
  after=self.store.account(self.actor,a['id']);self.assertFalse(after['school_auth_required']);self.assertEqual(after['run_at'],a['run_at']);self.assertEqual(after['automatic'],a['automatic']);self.assertEqual(after['schedule_slot'],a['schedule_slot'])
  s=State(self.temp.name)
  try:self.assertTrue(s.claimed(account_key({'student_id':'202600000001'}),now().date().isoformat()))
  finally:s.close()
 def test_cached_portal_login_is_not_school_recovery(self):
  self.login();self.blocked();before=len(self.school);self.login();self.assertEqual(len(self.school),before);self.assertEqual(self.count(),3)
 def test_location_edits_cannot_hide_a_legacy_school_authentication_failure(self):
  a=self.login()
  with self.store.db(True) as db:db.execute('UPDATE web_accounts SET last_result=?,last_run_at=? WHERE id=?',(json.dumps({'result':'error','reason':'daily_login_limit'}),time.time(),a['id']))
  self.store.save_account(self.actor,{'run_at':'22:01'},a['id'])
  self.assertTrue(self.store.account(self.actor,a['id'])['school_auth_required'])
 def test_cancelled_recovery_keeps_the_guard_and_daily_counter(self):
  self.login();self.blocked();started=self.begin();self.assertEqual(started.status_code,200)
  cancel=self.client.post('/api/onboarding/cancel',base_url=fixtures.ORIGIN,json={},headers={'Origin':fixtures.ORIGIN,'X-Onboarding-CSRF':started.json['onboarding_csrf']})
  self.assertEqual(cancel.status_code,200);self.assertEqual(self.count(),3)
 def test_other_student_and_administrator_cannot_be_selected_for_recovery(self):
  a=self.login();self.blocked();self.login('202600000002');started=self.begin();self.assertEqual(started.status_code,200)
  payload=next(data for action,data in reversed(self.bridge.calls) if action=='start');self.assertEqual(payload['student_id'],'202600000002');self.assertEqual(self.count('202600000001'),3)
  token,csrf,user=self.store.login('admin','Synthetic-admin-password-2026!','127.0.0.1');self.client.set_cookie('moon_dashboard_session',token,domain='moon.example.test');self.csrf=csrf
  self.assertEqual(self.begin().status_code,403)
 def test_recovery_requires_session_csrf_and_own_identity(self):
  self.login();self.assertEqual(self.begin(csrf=False).status_code,403)
  before=len(self.bridge.calls);self.assertEqual(self.begin({'student_id':'202600000002'}).status_code,400);self.assertEqual(len(self.bridge.calls),before)
  self.client.delete_cookie('moon_dashboard_session',domain='moon.example.test');self.assertEqual(self.begin().status_code,401)
 def test_failed_school_recovery_keeps_the_guard(self):
  self.login();self.blocked();started=self.begin();self.assertEqual(started.status_code,200)
  self.bridge.ready=True;self.manager.portal.verifier=lambda _:(_ for _ in ()).throw(ToolError('need_manual_captcha','cas_submit'))
  done=self.client.post('/api/onboarding/finish',base_url=fixtures.ORIGIN,json={},headers={'Origin':fixtures.ORIGIN,'X-Onboarding-CSRF':started.json['onboarding_csrf']})
  self.assertEqual(done.status_code,428);self.assertEqual(self.count(),3)

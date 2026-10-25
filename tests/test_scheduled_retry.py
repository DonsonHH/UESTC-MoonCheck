import tempfile,unittest
from unittest.mock import patch
from argon2 import PasswordHasher
from moonuestc.web_store import WebStore
from moonuestc.web_service import WebWorker
from moonuestc.errors import ToolError
from test_workflows import INSTANT
from dashboard_helpers import WebCase

class Retrying(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.store=WebStore(self.tmp.name,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));self.store.execution_window=('21:06','23:24')
  self.admin=self.store.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
  self.account=self.store.save_account(self.admin,WebCase.account_fields(None));self.job=self.store.enqueue(self.admin,self.account['id'],'checkin','schedule',INSTANT.date().isoformat())
 def tearDown(self):self.tmp.cleanup()
 def test_one_delayed_retry_is_persistent_and_second_failure_is_terminal(self):
  calls=[]
  def fail(*args,**kwargs):calls.append(True);raise ToolError('timeout','today')
  worker=WebWorker(self.store,runner=fail)
  with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_store.time.time',return_value=INSTANT.timestamp()):worker.run_one()
  job=self.store.jobs(self.admin,self.job);self.assertEqual(job['state'],'queued');self.assertEqual(job['attempt'],1);self.assertGreaterEqual(job['available_at'],INSTANT.timestamp()+120)
  with patch('moonuestc.web_store.time.time',return_value=INSTANT.timestamp()+119):self.assertIsNone(self.store.claim_job())
  restored=WebStore(self.tmp.name,self.store.hasher);restored.execution_window=self.store.execution_window;worker=WebWorker(restored,runner=fail)
  later=INSTANT.fromtimestamp(job['available_at'],INSTANT.tzinfo)
  with patch('moonuestc.web_service.now',return_value=later),patch('moonuestc.web_store.time.time',return_value=later.timestamp()):worker.run_one()
  job=restored.jobs(self.admin,self.job);self.assertEqual(job['state'],'failed');self.assertEqual(job['result']['reason'],'timeout');self.assertTrue(job['result']['retryExhausted']);self.assertEqual(len(calls),2)
 def test_captcha_is_owner_action_not_an_automatic_retry(self):
  worker=WebWorker(self.store,runner=lambda *a,**kw:(_ for _ in ()).throw(ToolError('need_manual_captcha','cas_submit')))
  with patch('moonuestc.web_service.now',return_value=INSTANT):worker.run_one()
  job=self.store.jobs(self.admin,self.job);self.assertEqual(job['state'],'failed');self.assertEqual(job['attempt'],0);self.assertNotIn('retryAt',job['result'])
 def test_manual_failure_leaves_the_automatic_job_and_retry_budget_available(self):
  from moonuestc.state import State
  from moonuestc.runner import account_key
  import datetime as dt
  with self.store.db(True) as db:db.execute("UPDATE web_jobs SET source='manual' WHERE id=?",(self.job,))
  calls=[]
  def runner(*args,**kwargs):
   calls.append(True)
   if len(calls)==1:raise ToolError('http_error','cas_submit',http_status=503)
   return {'result':'confirmed'}
  worker=WebWorker(self.store,runner=runner)
  with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_store.now',return_value=INSTANT),patch('moonuestc.web_store.time.time',return_value=INSTANT.timestamp()):
   worker.run_one();manual=self.store.jobs(self.admin,self.job)
   self.assertEqual(manual['state'],'failed');self.assertEqual(manual['attempt'],0)
   self.assertNotIn('retryAt',manual['result'])
   payload=self.store.job_payload({'account_id':self.account['id']});state=State(self.tmp.name)
   try:
    day=(INSTANT.date()-dt.timedelta(days=1)).isoformat();state.claim(account_key(payload),day);state.outcome(account_key(payload),day,'confirmed')
   finally:state.close()
   self.store.save_account(self.admin,{'automatic':True},self.account['id'])
   worker.schedule_once();self.assertTrue(worker.run_one())
   with self.store.db() as db:scheduled=db.execute("SELECT state,attempt FROM web_jobs WHERE source='schedule'").fetchall()
   self.assertEqual([(r['state'],r['attempt']) for r in scheduled],[('done',0)])
  self.assertEqual(len(calls),2)
 def test_unknown_submission_retry_only_rechecks_no_second_post(self):
  from test_workflows import FakeTransport
  from moonuestc.runner import run_account
  transport=FakeTransport();transport.timeout_post=True
  with self.store.db(True) as db:
   row=db.execute('SELECT * FROM web_accounts WHERE id=?',(self.account['id'],)).fetchone();payload=self.store._payload(row);payload['location']={'mode':'fixed','name':'Synthetic location','latitude':0,'longitude':0,'coordinate_system':'gcj02','reverse_geocode':'Synthetic place'}
   db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(payload,'account:'+self.account['id']),self.account['id']))
  def runner(a,m,s,d,**kw):return run_account(a,m,s,d,clock=lambda:INSTANT,sleep=lambda _:None,**kw)
  worker=WebWorker(self.store,runner=runner)
  with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_store.time.time',return_value=INSTANT.timestamp()),patch('moonuestc.web_service.EncryptedTransport',return_value=transport):worker.run_one()
  job=self.store.jobs(self.admin,self.job);later=INSTANT.fromtimestamp(job['available_at'],INSTANT.tzinfo)
  with patch('moonuestc.web_service.now',return_value=later),patch('moonuestc.web_store.time.time',return_value=later.timestamp()),patch('moonuestc.web_service.EncryptedTransport',return_value=transport):worker.run_one()
  self.assertEqual(transport.post_count,1);self.assertEqual(self.store.jobs(self.admin,self.job)['state'],'failed')
 def test_invalid_location_has_no_retry_and_deadline_blocks_retry(self):
  worker=WebWorker(self.store,runner=lambda *a,**kw:(_ for _ in ()).throw(ToolError('outside_allowed_location','location')))
  with patch('moonuestc.web_service.now',return_value=INSTANT):worker.run_one()
  self.assertEqual(self.store.jobs(self.admin,self.job)['state'],'failed')
 def test_second_attempt_can_recover_and_deadline_has_no_silent_retry(self):
  calls=[]
  def recover(*args,**kwargs):
   calls.append(True)
   if len(calls)==1:raise ToolError('timeout','today')
   return {'result':'confirmed'}
  worker=WebWorker(self.store,runner=recover)
  with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_store.time.time',return_value=INSTANT.timestamp()):worker.run_one()
  pending=self.store.jobs(self.admin,self.job);later=INSTANT.fromtimestamp(pending['available_at'],INSTANT.tzinfo)
  with patch('moonuestc.web_service.now',return_value=later),patch('moonuestc.web_store.time.time',return_value=later.timestamp()):worker.run_one()
  self.assertEqual(self.store.jobs(self.admin,self.job)['state'],'done');self.assertEqual(len(calls),2)
 def test_near_deadline_failure_reports_no_retry_slot(self):
  worker=WebWorker(self.store,runner=lambda *a,**kw:(_ for _ in ()).throw(ToolError('timeout','today')))
  late=INSTANT.replace(hour=23,minute=23)
  with patch('moonuestc.web_service.now',return_value=late),patch('moonuestc.web_store.time.time',return_value=late.timestamp()):worker.run_one()
  job=self.store.jobs(self.admin,self.job);self.assertEqual(job['state'],'failed');self.assertTrue(job['result']['retryUnavailable'])
 def test_retry_does_not_occupy_another_students_primary_slot(self):
  other=self.store.save_account(self.admin,WebCase.account_fields(None,student='202600000002',run_at='22:02'))
  worker=WebWorker(self.store,runner=lambda *a,**kw:(_ for _ in ()).throw(ToolError('timeout','today')))
  with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_store.time.time',return_value=INSTANT.timestamp()):worker.run_one()
  retry=self.store.jobs(self.admin,self.job)['available_at'];clock=INSTANT.fromtimestamp(retry,INSTANT.tzinfo).strftime('%H:%M:%S')
  self.assertFalse(other['schedule_slot']['start']+':00'<=clock<other['schedule_slot']['end'])

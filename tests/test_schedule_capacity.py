"""A same-time cohort queues HTTP jobs; it never fans out browser sessions."""
import tempfile,unittest,datetime as dt
from pathlib import Path
from unittest.mock import patch
from argon2 import PasswordHasher
from moonuestc.web_store import WebStore
from moonuestc.web_service import WebWorker
from moonuestc.state import State
from moonuestc.runner import account_key
from test_workflows import INSTANT
from dashboard_helpers import WebCase

class ScheduleCapacity(unittest.TestCase):
 def test_one_hundred_same_time_jobs_are_not_lost_and_run_at_bounded_rate(self):
  with tempfile.TemporaryDirectory() as root:
   store=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1))
   admin=store.create_user(None,{'username':'admin','password':'Synthetic-admin-2026!','role':'admin'},bootstrap=True)
   state=State(root);calls=[]
   try:
    for n in range(100):
     fields=WebCase.account_fields(None,student='20260000'+str(n).zfill(4))
     account=store.save_account(admin,fields)
     payload=store.job_payload({'account_id':account['id']});day=(INSTANT.date()-dt.timedelta(days=1)).isoformat()
     state.claim(account_key(payload),day);state.outcome(account_key(payload),day,'confirmed')
     store.save_account(admin,{'automatic':True,'run_at':'22:00'},account['id'])
    worker=WebWorker(store,runner=lambda a,*args,**kwargs:calls.append(a['id']) or {'result':'confirmed'})
    with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_service.time.monotonic',return_value=0):
     worker.tick()
     self.assertEqual(len(calls),1)
     worker.tick();self.assertEqual(len(calls),1)
     with store.db() as db:self.assertEqual(db.execute("SELECT count(*) FROM web_jobs WHERE source='schedule'").fetchone()[0],100)
    for n in range(1,100):
     with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_service.time.monotonic',return_value=n*20):worker.tick()
    self.assertEqual(len(calls),100);self.assertEqual(len(set(calls)),100)
    with store.db() as db:self.assertEqual(db.execute("SELECT count(*) FROM web_jobs WHERE state='done'").fetchone()[0],100)
   finally:state.close()

 def test_default_school_flow_uses_saved_http_session_without_a_browser(self):
  from test_workflows import FakeTransport
  from moonuestc.runner import run_account
  with tempfile.TemporaryDirectory() as root:
   store=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));admin=store.create_user(None,{'username':'admin','password':'Synthetic-admin-2026!','role':'admin'},bootstrap=True)
   fields=WebCase.account_fields(None,location={'mode':'fixed','name':'Synthetic point','latitude':0,'longitude':0,'coordinate_system':'gcj02','reverse_geocode':'Synthetic place'})
   account=store.save_account(admin,fields);store.enqueue(admin,account['id'],'checkin','schedule',INSTANT.date().isoformat())
   transport=FakeTransport();transport.session=True
   worker=WebWorker(store,runner=lambda a,m,s,d,**kw:run_account(a,m,s,d,clock=lambda:INSTANT,sleep=lambda _:None,**kw))
   with patch('moonuestc.web_service.now',return_value=INSTANT),patch('moonuestc.web_service.EncryptedTransport',return_value=transport),patch('moonuestc.assisted_auth.BrowserBridge.call',side_effect=AssertionError('Scheduled task invoked a browser')) as browser:
    worker.run_one();browser.assert_not_called()
   self.assertEqual(transport.post_count,1);self.assertFalse(any(stage=='cas_submit' for _,stage in transport.calls))
 def test_scheduled_deadline_is_reported_without_contacting_school(self):
  with tempfile.TemporaryDirectory() as root:
   store=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));store.execution_window=('21:06','23:24')
   admin=store.create_user(None,{'username':'admin','password':'Synthetic-admin-2026!','role':'admin'},bootstrap=True)
   account=store.save_account(admin,WebCase.account_fields(None));store.enqueue(admin,account['id'],'checkin','schedule',INSTANT.date().isoformat())
   calls=[];worker=WebWorker(store,runner=lambda *a,**kw:calls.append(True))
   with patch('moonuestc.web_service.now',return_value=INSTANT.replace(hour=23,minute=25)):worker.run_one()
   self.assertEqual(calls,[]);self.assertEqual(store.jobs(admin)[0]['result']['reason'],'schedule_deadline_missed')

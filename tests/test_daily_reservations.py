"""Daily dispatch stays within the preference band and survives restarts."""
import datetime as dt,tempfile,unittest
from unittest.mock import patch
from argon2 import PasswordHasher
from moonuestc.daily_plan import normalize_variation
from moonuestc.web_store import WebStore
from moonuestc.policy import SHANGHAI
from moonuestc.scheduling import slot_target
from dashboard_helpers import WebCase
from moonuestc.web_service import WebWorker
from moonuestc.state import State
from moonuestc.runner import account_key

class DailyReservations(unittest.TestCase):
 def test_worker_uses_the_persisted_daily_target_once_and_skips_completed_manual_days(self):
  with tempfile.TemporaryDirectory() as root:
   s=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));s.execution_window=('21:06','23:24');admin=s.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   a=s.save_account(admin,WebCase.account_fields(None,variation={'minutes':5,'meters':0}));payload=s.job_payload({'account_id':a['id']});state=State(root)
   state.claim(account_key(payload),'2026-09-30');state.outcome(account_key(payload),'2026-09-30','confirmed');state.close();s.save_account(admin,{'automatic':True},a['id'])
   calls=[];worker=WebWorker(s,runner=lambda *args,**kwargs:calls.append(True) or {'result':'confirmed'})
   for n in range(3):
    instant=dt.datetime(2026,10,1,tzinfo=SHANGHAI)+dt.timedelta(days=n);day=instant.date().isoformat()
    with patch('moonuestc.web_store.now',return_value=instant):
     s.ensure_slots(day=day)
     with s.db() as db:reserved=db.execute('SELECT minute FROM web_schedule_slots WHERE account_id=?',(a['id'],)).fetchone()[0]
    target=dt.datetime.fromisoformat(day+'T'+slot_target(payload,day,reserved)).replace(tzinfo=SHANGHAI)
    with patch('moonuestc.web_store.now',return_value=target),patch('moonuestc.web_service.now',return_value=target),patch('moonuestc.web_store.time.time',return_value=target.timestamp()):
     if n==2:
      jid=s.enqueue(admin,a['id'],'checkin',business_date=day);job=s.claim_job();s.finish_job(job,{'result':'confirmed','businessDate':day,'status':'CHECKED_IN'})
     worker.schedule_once();worker.schedule_once()
     if n<2:self.assertTrue(worker.run_one())
     with s.db() as db:self.assertEqual(db.execute("SELECT count(*) FROM web_jobs WHERE business_date=? AND source='schedule'",(day,)).fetchone()[0],0 if n==2 else 1)
   self.assertEqual(len(calls),2)
 def test_crowded_preferences_never_spill_outside_the_requested_band(self):
  with tempfile.TemporaryDirectory() as root:
   s=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));s.execution_window=('21:06','23:24');admin=s.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   values=[s.save_account(admin,WebCase.account_fields(None,student='20260000'+str(n).zfill(4),variation={'minutes':5,'meters':0})) for n in range(12)]
   self.assertEqual(sum(a['schedule_slot'] is not None for a in values),11)
   self.assertIsNone(values[-1]['schedule_slot'])
   self.assertTrue(all('21:55'<=a['schedule_slot']['start']<='22:05' for a in values if a['schedule_slot']))
 def test_ten_meter_radius_is_supported_and_larger_values_are_rejected(self):
  self.assertEqual(normalize_variation({'minutes':5,'meters':10}),{'minutes':5,'meters':10})
  for values in ({'minutes':6,'meters':10},{'minutes':5,'meters':11}):
   with self.assertRaises(Exception):normalize_variation(values)
 def test_random_daily_minute_then_small_stagger_is_stable_inside_five_minutes(self):
  with tempfile.TemporaryDirectory() as root:
   store=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));store.execution_window=('21:06','23:24')
   admin=store.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   a=store.save_account(admin,WebCase.account_fields(None,variation={'minutes':5,'meters':0}))
   minutes=[]
   for n in range(30):
    instant=dt.datetime(2026,10,1,tzinfo=SHANGHAI)+dt.timedelta(days=n)
    with patch('moonuestc.web_store.now',return_value=instant):
     store.ensure_slots(day=instant.date().isoformat())
     with store.db() as db:
      row=db.execute('SELECT * FROM web_schedule_slots WHERE account_id=?',(a['id'],)).fetchone();payload=store._payload(db.execute('SELECT * FROM web_accounts WHERE id=?',(a['id'],)).fetchone())
     minutes.append(row['minute']);self.assertTrue(1315<=row['minute']<=1325)
     target=slot_target(payload,instant.date().isoformat(),row['minute']);self.assertTrue(0<=int(target[-2:])<20)
     store.ensure_slots(day=instant.date().isoformat())
     with store.db() as db:self.assertEqual(db.execute('SELECT minute FROM web_schedule_slots WHERE account_id=?',(a['id'],)).fetchone()[0],row['minute'])
   self.assertGreater(len(set(minutes)),5)

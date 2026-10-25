import datetime as dt,tempfile,unittest
from unittest.mock import patch
from argon2 import PasswordHasher
from moonuestc.web_store import WebStore
from moonuestc.policy import SHANGHAI
from moonuestc.scheduling import reserve_slot,slot_bounds,slot_target

class Slots(unittest.TestCase):
 def test_one_hundred_spread_preferences_have_distinct_persistent_slots(self):
  with tempfile.TemporaryDirectory() as root:
   store=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));store.execution_window=('21:06','23:24')
   admin=store.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   from dashboard_helpers import WebCase
   slots=[]
   for n in range(100):
    a=store.save_account(admin,WebCase.account_fields(None,student='20260000'+str(n).zfill(4),run_at='%02d:%02d'%divmod(1266+n,60)))
    slots.append(a['schedule_slot'])
   self.assertEqual(len({s['start'] for s in slots}),100)
   self.assertTrue(all('21:06'<=s['start']<='23:19' for s in slots))
   restored=WebStore(root,store.hasher);restored.execution_window=store.execution_window
   self.assertEqual([a['schedule_slot'] for a in restored.accounts(admin)],slots)
 def test_preferred_time_change_respects_another_reserved_slot(self):
  with tempfile.TemporaryDirectory() as root:
   store=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));store.execution_window=('21:06','23:24')
   from dashboard_helpers import WebCase
   admin=store.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   a=store.save_account(admin,WebCase.account_fields(None,variation={'minutes':5,'meters':0}));b=store.save_account(admin,WebCase.account_fields(None,variation={'minutes':5,'meters':0},student='202600000002'))
   changed=store.save_account(admin,{'run_at':b['schedule_slot']['start']},a['id'])
   self.assertNotEqual(changed['schedule_slot']['start'],b['schedule_slot']['start'])
 def test_daily_jitter_stays_inside_assigned_slot(self):
  for n in range(365):
   day=(dt.date(2026,1,1)+dt.timedelta(days=n)).isoformat();target=slot_target({'id':'synthetic','variation':{'minutes':5,'meters':5}},day,1320)
   self.assertTrue('22:00:00'<=target<'22:00:30')
 def test_school_window_is_respected_and_no_slot_is_silently_reused(self):
  with tempfile.TemporaryDirectory() as root:
   store=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));store.execution_window=('21:06','23:24')
   from dashboard_helpers import WebCase
   admin=store.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   a=store.save_account(admin,WebCase.account_fields(None))
   with store.db(True) as db:
    chosen=reserve_slot(db,a['id'],'21:06',store.execution_window,replace=True,school={'start':'21:15','end':'23:30'})
   self.assertIsNone(chosen)
   with store.db(True) as db:chosen=reserve_slot(db,a['id'],'21:18',store.execution_window,replace=True,school={'start':'21:15','end':'23:30'})
   self.assertGreaterEqual(chosen,21*60+15)
   with self.assertRaises(Exception):store.save_account(admin,{'schedule_slot':{'start':'21:06'}},a['id'])

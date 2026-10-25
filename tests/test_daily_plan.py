import datetime as dt,unittest,math
import tempfile
from moonuestc.daily_plan import normalize_variation,planned_time,position_for,verify_circle
from moonuestc.errors import ToolError

ACCOUNT={'id':'synthetic','student_id':'202600000001','variation_seed':'synthetic-only','variation':{'minutes':5,'meters':10}}
class DailyPlan(unittest.TestCase):
 def test_daily_values_are_stable_for_refresh_retry_and_restart(self):
  a=position_for(ACCOUNT,'2026-10-22',30.753607,103.935437)
  self.assertEqual(a,position_for(dict(ACCOUNT),'2026-10-22',30.753607,103.935437))
  self.assertNotEqual(a,position_for(ACCOUNT,'2026-10-23',30.753607,103.935437))
 def test_all_daily_points_stay_inside_ten_meter_circle(self):
  for day in range(365):
   date=(dt.date(2026,1,1)+dt.timedelta(days=day)).isoformat();lat,lng=position_for(ACCOUNT,date,30.753607,103.935437)
   distance=6371000*math.hypot(math.radians(lat-30.753607),math.radians(lng-103.935437)*math.cos(math.radians(30.753607)))
   self.assertLessEqual(distance,10.00001)
 def test_times_are_per_day_and_clamped_to_user_and_school_windows(self):
  for day in range(100):
   date=(dt.date(2026,1,1)+dt.timedelta(days=day)).isoformat()
   for base in ('21:06','22:00','23:24'):
    value=planned_time(ACCOUNT,base,date,('21:06','23:24'))
    self.assertGreaterEqual(value,'21:06');self.assertLessEqual(value,'23:24')
    self.assertEqual(value,planned_time(ACCOUNT,base,date,('21:06','23:24')))
   self.assertEqual(planned_time(ACCOUNT,'21:06',date,('21:06','23:24'),{'start':'21:15','end':'23:30'}),'21:15')
 def test_no_variation_preserves_exact_existing_coordinates(self):
  self.assertEqual(position_for({},'2026-10-22',30.7,103.9),(30.7,103.9))
 def test_invalid_ranges_and_bool_are_rejected(self):
  for value in ({'minutes':6},{'meters':11},{'meters':True},{'minutes':-1},{'anything':5}):
   with self.assertRaises(ToolError):normalize_variation(value)
 def test_entire_circle_must_fit_school_fence_without_snapping(self):
  fence=[{'latitude':30.753587,'longitude':103.935454,'radiusMeter':150}]
  verify_circle(30.753607,103.935437,10,fence)
  with self.assertRaises(ToolError):verify_circle(30.753780,103.932328,5,fence)
  with self.assertRaises(ToolError):verify_circle(30.753587,103.935454,5,[dict(fence[0],radiusMeter=3)])

class DailyExecution(unittest.TestCase):
 def test_real_runner_uses_daily_point_and_never_resubmits_unknown_result(self):
  from test_fixed_locations import fixed_account,RecordingTransport
  from test_workflows import INSTANT
  from moonuestc.state import State
  from moonuestc.runner import run_account
  account={**fixed_account(),'variation':{'minutes':5,'meters':10},'variation_seed':'synthetic-only','_execution_window':('21:06','23:24')}
  transport=RecordingTransport();transport.timeout_post=True
  with tempfile.TemporaryDirectory() as root:
   state=State(root)
   try:
    kwargs={'clock':lambda:INSTANT,'sleep':lambda _:None,'transport_factory':lambda *a:transport}
    first=run_account(account,'checkin',state,root,**kwargs)
    point=transport.last_payload.copy();second=run_account(account,'checkin',state,root,**kwargs)
    self.assertEqual(first['result'],'submission_unknown');self.assertEqual(second['result'],'submission_unknown');self.assertEqual(transport.post_count,1)
    expected=position_for(account,INSTANT.date().isoformat(),account['location']['latitude'],account['location']['longitude'])
    self.assertEqual((point['latitude'],point['longitude']),expected)
   finally:state.close()
 def test_local_window_stops_before_school_post_and_durable_claim(self):
  from test_fixed_locations import fixed_account,RecordingTransport
  from test_workflows import INSTANT
  from moonuestc.state import State
  from moonuestc.runner import run_account,account_key
  transport=RecordingTransport();account={**fixed_account(),'_execution_window':('21:06','23:24')}
  with tempfile.TemporaryDirectory() as root:
   state=State(root)
   try:
    with self.assertRaises(ToolError) as error:run_account(account,'checkin',state,root,clock=lambda:INSTANT.replace(hour=23,minute=25),sleep=lambda _:None,transport_factory=lambda *a:transport)
    self.assertEqual(error.exception.reason,'outside_execution_window');self.assertEqual(transport.post_count,0);self.assertFalse(state.claimed(account_key(account),INSTANT.date().isoformat()))
   finally:state.close()

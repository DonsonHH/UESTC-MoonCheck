import unittest
import test_portal as fixtures
from moonuestc.policy import build_payload,now

class StudentPlan(unittest.TestCase):
 setUp=fixtures.PortalCase.setUp
 tearDown=fixtures.PortalCase.tearDown
 login=fixtures.PortalCase.login
 request=fixtures.PortalCase.request
 def prepare(self):
  self.store.allowed_presets=('xuezhi_group2_amap','xuezhi_group5_amap');self.store.execution_window=('21:06','23:24')
  login=self.login();self.assertEqual(login.status_code,200,login.json)
  return login.json['csrf_token'],self.request('/api/portal/me').json['account']
 def test_new_account_requires_choosing_location_and_lists_only_open_groups(self):
  _,account=self.prepare();self.assertFalse(account['location_open']);self.assertIsNone(account['location'])
  options=self.request('/api/locations').json
  self.assertEqual([x['id'] for x in options['locations']],list(self.store.allowed_presets));self.assertFalse(options['custom_allowed'])
 def test_save_rejects_unopened_locations_custom_coordinates_and_outside_times(self):
  csrf,account=self.prepare();path='/api/accounts/'+account['id']
  for data in [{'location':{'mode':'preset','preset':'xuezhi_group3_amap'}},{'location':{'mode':'fixed','name':'synthetic','latitude':30,'longitude':103}},{'location':{'mode':'preset','preset':'xuezhi_group5_amap'},'run_at':'21:05'},{'location':{'mode':'preset','preset':'xuezhi_group5_amap'},'run_at':'23:25'}]:
   self.assertEqual(self.request(path,'PATCH',data,csrf).status_code,400)
 def test_save_daily_variation_and_read_planned_time_without_exposing_seed(self):
  csrf,account=self.prepare();path='/api/accounts/'+account['id']
  result=self.request(path,'PATCH',{'location':{'mode':'preset','preset':'xuezhi_group5_amap'},'run_at':'21:06','variation':{'minutes':5,'meters':10}},csrf)
  self.assertEqual(result.status_code,200,result.json);public=result.json['account']
  self.assertEqual(public['variation'],{'minutes':5,'meters':10});self.assertNotIn('variation_seed',public)
  self.assertTrue('21:06'<=public['planned_run_at']<='21:11:59')
  payload=self.store.job_payload({'account_id':account['id']});self.assertTrue(payload['variation_seed'])
  instant=now();self.assertEqual(build_payload(payload,instant),build_payload(payload,instant))
 def test_client_cannot_set_variation_seed_or_exceed_ten_meter_limit(self):
  csrf,account=self.prepare();path='/api/accounts/'+account['id']
  self.assertEqual(self.request(path,'PATCH',{'variation_seed':'chosen-by-client'},csrf).status_code,400)
  self.assertEqual(self.request(path,'PATCH',{'location':{'mode':'preset','preset':'xuezhi_group5_amap'},'variation':{'meters':11}},csrf).status_code,400)

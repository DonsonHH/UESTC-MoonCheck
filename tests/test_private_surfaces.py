"""Public and private listeners share data, never administrator reachability."""
import tempfile,unittest
from argon2 import PasswordHasher
from moonuestc.web_app import create_app
from pathlib import Path

PUBLIC='https://moon.example.test';PRIVATE='http://127.0.0.1:4497';PASSWORD='Synthetic-Admin-Password-2026!'
class PrivateSurfaces(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);fast=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1)
  self.public=create_app(self.root,PUBLIC,portal_enabled=True,surface='public',school_verifier=lambda a:[],hasher=fast)
  self.store=self.public.extensions['moon_store'];self.store.create_user(None,{'username':'admin','password':PASSWORD,'role':'admin'},bootstrap=True)
  self.private=create_app(self.root,PRIVATE,allow_http=True,portal_enabled=True,surface='admin',start_worker=True,hasher=fast)
  self.pc=self.public.test_client();self.ac=self.private.test_client()
 def tearDown(self):self.temp.cleanup()
 def post(self,client,origin,path,value):return client.post(path,base_url=origin,json=value,headers={'Origin':origin})
 def test_admin_ui_and_api_unreachable_from_public_even_with_admin_cookie(self):
  login=self.post(self.ac,PRIVATE,'/api/admin/login',{'username':'admin','password':PASSWORD});self.assertEqual(login.status_code,200)
  token=self.ac.get_cookie('moon_dashboard_session',domain='127.0.0.1').value
  self.pc.set_cookie('moon_dashboard_session',token,domain='moon.example.test')
  for path in ['/admin','/admin/login','/admin/users','/admin/accounts','/api/users','/api/portal/authorizations']:
   self.assertEqual(self.pc.get(path,base_url=PUBLIC).status_code,404,path)
  for path in ['/api/login','/api/admin/login']:
   self.assertEqual(self.post(self.pc,PUBLIC,path,{'username':'admin','password':PASSWORD}).status_code,404)
  self.assertEqual(self.pc.get('/api/accounts',base_url=PUBLIC).status_code,401)
  self.assertEqual(self.ac.get('/api/users',base_url=PRIVATE).status_code,200)
  self.assertIsNotNone(self.store.session(token),'Public probing revoked the private operator session')
 def test_private_instance_cannot_start_a_second_scheduler_or_student_onboarding(self):
  self.assertIsNone(self.private.extensions['moon_worker'].thread)
  self.assertEqual(self.ac.get('/',base_url=PRIVATE).headers['Location'],'/admin/login')
  self.assertEqual(self.post(self.ac,PRIVATE,'/api/portal/login',{'student_id':'202600000001','password':'synthetic'}).status_code,404)
  self.assertFalse(self.pc.get('/api/interface',base_url=PUBLIC).json['adminInterface'])
  self.assertTrue(self.ac.get('/api/interface',base_url=PRIVATE).json['adminInterface'])
 def test_public_student_login_still_works_and_public_host_cannot_be_spoofed(self):
  response=self.post(self.pc,PUBLIC,'/api/portal/login',{'student_id':'202600000001','password':'Synthetic-school-pass!','browser_fingerprint':'0'*32,'user_agent':'Synthetic browser User Agent'})
  self.assertEqual(response.status_code,200,response.json)
  self.assertEqual(self.pc.get('/api/accounts',base_url=PUBLIC).status_code,200)
  for headers in ({'Host':'127.0.0.1:4497'},{'X-Forwarded-Host':'127.0.0.1:4497'},{'X-Forwarded-For':'127.0.0.1'}):
   self.assertNotEqual(self.pc.get('/api/users',base_url=PUBLIC,headers=headers).status_code,200)

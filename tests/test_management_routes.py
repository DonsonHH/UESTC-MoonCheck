"""Real HTTP roles, deletion/re-onboarding and deep links; synthetic school boundary."""
import tempfile,unittest
from pathlib import Path
from argon2 import PasswordHasher
from moonuestc.web_app import create_app
from moonuestc.state import State
from moonuestc.runner import account_key
from moonuestc.policy import now

ORIGIN='https://moon.example.test'
PASSWORD='Synthetic-school-pass-2026!'
class ManagementRoutes(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.app=create_app(self.root,ORIGIN,portal_enabled=True,surface='combined',registration_enabled=False,school_verifier=lambda account:[],hasher=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1))
        self.store=self.app.extensions['moon_store']
        self.admin=self.store.create_user(None,{'username':'admin','password':'Synthetic-Admin-Pass-2026!','role':'admin'},bootstrap=True)
        self.ac=self.app.test_client();reply=self.post(self.ac,'/api/admin/login',{'username':'admin','password':'Synthetic-Admin-Pass-2026!'})
        self.csrf=reply.json['csrf_token'];self.student=self.app.test_client();self.login_student()
    def tearDown(self):self.temp.cleanup()
    def post(self,client,path,data):return client.post(path,base_url=ORIGIN,headers={'Origin':ORIGIN},json=data)
    def login_student(self):
        reply=self.post(self.student,'/api/portal/login',{'student_id':'202600000001','password':PASSWORD,'browser_fingerprint':'0123456789abcdef0123456789abcdef','user_agent':'Synthetic school browser for route tests'})
        self.assertEqual(reply.status_code,200,reply.json);self.user=reply.json['user']
        self.account=self.student.get('/api/portal/me',base_url=ORIGIN).json['account'];return reply
    def delete(self,path,token=None):return self.ac.delete(path,base_url=ORIGIN,headers={'Origin':ORIGIN,'X-CSRF-Token':self.csrf if token is None else token})
    def test_admin_deletes_school_account_and_student_can_rebind_without_resetting_daily_claims(self):
        original=self.account['id'];payload=self.store.job_payload({'account_id':original});key=account_key(payload);day=now().date().isoformat()
        state=State(self.root);state.claim(key,day);state.outcome(key,day,'confirmed');state.close()
        self.assertEqual(self.delete('/api/accounts/'+original).status_code,200)
        self.assertEqual(self.student.get('/api/accounts',base_url=ORIGIN).status_code,401)
        self.assertEqual(len(self.store.accounts(self.admin)),0)
        state=State(self.root);self.assertTrue(state.claimed(key,day));state.close()
        self.login_student();self.assertNotEqual(self.account['id'],original)
        self.assertEqual(len(self.store.accounts(self.user)),1)
    def test_delete_user_removes_binding_and_sessions_but_cannot_remove_current_admin(self):
        self.assertEqual(self.delete('/api/users/'+str(self.user['id'])).status_code,200)
        self.assertEqual(self.student.get('/api/portal/me',base_url=ORIGIN).status_code,401)
        self.assertEqual(len(self.store.users()),1);self.assertEqual(self.store.accounts(self.admin),[])
        self.assertEqual(self.delete('/api/users/'+str(self.admin['id'])).status_code,409)
    def test_busy_account_and_missing_csrf_rejected(self):
        path='/api/accounts/'+self.account['id']
        self.assertEqual(self.delete(path,token='wrong').status_code,403)
        self.store.enqueue(self.admin,self.account['id'],'diagnose')
        self.assertEqual(self.delete(path).status_code,409)
        self.assertEqual(len(self.store.accounts(self.admin)),1)
    def test_deep_links_reload_and_admin_paths_are_role_guarded(self):
        for path in ['/admin','/admin/accounts','/admin/users','/admin/history']:
            with self.subTest(path=path):
                with self.ac.get(path,base_url=ORIGIN) as response:self.assertEqual(response.status_code,200)
                self.assertEqual(self.student.get(path,base_url=ORIGIN).status_code,403)
        for path in ['/app','/app/history','/app/settings']:
            with self.student.get(path,base_url=ORIGIN) as response:self.assertEqual(response.status_code,200)
        self.assertEqual(self.app.test_client().get('/',base_url=ORIGIN).headers['Location'],'/login')
        self.assertEqual(self.ac.get('/',base_url=ORIGIN).headers['Location'],'/admin')
        self.assertEqual(self.student.get('/',base_url=ORIGIN).headers['Location'],'/app')
        self.assertEqual(self.ac.get('/admin/not-a-route',base_url=ORIGIN).status_code,404)

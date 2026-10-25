"""Browser-service boundary is synthetic; no school requests or real credentials."""
import base64,tempfile,unittest
from pathlib import Path
from argon2 import PasswordHasher
from moonuestc.web_app import create_app
from moonuestc.web_errors import WebError

ORIGIN='https://moon.example.test'
PASSWORD='Synthetic-school-password-2026!'
FINGERPRINT='0123456789abcdef0123456789abcdef'

class FakeBridge:
    def __init__(self):self.calls=[];self.index=0;self.ready=False
    def call(self,action,data):
        self.calls.append((action,dict(data)))
        if action=='start':self.index+=1;return {'id':str(self.index)}
        if action=='state':return {'ready':self.ready,'image':'synthetic','fields':[],'width':420,'height':760,'host':'idas.uestc.edu.cn','expires_in':280,'browser_fingerprint':FINGERPRINT,'cookies':['private']}
        if action=='result':
            if not self.ready:raise WebError(503,'browser_unavailable','not ready')
            return {'browser_fingerprint':FINGERPRINT,'user_agent':'Synthetic assisted-school browser'}
        return {}

class AssistedCase(unittest.TestCase):
    def test_regular_device_profiles_are_private_stable_and_distinct_per_student(self):
        for student in ('202600000001','202600000002'):
            self.manager.portal.login({'student_id':student,'password':PASSWORD,'browser_fingerprint':FINGERPRINT,'user_agent':'Synthetic assisted-school browser'},'127.0.0.1')
        values=[]
        for student in ('202600000001','202600000001','202600000002'):
            token,csrf=self.manager.start({'student_id':student,'password':PASSWORD},'127.0.0.1')
            reply=next(data for action,data in reversed(self.bridge.calls) if action=='start')
            values.append(reply['device_profile']);self.assertEqual(len(values[-1]),24)
            self.manager.close(__import__('hashlib').sha256(token.encode()).hexdigest())
        self.assertEqual(values[0],values[1]);self.assertNotEqual(values[0],values[2])
        self.assertNotIn('202600000001',values[0])
    def test_new_profile_is_kept_only_after_verification_and_old_login_needs_no_browser(self):
        profiles=[]
        for _ in range(2):
            token,csrf=self.manager.start({'student_id':'202600000001','password':PASSWORD},'127.0.0.1')
            profiles.append(self.manager.get(token)['device_profile'])
            if len(profiles)==1:self.manager.close(__import__('hashlib').sha256(token.encode()).hexdigest())
        self.assertNotEqual(profiles[0],profiles[1]);self.bridge.ready=True
        self.manager.finish(token,csrf)
        token,csrf=self.manager.start({'student_id':'202600000001','password':PASSWORD},'127.0.0.1')
        self.assertEqual(self.manager.get(token)['device_profile'],profiles[1])
        before=len(self.bridge.calls);school_before=len(self.school)
        self.manager.portal.login({'student_id':'202600000001','password':PASSWORD},'127.0.0.1')
        self.assertEqual(len(self.bridge.calls),before);self.assertEqual(len(self.school),school_before)
        self.assertEqual(self.post('start',{'student_id':'202600000001','password':PASSWORD,'fresh_environment':True}).status_code,400)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.bridge=FakeBridge();self.school=[]
        def verifier(data):self.school.append(data);return []
        self.app=create_app(Path(self.temp.name),ORIGIN,portal_enabled=True,surface='combined',registration_enabled=False,
            browser_bridge=self.bridge,school_verifier=verifier,hasher=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1))
        self.store=self.app.extensions['moon_store'];self.manager=self.app.extensions['moon_assisted']
        self.store.create_user(None,{'username':'admin','password':'Synthetic-admin-password-2026!','role':'admin'},bootstrap=True)
        self.client=self.app.test_client()
    def tearDown(self):
        for token in list(self.manager.pending):self.manager.close(token)
        self.temp.cleanup()
    def post(self,path,data=None,token='',client=None,origin=ORIGIN):
        return (client or self.client).post('/api/onboarding/'+path,base_url=ORIGIN,json=data or {},headers={'Origin':origin,'X-Onboarding-CSRF':token})
    def start(self):
        return self.post('start',{'student_id':'202600000001','password':PASSWORD})
    def test_state_preserves_passive_original_document_without_full_page_image(self):
        self.start();original=self.bridge.call
        self.bridge.call=lambda action,data:({'ready':False,'mode':'page','html':'<html><body><div hidden>Hidden modal</div><button>School button</button></body></html>','revision':'abc','width':1280,'height':900,'host':'idas.uestc.edu.cn','expires_in':280,'document':'doc','image':'must-not-be-forwarded','cookies':['private']} if action=='state' else original(action,data))
        response=self.client.get('/api/onboarding/state',base_url=ORIGIN)
        self.assertEqual(response.json.get('mode'),'page')
        self.assertIn('<div hidden>',response.json['html'])
        self.assertNotIn('image',response.json)
        self.assertNotIn('cookies',response.json)
    def test_owner_event_cannot_use_old_unscoped_screen_coordinates(self):
        csrf=self.start().json['onboarding_csrf']
        self.assertEqual(self.post('event',{'kind':'click','x':2,'y':2},csrf).status_code,400)
    def test_passive_document_compression_obeys_accept_encoding(self):
        import gzip
        self.start();original=self.bridge.call
        self.bridge.call=lambda action,data:({'mode':'page','html':'<html>'+('document-text '*1000)+'</html>','document':'doc','revision':'a'*64,'ready':False} if action=='state' else original(action,data))
        response=self.client.get('/api/onboarding/state',base_url=ORIGIN,headers={'Accept-Encoding':'gzip'})
        self.assertEqual(response.headers['Content-Encoding'],'gzip')
        self.assertIn(b'document-text',gzip.decompress(response.data))
        denied=self.client.get('/api/onboarding/state',base_url=ORIGIN,headers={'Accept-Encoding':'gzip;q=0'})
        self.assertNotIn('Content-Encoding',denied.headers)
    def test_original_page_assets_are_owner_bound_and_reject_executable_content(self):
        token=self.start().json['onboarding_csrf'];original=self.bridge.call
        mime='image/png'
        self.bridge.call=lambda action,data:({'mime':mime,'body':base64.b64encode(b'synthetic-image').decode()} if action=='asset' else original(action,data))
        path='/api/onboarding/assets/'+'a'*32
        self.assertEqual(self.app.test_client().get(path,base_url=ORIGIN).status_code,410)
        response=self.client.get(path,base_url=ORIGIN)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.data,b'synthetic-image')
        mime='text/html'
        self.assertEqual(self.client.get(path,base_url=ORIGIN).status_code,400)
        self.assertEqual(self.client.get('/api/onboarding/assets/not-a-key',base_url=ORIGIN).status_code,400)
    def test_start_needs_only_student_and_password_and_state_does_not_disclose_cookies(self):
        started=self.start();self.assertEqual(started.status_code,200,started.json)
        self.assertIn('onboarding_csrf',started.json)
        self.assertNotIn(PASSWORD,started.get_data(as_text=True))
        state=self.client.get('/api/onboarding/state',base_url=ORIGIN)
        self.assertEqual(state.status_code,200)
        self.assertNotIn('cookies',state.json);self.assertNotIn(FINGERPRINT,state.get_data(as_text=True))
        self.assertEqual(self.store.accounts({'id':1,'role':'admin'}),[])
    def test_second_browser_and_cross_site_cannot_control_authentication(self):
        started=self.start();token=started.json['onboarding_csrf'];other=self.app.test_client()
        self.assertEqual(other.get('/api/onboarding/state',base_url=ORIGIN).status_code,410)
        self.assertEqual(self.post('event',{'kind':'click','x':2,'y':2},token,client=other).status_code,410)
        self.assertEqual(self.post('event',{'kind':'click','x':2,'y':2},'wrong').status_code,403)
        self.assertEqual(self.post('event',{'kind':'click','x':2,'y':2},token,origin='https://evil.example').status_code,403)
    def test_finish_uses_school_result_server_side_then_logs_in_original_student(self):
        token=self.start().json['onboarding_csrf'];self.bridge.ready=True
        response=self.post('finish',{},token)
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(self.school[0]['student_id'],'202600000001')
        self.assertEqual(self.school[0]['browser_fingerprint'],FINGERPRINT)
        self.assertNotIn(FINGERPRINT,response.get_data(as_text=True))
        self.assertEqual(self.client.get('/api/portal/me',base_url=ORIGIN).json['account']['student_id'],'202600000001')
        self.assertEqual(self.manager.pending,{})
        self.assertEqual(self.client.get('/api/jobs',base_url=ORIGIN).json['jobs'],[])
    def test_cancel_and_expiry_remove_pending_password_and_close_browser(self):
        token=self.start().json['onboarding_csrf']
        self.assertEqual(self.post('cancel',{},token).status_code,200)
        self.assertEqual(self.manager.pending,{})
        self.assertEqual(self.client.get('/api/onboarding/state',base_url=ORIGIN).status_code,410)
        self.assertTrue(any(action=='close' for action,_ in self.bridge.calls))
    def test_backend_verification_failure_cannot_bind_account(self):
        token=self.start().json['onboarding_csrf'];self.bridge.ready=True
        self.app.extensions['moon_portal'].verifier=lambda data:(_ for _ in ()).throw(__import__('moonuestc.errors',fromlist=['ToolError']).ToolError('login_rejected','cas_submit'))
        response=self.post('finish',{},token)
        self.assertEqual(response.status_code,401)
        self.assertEqual(self.store.accounts({'id':1,'role':'admin'}),[])
        self.assertEqual(self.manager.pending,{})
    def test_wrong_finish_csrf_does_not_consume_owner_session(self):
        token=self.start().json['onboarding_csrf'];self.bridge.ready=True
        self.assertEqual(self.post('finish',{},'invalid').status_code,403)
        self.assertEqual(self.post('finish',{},token).status_code,200)
    def test_browser_worker_never_receives_a_user_chosen_navigation_url(self):
        token=self.start().json['onboarding_csrf']
        self.assertEqual(self.post('start',{'student_id':'202600000002','password':PASSWORD,'url':'http://169.254.169.254/'}).status_code,400)
        self.assertEqual(len([1 for action,_ in self.bridge.calls if action=='start']),1)

    def test_loading_frame_is_a_valid_intermediate_state_and_keeps_owner_session(self):
        token=self.start().json['onboarding_csrf'];original=self.bridge.call
        self.bridge.call=lambda action,data:({'ready':False,'loading':True,'fields':[],'host':'idas.uestc.edu.cn','expires_in':250,'width':420,'height':760} if action=='state' else original(action,data))
        response=self.client.get('/api/onboarding/state',base_url=ORIGIN)
        self.assertEqual(response.status_code,200);self.assertTrue(response.json['loading'])
        self.assertEqual(len(self.manager.pending),1)
        self.assertEqual(self.post('cancel',{},token).status_code,200)

if __name__=='__main__':unittest.main()

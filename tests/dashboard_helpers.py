import copy
import os
import tempfile
import unittest
from pathlib import Path
from argon2 import PasswordHasher
from moonuestc.web_app import create_app
import test_workflows as fixtures

ORIGIN='https://203.0.113.10:8443'
ADMIN_PASS='Admin-Strong-Pass-2026!'
USER_PASS='User-Strong-Pass-2026!'
FAST_HASHER=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1)


class WebCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='moon-dashboard-',dir=os.environ.get('MOON_TEST_TMP'))
        self.root=Path(self.temp.name)
        self.calls=[]
        def fake_runner(payload,mode,state,directory,**kwargs):
            self.calls.append((payload,mode))
            return {'result':'auth_ready' if mode=='diagnose' else 'dry_run_ready',
                    'businessDate':__import__('moonuestc.policy',fromlist=['now']).now().date().isoformat()}
        self.app=create_app(self.root,ORIGIN,hasher=FAST_HASHER,runner=fake_runner)
        self.store=self.app.extensions['moon_store']
        self.worker=self.app.extensions['moon_worker']
        self.admin=self.store.create_user(None,{'username':'admin','display_name':'管理员','password':ADMIN_PASS,'role':'admin'},bootstrap=True)
        self.u1=self.store.create_user(self.admin,{'username':'alice','display_name':'同学甲','password':USER_PASS})
        self.u2=self.store.create_user(self.admin,{'username':'bob','display_name':'同学乙','password':USER_PASS})
        self.store.reset_password_local('alice',USER_PASS)
        self.store.reset_password_local('bob',USER_PASS)
        self.ac,self.at=self.login_client('admin',ADMIN_PASS)
        self.c1,self.t1=self.login_client('alice',USER_PASS)
        self.c2,self.t2=self.login_client('bob',USER_PASS)

    def tearDown(self):
        self.worker.stop()
        self.temp.cleanup()

    def login_client(self,username,password):
        client=self.app.test_client()
        response=client.post('/api/login',base_url=ORIGIN,headers={'Origin':ORIGIN},json={'username':username,'password':password})
        self.assertEqual(response.status_code,200,response.get_json())
        return client,response.get_json()['csrf_token']

    def req(self,client,token,path,method='GET',data=None,origin=ORIGIN,extra_headers=None):
        headers={'Origin':origin,'X-CSRF-Token':token}
        headers.update(extra_headers or {})
        return client.open(path,method=method,base_url=ORIGIN,headers=headers,json=data)

    def account_fields(self,student='202300000001',**kwargs):
        return {'label':'我的学校账号','student_id':student,'password':fixtures.ACCOUNT['password'],
                'browser_fingerprint':fixtures.ACCOUNT['browser_fingerprint'],
                'user_agent':fixtures.ACCOUNT['user_agent'],'location':{'mode':'preset','preset':'xuezhi_group3_amap'},
                'enabled':True,'automatic':False,'run_at':'22:00',**kwargs}

    def add_account(self,owner=1,student='202300000001',**kwargs):
        client,token=(self.c1,self.t1) if owner==1 else (self.c2,self.t2)
        response=self.req(client,token,'/api/accounts','POST',self.account_fields(student,**kwargs))
        self.assertEqual(response.status_code,201,response.get_json())
        return response.get_json()['account']

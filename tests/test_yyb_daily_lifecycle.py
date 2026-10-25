"""A single consent survives expired credentials, new days and new workers."""
import base64
from contextlib import ExitStack
import datetime as dt
import hashlib
import time
from unittest.mock import patch

from dashboard_helpers import WebCase,FAST_HASHER
import test_workflows as f
from test_submission_diagnostics import DiagnosticTransport
from test_yyb_authorization import FakeClient
from moonuestc.runner import account_key,run_account
from moonuestc.state import State
from moonuestc.web_store import WebStore
from moonuestc.web_service import WebWorker
from moonuestc.wechat_authorization import CONSENT_VERSION,WechatManager


class DailyClient(FakeClient):
    def __init__(self,label):super().__init__();self.label=label;self.serial=0;self.refresh_inputs=[]
    def call(self,operation,**values):
        if operation=='refresh':
            self.calls.append(operation);self.refresh_inputs.append(values['credentials']['refreshtoken'])
            return {**values['credentials'],'accesstoken':'synthetic-access-'+self.label,
                    'refreshtoken':'synthetic-refresh-'+self.label,'expires_at':time.time()+7200}
        if operation=='code':
            self.calls.append(operation);self.serial+=1
            return {'code':'synthetic-code-'+self.label+'-'+str(self.serial)}
        return super().call(operation,**values)


class DailyGateway:
    used=set()
    def __init__(self,account):self.account=account
    def consume(self,code):
        if code in self.used:raise AssertionError('A one-use login code was reused')
        self.used.add(code)
    def bind(self,code):
        self.consume(code)
        return {'id':'synthetic-school-user','username':self.account['student_id'],'fullName':'合成同学'}
    def ticket(self,code):
        self.consume(code)
        return {'ticket':base64.urlsafe_b64encode(hashlib.sha256(code.encode()).digest()).decode().rstrip('='),
                'expiresAt':str(int((time.time()+1800)*1000))}
    def close(self):pass


class DailyTransport(DiagnosticTransport):
    def __init__(self,instant,student):super().__init__(instant);self.student=student;self.tickets=[]
    def request(self,method,url,**values):
        if values['stage']=='wechat_business_identity':
            self.calls.append((method,values['stage']))
            return f.response(url,{'code':0,'ok':True,'data':{'userData':{
                'id':'synthetic-school-user','username':self.student,'fullName':'合成同学'}}})
        if values['stage']=='checkin_post':self.tickets.append(values['headers'].get('X-Checkin-Ticket'))
        return super().request(method,url,**values)


class DailyLifecycle(WebCase):
    def setUp(self):
        super().setUp();DailyGateway.used=set()
        self.a=self.add_account(location={'mode':'fixed','name':'Synthetic point','latitude':0,'longitude':0,
            'coordinate_system':'gcj02','reverse_geocode':'Synthetic place'},variation={'minutes':0,'meters':0})
        self.store.execution_window=('21:06','23:24')
        with self.store.db() as db:payload=self.store._payload(self.store._row(db,self.u1,self.a['id']))
        state=State(self.root)
        try:
            state.claim(account_key(payload),(f.INSTANT.date()-dt.timedelta(days=2)).isoformat())
            state.outcome(account_key(payload),(f.INSTANT.date()-dt.timedelta(days=2)).isoformat(),'confirmed')
            state.require_school_client(46001)
        finally:state.close()
        self.store.save_account(self.u1,{'automatic':True},self.a['id'])
        client=DailyClient('initial');manager=WechatManager(self.store,client,DailyGateway,background=False)
        with patch('time.time',return_value=(f.INSTANT-dt.timedelta(days=1)).timestamp()):
            flow=manager.start(self.u1,self.a['id'],CONSENT_VERSION);manager.advance(flow['id'])
            self.assertEqual(manager.get(self.u1,flow['id'])['status'],'completed')
        manager.close()

    def run_day(self,offset,*,mfa=False):
        instant=f.INSTANT+dt.timedelta(days=offset)
        with ExitStack() as stack:
            stack.enter_context(patch('time.time',return_value=instant.timestamp()))
            stack.enter_context(patch('moonuestc.web_store.now',return_value=instant))
            stack.enter_context(patch('moonuestc.web_service.now',return_value=instant))
            store=WebStore(self.root,FAST_HASHER);store.execution_window=('21:06','23:24');store.wechat_enabled=True
            client=DailyClient('day-'+str(offset));manager=WechatManager(store,client,DailyGateway,background=False)
            transport=DailyTransport(instant,self.a['student_id']);transport.mfa=mfa
            worker=WebWorker(store,runner=lambda a,m,s,d,**kw:run_account(a,m,s,d,clock=lambda:instant,sleep=lambda _:None,**kw))
            worker.wechat_manager=manager
            stack.enter_context(patch('moonuestc.web_service.EncryptedTransport',return_value=transport))
            browser=stack.enter_context(patch('moonuestc.assisted_auth.BrowserBridge.call',side_effect=AssertionError('Daily task opened a browser')))
            try:
                worker.schedule_once();worker.schedule_once();ran=worker.run_one();worker.schedule_once()
                with store.db() as db:
                    jobs=db.execute("SELECT * FROM web_jobs WHERE business_date=? AND source='schedule'",(instant.date().isoformat(),)).fetchall()
                    account=store._payload(store._row(db,self.u1,self.a['id']))
                browser.assert_not_called()
                return client,transport,ran,jobs,account
            finally:worker.stop()

    def test_one_scan_drives_three_days_with_expired_tokens_cookies_and_new_workers(self):
        tickets=[];previous='private-refresh-token'
        for offset in range(3):
            client,transport,ran,jobs,account=self.run_day(offset)
            self.assertTrue(ran);self.assertEqual(len(jobs),1)
            self.assertEqual(jobs[0]['state'],'done');self.assertIn('"confirmed"',jobs[0]['result'])
            self.assertEqual(client.refresh_inputs,[previous]);previous='synthetic-refresh-day-'+str(offset)
            self.assertEqual(account['wechat_authorization']['credentials']['refreshtoken'],previous)
            self.assertNotIn('start',client.calls);self.assertNotIn('exchange',client.calls)
            self.assertEqual(transport.post_count,1)
            self.assertEqual([stage for _,stage in transport.calls].count('cas_submit'),1)
            tickets.extend(transport.tickets)
        self.assertEqual(len(set(tickets)),3)

    def test_school_mfa_stops_future_automatic_attempts_without_revoking_wechat(self):
        self.run_day(0)
        _,transport,ran,jobs,account=self.run_day(1,mfa=True)
        self.assertTrue(ran);self.assertEqual(transport.post_count,0)
        self.assertIn('need_manual_mfa',jobs[0]['result'])
        self.assertEqual(account['wechat_authorization']['status'],'ready')
        client,transport,ran,jobs,_=self.run_day(2)
        self.assertFalse(ran);self.assertEqual(jobs,[]);self.assertEqual(transport.calls,[])
        self.assertEqual(client.calls,[])

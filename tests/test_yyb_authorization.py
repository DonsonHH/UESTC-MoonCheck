"""Account-bound OAuth/ticket regression tests; all network boundaries are fake."""
import copy
import json
import time
import unittest
import threading
from types import SimpleNamespace
from unittest.mock import patch

from dashboard_helpers import WebCase,ORIGIN,FAST_HASHER,USER_PASS
import test_workflows as fixtures
from moonuestc.errors import ToolError
from moonuestc.web_errors import WebError
from moonuestc.web_app import create_app
from moonuestc.wechat_authorization import (
    APP_ID, CONSENT_VERSION, WechatManager, OperationAuthorization,
    authorization_eligible, authorization_summary,
)


class FakeClient:
    def __init__(self):self.calls=[];self.fail_code=False
    def call(self,operation,**values):
        self.calls.append(operation)
        if operation=='start':return {'qr':'private-scan-reference','image':'aW1hZ2U='}
        if operation=='poll':return {'status':'authorized'}
        if operation=='exchange':return {'openid':'private-openid','accesstoken':'private-access-token','refreshtoken':'private-refresh-token','expires_at':time.time()+7200,'logintype':'WX'}
        if operation=='refresh':return {**values['credentials'],'accesstoken':'rotated-secret','expires_at':time.time()+7200}
        if operation=='code':
            if self.fail_code:raise ToolError('wechat_code_unavailable','wechat_authorization')
            return {'code':'private-one-use-code'}
        return {'ok':True}
    def close(self):pass


class FakeGateway:
    student=fixtures.ACCOUNT['student_id']
    ticket_failure=False
    calls=[]
    def __init__(self,account):self.account=account
    def bind(self,code):
        self.calls.append('bind')
        return {'id':'school-user-1','username':self.student,'fullName':'合成同学'}
    def ticket(self,code):
        self.calls.append('ticket')
        if self.ticket_failure:raise ToolError('wechat_ticket_rejected','wechat_ticket',46002)
        return {'ticket':'T'*43,'expiresAt':str(int((time.time()+1800)*1000))}
    def close(self):pass


class Authorization(WebCase):
    def setUp(self):
        super().setUp()
        self.a=self.add_account(1)
        self.client=FakeClient()
        FakeGateway.student=fixtures.ACCOUNT['student_id'];FakeGateway.ticket_failure=False;FakeGateway.calls=[]
        self.manager=WechatManager(self.store,client=self.client,gateway_factory=FakeGateway,background=False)
    def tearDown(self):self.manager.close();super().tearDown()
    def grant(self):
        flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION)
        self.manager.advance(flow['id'])
        self.assertEqual(self.manager.get(self.u1,flow['id'])['status'],'completed')
        with self.store.db() as db:
            row=self.store._row(db,self.u1,self.a['id']);return self.store._payload(row)
    def test_scan_requires_explicit_processing_consent(self):
        with self.assertRaises(WebError):self.manager.start(self.u1,self.a['id'],'old-notice')
        self.assertEqual(self.client.calls,[])
    def test_scan_and_results_are_owner_scoped_even_for_admin(self):
        flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION)
        for actor in (self.u2,self.admin):
            with self.assertRaises(WebError):self.manager.get(actor,flow['id'])
            with self.assertRaises(WebError):self.manager.start(actor,self.a['id'],CONSENT_VERSION)
    def test_wrong_school_identity_never_saves_credentials(self):
        FakeGateway.student='202399999999'
        flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION);self.manager.advance(flow['id'])
        self.assertEqual(self.manager.get(self.u1,flow['id'])['status'],'failed')
        with self.store.db() as db:
            self.assertNotIn('wechat_authorization',self.store._payload(self.store._row(db,self.u1,self.a['id'])))
    def test_cancelled_scan_does_not_exchange_or_persist(self):
        flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION)
        self.manager.cancel(self.u1,flow['id']);self.manager.advance(flow['id'])
        self.assertNotIn('exchange',self.client.calls)
    def test_closed_site_session_cannot_commit_a_grant(self):
        alive=[True]
        flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION,session_valid=lambda:alive[0])
        alive[0]=False;self.manager.advance(flow['id'])
        self.assertNotEqual(self.manager.get(self.u1,flow['id'])['status'],'completed')
        self.assertNotIn('exchange',self.client.calls)
    def test_authorization_is_encrypted_and_public_summary_has_no_secrets(self):
        payload=self.grant()
        self.assertTrue(authorization_eligible(payload))
        self.assertEqual(payload['wechat_authorization']['app_id'],APP_ID)
        with self.store.db() as db:encrypted=db.execute('SELECT payload FROM web_accounts WHERE id=?',(self.a['id'],)).fetchone()[0]
        self.assertNotIn(b'private-access-token',encrypted)
        public=json.dumps(authorization_summary(payload))
        for secret in ('private-openid','private-access-token','private-refresh-token','private-one-use-code','T'*43):self.assertNotIn(secret,public)
    def test_ticket_and_code_never_persist_in_account(self):
        payload=self.grant();serialized=json.dumps(payload)
        self.assertNotIn('private-one-use-code',serialized);self.assertNotIn('T'*43,serialized)
        self.assertEqual(FakeGateway.calls,['bind','ticket'])
    def test_refresh_is_saved_before_subsequent_code_failure(self):
        payload=self.grant();meta=payload['wechat_authorization'];meta['credentials']['expires_at']=0
        writes=[]
        authorization=OperationAuthorization(payload,self.client,lambda value:writes.append(copy.deepcopy(value)),FakeGateway)
        self.client.fail_code=True
        with self.assertRaises(ToolError):authorization.prepare()
        self.assertEqual(writes[0]['credentials']['accesstoken'],'rotated-secret')
    def test_tampered_app_or_identity_is_not_eligible(self):
        payload=self.grant()
        for key,value in (('app_id','another-app'),('student_id','another-student'),('consent_version','old')):
            altered=copy.deepcopy(payload);altered['wechat_authorization'][key]=value
            self.assertFalse(authorization_eligible(altered))
    def test_revoke_preserves_plan_and_other_accounts(self):
        self.grant();before=self.store.account(self.u1,self.a['id'])
        self.manager.revoke(self.u1,self.a['id'])
        after=self.store.account(self.u1,self.a['id'])
        for key in ('student_id','owner_id','run_at','automatic','location'):self.assertEqual(before[key],after[key])
        with self.store.db() as db:self.assertNotIn('wechat_authorization',self.store._payload(self.store._row(db,self.u1,self.a['id'])))
    def test_revoke_cancels_a_pending_reauthorization_and_prevents_rebinding(self):
        self.grant()
        flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION)
        self.manager.revoke(self.u1,self.a['id'])
        self.manager.advance(flow['id'])
        self.assertEqual(self.manager.get(self.u1,flow['id'])['status'],'cancelled')
        with self.store.db() as db:self.assertNotIn('wechat_authorization',self.store._payload(self.store._row(db,self.u1,self.a['id'])))
    def test_initial_authorization_requires_a_refreshable_grant(self):
        original=self.client.call
        def missing_refresh(operation,**values):
            result=original(operation,**values)
            return {**result,'refreshtoken':''} if operation=='exchange' else result
        with patch.object(self.client,'call',side_effect=missing_refresh):
            flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION)
            self.manager.advance(flow['id'])
        self.assertEqual(self.manager.get(self.u1,flow['id'])['status'],'failed')
        with self.store.db() as db:self.assertNotIn('wechat_authorization',self.store._payload(self.store._row(db,self.u1,self.a['id'])))
    def test_a_scan_cannot_overwrite_an_authorization_changed_after_it_started(self):
        self.grant();flow=self.manager.start(self.u1,self.a['id'],CONSENT_VERSION)
        with self.store.db(True) as db:
            row=self.store._row(db,self.u1,self.a['id']);payload=self.store._payload(row)
            payload['wechat_authorization']['id']='b'*32
            db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(payload,'account:'+self.a['id']),self.a['id']))
        self.manager.advance(flow['id'])
        self.assertEqual(self.manager.get(self.u1,flow['id'])['error'],'wechat_authorization_changed')
        with self.store.db() as db:self.assertEqual(self.store._payload(self.store._row(db,self.u1,self.a['id']))['wechat_authorization']['id'],'b'*32)
    def test_deleted_account_drops_in_memory_native_keys_and_identity_locks(self):
        self.grant()
        self.client.codes=SimpleNamespace(lock=threading.RLock(),sessions={'private-openid':{'expires':time.monotonic()+1000}},account_locks={'private-openid':threading.Lock()})
        self.store.delete_account(self.u1,self.a['id'])
        self.manager.prune(force=True)
        self.assertEqual(self.client.codes.sessions,{})
        self.assertEqual(self.client.codes.account_locks,{})


class AuthorizationApi(WebCase):
    def setUp(self):
        super().setUp()
        self.auth=FakeClient()
        FakeGateway.student=fixtures.ACCOUNT['student_id'];FakeGateway.ticket_failure=False
        self.app=create_app(self.root,ORIGIN,hasher=FAST_HASHER,wechat_client=self.auth,
                            wechat_gateway_factory=FakeGateway,wechat_background=False)
        self.store=self.app.extensions['moon_store'];self.worker=self.app.extensions['moon_worker']
        self.manager=self.app.extensions['moon_wechat']
        self.c1,self.t1=self.login_client('alice',USER_PASS);self.c2,self.t2=self.login_client('bob',USER_PASS)
        self.a=self.add_account(1)
    def start(self):
        r=self.req(self.c1,self.t1,'/api/accounts/'+self.a['id']+'/wechat/scans','POST',{'consent_version':CONSENT_VERSION})
        self.assertEqual(r.status_code,201,r.get_json());return r.get_json()['scan']
    def test_csrf_and_owner_checks_precede_auth_network(self):
        url='/api/accounts/'+self.a['id']+'/wechat/scans'
        self.assertEqual(self.req(self.c1,'invalid',url,'POST',{'consent_version':CONSENT_VERSION}).status_code,403)
        self.assertEqual(self.req(self.c2,self.t2,url,'POST',{'consent_version':CONSENT_VERSION}).status_code,404)
        self.assertEqual(self.auth.calls,[])
    def test_authorization_deep_link_can_be_reloaded(self):
        self.app.config['MOON_PORTAL_ENABLED']=True
        response=self.c1.get('/app/authorization',base_url=ORIGIN)
        self.assertEqual(response.status_code,200)
        self.assertIn('text/html',response.content_type)
        response.close()
    def test_client_cannot_supply_credentials_or_student_identity(self):
        r=self.req(self.c1,self.t1,'/api/accounts/'+self.a['id']+'/wechat/scans','POST',{'consent_version':CONSENT_VERSION,'credentials':{'openid':'attacker'}})
        self.assertEqual(r.status_code,400);self.assertEqual(self.auth.calls,[])
    def test_logout_invalidates_pending_scan_without_persisting_grant(self):
        flow=self.start();self.req(self.c1,self.t1,'/api/logout','POST',{})
        self.manager.advance(flow['id'])
        self.assertNotIn('exchange',self.auth.calls)
        with self.store.db() as db:self.assertNotIn('wechat_authorization',self.store._payload(self.store._row(db,self.u1,self.a['id'])))
    def test_completed_authorization_survives_site_logout_without_another_scan(self):
        flow=self.start();self.manager.advance(flow['id'])
        self.req(self.c1,self.t1,'/api/logout','POST',{})
        with self.store.db() as db:payload=self.store._payload(self.store._row(db,self.u1,self.a['id']))
        self.assertTrue(authorization_eligible(payload));self.auth.calls.clear()
        authorization=self.manager.for_account(payload)
        try:self.assertEqual(authorization.prepare()['username'],payload['student_id'])
        finally:authorization.close()
        self.assertNotIn('start',self.auth.calls);self.assertNotIn('exchange',self.auth.calls)
    def test_public_account_only_returns_redacted_authorization_status(self):
        flow=self.start();self.manager.advance(flow['id'])
        r=self.req(self.c1,self.t1,'/api/accounts/'+self.a['id'])
        self.assertEqual(r.status_code,200)
        account=r.get_json()['account'];self.assertTrue(account['wechat_authorization']['eligible'])
        self.assertFalse(account['school_checkin_required'])
        for secret in ('private-openid','private-access-token','private-refresh-token','T'*43):self.assertNotIn(secret,r.get_data(as_text=True))
        self.assertEqual(self.req(self.c2,self.t2,'/api/wechat/scans/'+flow['id']).status_code,404)


if __name__=='__main__':unittest.main()

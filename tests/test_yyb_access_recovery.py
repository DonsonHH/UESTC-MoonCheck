"""Explicitly rejected access tokens can expire before their cached metadata."""
import copy
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from moonuestc.errors import ToolError
from moonuestc.yyb.auth import AuthClient,AuthError
from moonuestc.wechat_authorization import APP_ID,CONSENT_VERSION,OperationAuthorization,authorization_eligible
from test_yyb_authorization import FakeClient,FakeGateway


class Gateway(FakeGateway):
    def bind(self,code):return {'id':'synthetic-school-user','username':self.account['student_id'],'fullName':'合成同学'}


class EarlyClient(FakeClient):
    def __init__(self,rejections=1,refresh_error=None,code_error=None):
        super().__init__();self.rejections=rejections;self.refresh_error=refresh_error;self.code_error=code_error
    def call(self,operation,**values):
        if operation=='code' and self.code_error:
            self.calls.append(operation);raise self.code_error
        if operation=='code' and self.rejections:
            self.calls.append(operation);self.rejections-=1
            error=AuthError('login_buffer_failed');error.access_invalid=True
            raise error
        if operation=='refresh' and self.refresh_error:
            self.calls.append(operation);raise self.refresh_error
        return super().call(operation,**values)


class AccessRecovery(unittest.TestCase):
    def operation(self,client,gateway=Gateway):
        credentials=client.call('exchange');client.calls.clear()
        account={'id':'synthetic-account','student_id':'202300000001','user_agent':'Synthetic browser',
            'wechat_authorization':{'id':'a'*32,'app_id':APP_ID,'student_id':'202300000001',
                'school_user_id':'synthetic-school-user','verified_at':1,'consent_version':CONSENT_VERSION,
                'status':'ready','credentials':credentials}}
        self.writes=[]
        operation=OperationAuthorization(account,client,lambda value:self.writes.append(copy.deepcopy(value)),gateway)
        self.addCleanup(operation.close)
        return operation

    def test_early_rejection_refreshes_once_rebuilds_session_and_obtains_ticket(self):
        client=EarlyClient();operation=self.operation(client)
        self.assertGreater(operation.meta['credentials']['expires_at'],time.time()+60)
        operation.prepare();operation.ticket()
        self.assertEqual(client.calls.count('refresh'),1);self.assertEqual(client.calls.count('forget'),1)
        self.assertEqual(client.calls.count('code'),3)
        self.assertEqual(self.writes[0]['credentials']['accesstoken'],'rotated-secret')

    def test_repeated_explicit_rejection_stops_after_one_refresh_and_exposes_reconnect(self):
        client=EarlyClient(rejections=9);operation=self.operation(client)
        with self.assertRaises(ToolError) as raised:operation.prepare()
        self.assertEqual(raised.exception.reason,'wechat_access_token_invalid')
        self.assertEqual(client.calls.count('refresh'),1);self.assertEqual(client.calls.count('code'),2)
        self.assertEqual(self.writes[-1]['status'],'access_rejected')
        self.assertFalse(authorization_eligible(operation.account))

    def test_refresh_network_failure_keeps_the_grant_retryable(self):
        client=EarlyClient(refresh_error=AuthError('network_unavailable'));operation=self.operation(client)
        with self.assertRaises(ToolError) as raised:operation.prepare()
        self.assertEqual(raised.exception.reason,'wechat_network_unavailable')
        self.assertEqual(client.calls.count('refresh'),1);self.assertEqual(self.writes,[])
        self.assertTrue(authorization_eligible(operation.account))

    def test_unrelated_network_failure_does_not_force_refresh(self):
        client=EarlyClient(code_error=AuthError('network_unavailable'));operation=self.operation(client)
        with self.assertRaises(ToolError):operation.prepare()
        self.assertNotIn('refresh',client.calls);self.assertEqual(self.writes,[])

    def test_rotated_credentials_survive_a_later_school_failure(self):
        class FailedGateway(Gateway):
            def bind(self,code):raise ToolError('wechat_school_response_invalid','wechat_identity')
        client=EarlyClient();operation=self.operation(client,FailedGateway)
        with self.assertRaises(ToolError) as raised:operation.prepare()
        self.assertEqual(raised.exception.reason,'wechat_school_response_invalid')
        self.assertEqual(self.writes[0]['credentials']['accesstoken'],'rotated-secret')

    def test_only_login_buffer_access_rejection_signals_early_refresh(self):
        client=object.__new__(AuthClient)
        response=SimpleNamespace(json=lambda:{'code':10001,'message':'access_token is invalid or not latest'})
        with patch.object(client,'http',return_value=response):
            for operation,expected in [('pcyyb_get_wx_login_buffer_auth',True),('pcyyb_refresh_token_auth',False)]:
                with self.assertRaises(AuthError) as raised:client.signed(operation,{})
                self.assertEqual(getattr(raised.exception,'access_invalid',False),expected)
                self.assertFalse(raised.exception.definitive)

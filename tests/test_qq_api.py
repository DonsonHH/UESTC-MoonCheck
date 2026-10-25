"""Official QQ protocol boundaries without making any network requests."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from moonuestc.qq_bot import QQClient,QQError,verified_callback,signing_key,event_context


class Session:
    def __init__(self):self.calls=[];self.fail=False;self.bad_token=False;self.no_id=False;self.closed=False
    def request(self,method,url,**values):
        self.calls.append((method,url,values))
        if url.endswith('/app/getAppAccessToken'):
            result={'code':100016,'message':'synthetic secret must not be logged'} if self.bad_token else {'access_token':'synthetic-runtime-token','expires_in':'7200'}
        elif self.fail:result={'code':40034105,'message':'synthetic failure'}
        elif self.no_id:result={'code':0}
        else:result={'id':'synthetic-message-id'}
        raw=json.dumps(result).encode();return SimpleNamespace(status_code=200,content=raw,json=lambda:result)
    def close(self):self.closed=True


class QQProtocol(unittest.TestCase):
    def test_official_dotted_message_ids_are_opaque_metadata_not_target_ids(self):
        message='ROBOT1.0_SyntheticMessageWithPadding=='
        event={'t':'GROUP_AT_MESSAGE_CREATE','d':{'id':message,'group_openid':'synthetic-group','author':{'member_openid':'synthetic-member'},'content':' /绑定班级 ABCDEF0123456789 '}}
        context=event_context(event)
        self.assertIsNotNone(context,'Official ROBOT1.0 message IDs must not be rejected by the OpenID validator')
        self.assertEqual(context['msg_id'],message)
        client=self.client();client.send('group','synthetic-group','合成测试',msg_id=message)
        self.assertEqual(self.session.calls[-1][2]['json']['msg_id'],message)
    def client(self):
        self.session=Session();client=QQClient({'app_id':'synthetic-app','app_secret':'synthetic-client-secret'},session=self.session)
        self.addCleanup(client.close);return client
    def test_token_is_server_only_cached_and_no_redirect_is_allowed(self):
        client=self.client();client.send('group','synthetic-group','合成测试');client.send('user','synthetic-user','合成测试')
        self.assertEqual(sum(url.endswith('/app/getAppAccessToken') for _,url,_ in self.session.calls),1)
        for method,url,values in self.session.calls:
            self.assertTrue(url.startswith('https://api.bot.qq.com/'));self.assertFalse(values['allow_redirects'])
        self.assertNotIn('msg_id',self.session.calls[-1][2]['json'])
    def test_http_200_business_rejection_is_not_delivery_success(self):
        client=self.client();self.session.fail=True
        with self.assertRaises(QQError) as raised:client.send('group','synthetic-group','合成测试')
        self.assertEqual(raised.exception.code,40034105)
    def test_token_error_is_not_accepted_as_identity(self):
        client=self.client();self.session.bad_token=True
        with self.assertRaises(QQError) as raised:client.identity()
        self.assertEqual(raised.exception.code,100016)
        self.assertNotIn('secret',str(raised.exception))
    def test_response_without_message_id_is_unconfirmed(self):
        client=self.client();self.session.no_id=True
        with self.assertRaises(QQError) as raised:client.send('group','synthetic-group','合成测试')
        self.assertEqual(raised.exception.code,'qq_delivery_unconfirmed')
    def test_target_cannot_inject_another_endpoint(self):
        client=self.client()
        for target in ('../users','x?openid=evil','<@all>',''):
            with self.assertRaises(QQError):client.send('group',target,'合成测试')
        self.assertEqual(self.session.calls,[])
    def test_callback_event_signature_and_challenge_are_distinct(self):
        config={'app_id':'synthetic-app','app_secret':'synthetic-client-secret'};stamp='1792970400'
        value={'op':0,'t':'C2C_MESSAGE_CREATE','d':{}};raw=json.dumps(value).encode()
        headers={'X-Bot-Appid':config['app_id'],'X-Signature-Timestamp':stamp,
            'X-Signature-Ed25519':signing_key(config['app_secret']).sign(stamp.encode()+raw).hex()}
        ack,event=verified_callback(config,headers,raw,clock=lambda:int(stamp))
        self.assertEqual(ack,{'op':12,'d':0});self.assertEqual(event,value)

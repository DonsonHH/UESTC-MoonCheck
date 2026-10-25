"""Official QQ HTTPS API and authenticated callbacks; no personal QQ session."""
import json
import re
import threading
import time

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .web_errors import WebError

API='https://api.bot.qq.com'


class QQError(Exception):
    def __init__(self,code='qq_unavailable',http=None):self.code=code;self.http=http;super().__init__(code)


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9_-]{6,160}',value):raise QQError('qq_invalid_identifier')
    return value


class QQClient:
    def __init__(self,config,session=None):
        self.config=config;self.session=session or requests.Session()
        if session is None:self.session.trust_env=False
        self.token=None;self.expires=0;self.lock=threading.RLock()
    def _request(self,method,path,*,body=None,headers=None):
        try:
            response=self.session.request(method,API+path,json=body,headers=headers or {},timeout=(5,12),allow_redirects=False)
            if len(response.content)>256*1024:raise QQError('qq_response_limit')
            value=response.json()
        except (requests.RequestException,ValueError):raise QQError('qq_network_error') from None
        if response.status_code!=200 or not isinstance(value,dict) or value.get('code',0)!=0:
            code=value.get('code') if isinstance(value,dict) and type(value.get('code')) is int else 'qq_response_invalid'
            raise QQError(code,response.status_code)
        return value
    def access_token(self):
        with self.lock:
            if self.token and time.monotonic()<self.expires:return self.token
            result=self._request('POST','/app/getAppAccessToken',body={'appId':self.config['app_id'],'clientSecret':self.config['app_secret']})
            token=result.get('access_token')
            try:ttl=int(result.get('expires_in'))
            except (ValueError,TypeError):raise QQError('qq_token_invalid') from None
            if not isinstance(token,str) or not token or not 60<=ttl<=86400:raise QQError('qq_token_invalid')
            self.token=token;self.expires=time.monotonic()+ttl-60;return token
    def call(self,method,path,body=None):
        return self._request(method,path,body=body,headers={'Authorization':'QQBot '+self.access_token()})
    def identity(self):
        result=self.call('GET','/users/@me')
        if not result.get('id'):raise QQError('qq_identity_invalid')
        return {'verified':True}
    def send(self,kind,target,text,*,msg_id=None):
        if kind not in ('group','user'):raise QQError('qq_invalid_target')
        identifier(target)
        if not isinstance(text,str) or not 1<=len(text)<=5000:raise QQError('qq_message_size')
        value={'msg_type':0,'content':text}
        if msg_id:value.update(msg_id=identifier(msg_id),msg_seq=1)
        result=self.call('POST','/v2/'+('groups' if kind=='group' else 'users')+'/'+target+'/messages',value)
        if not result.get('id'):raise QQError('qq_delivery_unconfirmed')
        return {'sent':True}
    def close(self):self.session.close()


def signing_key(secret):
    value=secret.encode('utf-8')
    if not value:raise ValueError('Missing QQ secret')
    while len(value)<32:value+=value
    return Ed25519PrivateKey.from_private_bytes(value[:32])


def verified_callback(config,headers,raw,*,clock=time.time):
    """The public nonce path is checked before this function is called."""
    if len(raw)>32768:raise WebError(413,'callback_too_large','回调内容过大。')
    if headers.get('X-Bot-Appid')!=config['app_id']:raise WebError(403,'qq_signature_invalid','回调校验失败。')
    try:value=json.loads(raw)
    except (ValueError,UnicodeError):raise WebError(400,'invalid_callback','回调格式不正确。') from None
    if not isinstance(value,dict):raise WebError(400,'invalid_callback','回调格式不正确。')
    key=signing_key(config['app_secret'])
    if value.get('op')==13:
        data=value.get('d') or {};plain=data.get('plain_token');stamp=data.get('event_ts')
        # Restrict validation to the documented alphanumeric nonce, never JSON:
        # this challenge cannot become an oracle for forging event signatures.
        if not isinstance(plain,str) or not re.fullmatch('[A-Za-z0-9]{1,128}',plain) or not isinstance(stamp,str) or not stamp.isdigit() or abs(clock()-int(stamp))>300:
            raise WebError(400,'invalid_challenge','回调验证参数不正确。')
        return {'plain_token':plain,'signature':key.sign((stamp+plain).encode()).hex()},None
    stamp=headers.get('X-Signature-Timestamp','');signature=headers.get('X-Signature-Ed25519','')
    try:
        if not stamp.isdigit() or abs(clock()-int(stamp))>300:raise ValueError()
        sig=bytes.fromhex(signature)
        if len(sig)!=64:raise ValueError()
        key.public_key().verify(sig,stamp.encode()+raw)
    except (ValueError,InvalidSignature):raise WebError(403,'qq_signature_invalid','回调校验失败。') from None
    return {'op':12,'d':0},value


def event_context(event):
    name=event.get('t');data=event.get('d') or {}
    if name not in ('GROUP_AT_MESSAGE_CREATE','GROUP_MESSAGE_CREATE','C2C_MESSAGE_CREATE'):return None
    try:
        author=data.get('author') or {};group=name!='C2C_MESSAGE_CREATE'
        sender=identifier(author.get('member_openid') if group else author.get('user_openid'))
        target=identifier(data.get('group_openid')) if group else sender
        message=identifier(data.get('id'));content=data.get('content','')
        if not isinstance(content,str) or len(content)>5000:return None
        content=re.sub(r'<@!?[A-Za-z0-9_-]+>','',content).strip().lstrip('/')
        return {'kind':'group' if group else 'user','target':target,'sender':sender,'msg_id':message,'content':content}
    except (QQError,AttributeError):return None


def group_message(day,pending,mapping):
    mapped=[mapping[r['student_id']] for r in pending if r['student_id'] in mapping]
    if not pending:return f'晚安成电 · {day} 23:10 检查：本班没有待签到记录。'
    mentions=' '.join('<qqbot-at-user id="'+identifier(member)+'" />' for member in mapped)
    return f'晚安成电 · {day} 23:10\n本班还有 {len(pending)} 人未签到，请在学校截止前处理。\n'+mentions+f'\n已绑定并提醒 {len(mapped)} 人，另有 {len(pending)-len(mapped)} 人尚未绑定 QQ。'

"""Owner-confirmed YYB grants and fresh school operation tickets.

OAuth grants are encrypted inside the existing account payload. Native session
keys, login codes, mini-program cookies and operation tickets remain in memory.
"""
import copy
import hashlib
import http.cookiejar
import re
import secrets
import ssl
import threading
import time
import urllib.request
from pathlib import Path

from .errors import ToolError
from .transport import Transport, NoRedirect
from .web_errors import WebError

APP_ID='wxaa78bf2905f01cee'
CONSENT_VERSION='2026-10-25-yyb-v1'
AUTHORIZATION_NOTICE={
    'version':CONSENT_VERSION,
    'title':'微信扫码授权',
    'text':'本功能通过应用宝授权通道获取学校小程序登录码。扫码页可能显示“应用宝”。服务器会加密保存授权标识、访问令牌和刷新令牌，用于每天申请学校打卡票据；不运行完整微信客户端，不读取聊天记录或通讯录。授权失效时需要本人重新扫码。授权过程不会提交签到。',
}


def authorization_eligible(account):
    meta=account.get('wechat_authorization') or {}
    credentials=meta.get('credentials') or {}
    return bool(isinstance(meta.get('id'),str) and re.fullmatch('[a-f0-9]{32}',meta['id'])
        and meta.get('app_id')==APP_ID and meta.get('student_id')==account.get('student_id')
        and meta.get('school_user_id') and meta.get('verified_at')
        and meta.get('consent_version')==CONSENT_VERSION and meta.get('status') in ('ready','retrying')
        and credentials.get('openid') and credentials.get('accesstoken')
        and isinstance(credentials.get('refreshtoken'),str) and credentials['refreshtoken'].strip())


def authorization_summary(account):
    meta=account.get('wechat_authorization') or {}
    return {'linked':bool(meta),'status':meta.get('status','not_authorized'),
            'eligible':authorization_eligible(account),
            'verified_at':meta.get('verified_at'),
            'access_expires_at':(meta.get('credentials') or {}).get('expires_at'),
            'last_error':meta.get('last_error')}


def identity(value):
    user=value.get('userData') if isinstance(value,dict) else None
    if not isinstance(user,dict) or any(not isinstance(user.get(k),str) or not user[k].strip() for k in ('id','username','fullName')):
        raise ToolError('wechat_identity_unavailable','wechat_identity')
    return {key:user[key] for key in ('id','username','fullName')}


class MemoryTransport(Transport):
    def __init__(self,user_agent):
        self.user_agent=user_agent;self.timeout=15;self.cookie_path=Path('/tmp/not-persisted')
        self.jar=http.cookiejar.CookieJar()
        self.opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def save(self):raise RuntimeError('Mini-program session persistence is forbidden')


class SchoolMiniGateway:
    def __init__(self,account):self.transport=MemoryTransport(account['user_agent'])
    def api(self,path,code=None):
        stage='wechat_ticket' if path=='checkin-ticket' else 'wechat_identity'
        r=self.transport.request('GET' if code is None else 'POST',
            'https://jzsz.uestc.edu.cn/platform-app/api/auth/'+path,
            stage=stage,payload=None if code is None else {'code':code,**({'sn':''} if path=='check-bind' else {})},
            headers={'platform':'mp-weixin','Accept':'application/json'})
        try:data=r.json(stage)
        except ToolError:raise ToolError('wechat_school_response_invalid',stage,http_status=r.status) from None
        if r.status!=200 or not isinstance(data,dict) or data.get('code')!=0 or data.get('ok') is False:
            code=data.get('code') if isinstance(data,dict) and type(data.get('code')) is int else None
            raise ToolError('wechat_ticket_rejected' if stage=='wechat_ticket' else 'wechat_binding_rejected',stage,code,http_status=r.status)
        return data.get('data')
    def bind(self,code):
        data=self.api('check-bind',code)
        if not isinstance(data,dict) or data.get('bind') is not True:raise ToolError('wechat_school_not_bound','wechat_identity')
        sid=data.get('sessionId')
        if not isinstance(sid,str) or not sid or any(ord(c)<=32 or ord(c)>=127 or c in '\";,\\' for c in sid):
            raise ToolError('wechat_school_response_invalid','wechat_identity')
        if not self.transport.has_session():
            self.transport.jar.set_cookie(http.cookiejar.Cookie(version=0,name='SESSION',value=sid,port=None,
                port_specified=False,domain='jzsz.uestc.edu.cn',domain_specified=False,domain_initial_dot=False,
                path='/',path_specified=True,secure=True,expires=None,discard=True,comment=None,comment_url=None,rest={'HttpOnly':None}))
        return identity(self.api('user-info'))
    def ticket(self,code):return self.api('checkin-ticket',code)
    def close(self):self.transport.jar.clear()


class OperationAuthorization:
    def __init__(self,account,client,save,gateway_factory=SchoolMiniGateway,*,bootstrap=False):
        self.account=account;self.client=client;self.save=save;self.gateway=gateway_factory(account)
        self.meta=copy.deepcopy(account.get('wechat_authorization') or {})
        self.user=None;self.bootstrap=bootstrap;self.access_refresh_attempted=False
    def _call(self,operation,**values):
        from .yyb.auth import AuthError
        try:return self.client.call(operation,**values)
        except AuthError as error:
            if error.definitive:
                self.meta.update(status='needs_rescan',last_error='wechat_authorization_expired')
                if not self.bootstrap:self.save(self.meta)
                raise ToolError('wechat_authorization_expired','wechat_authorization') from None
            if getattr(error,'access_invalid',False):
                raise ToolError('wechat_access_token_invalid','wechat_authorization') from None
            raise ToolError('wechat_'+error.code,'wechat_authorization') from None
    def code(self):
        for _ in range(2):
            try:
                result=self._call('code',credentials=self.meta['credentials'])
                break
            except ToolError as error:
                if error.reason!='wechat_access_token_invalid':raise
                if self.access_refresh_attempted:
                    self.meta.update(status='access_rejected',last_error='wechat_access_token_invalid')
                    self.account['wechat_authorization']=self.meta
                    if not self.bootstrap:self.save(self.meta)
                    raise
                self.access_refresh_attempted=True
                self._refresh_credentials(force=True)
                self._call('forget',credentials=self.meta['credentials'])
        code=result.get('code') if isinstance(result,dict) else None
        if not isinstance(code,str) or not code.strip() or len(code)>1024:
            raise ToolError('wechat_code_unavailable','wechat_authorization')
        return code
    def _refresh_credentials(self,*,force=False):
        credentials=self.meta.get('credentials') or {}
        if not credentials.get('openid') or not credentials.get('accesstoken'):
            raise ToolError('wechat_authorization_required','wechat_authorization')
        if force or credentials.get('expires_at',0)<=time.time()+60:
            if not credentials.get('refreshtoken'):raise ToolError('wechat_authorization_expired','wechat_authorization')
            rotated=self._call('refresh',credentials=credentials)
            if rotated.get('openid')!=credentials['openid'] or not rotated.get('accesstoken') or rotated.get('expires_at',0)<=time.time():
                raise ToolError('wechat_refresh_response_invalid','wechat_authorization')
            self.meta['credentials']=rotated;self.account['wechat_authorization']=self.meta
            self.save(self.meta)  # Preserve rotation even if later school/code calls fail.
    def prepare(self):
        if not self.bootstrap and not authorization_eligible(self.account):
            raise ToolError('wechat_authorization_required','wechat_authorization')
        self._refresh_credentials()
        self.user=self.gateway.bind(self.code())
        if self.user['username']!=self.account['student_id'] or self.meta.get('school_user_id') not in (None,self.user['id']):
            raise ToolError('wechat_identity_mismatch','wechat_identity')
        return self.user
    def check_business(self,school):
        if self.user is None:self.prepare()
        user=identity(school.api('/auth/user-info',stage='wechat_business_identity'))
        if user['id']!=self.user['id'] or user['username']!=self.user['username']:
            raise ToolError('wechat_identity_mismatch','wechat_identity')
    def ticket(self):
        if self.user is None:self.prepare()
        data=self.gateway.ticket(self.code())
        value=data.get('ticket') if isinstance(data,dict) else None
        try:
            raw=data.get('expiresAt')
            if isinstance(raw,bool):raise ValueError()
            expiry=float(raw)
            if expiry>10**11:expiry/=1000
        except (ValueError,TypeError,AttributeError):raise ToolError('wechat_ticket_response_invalid','wechat_ticket') from None
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',value) or not time.time()+10<expiry<time.time()+3600:
            raise ToolError('wechat_ticket_response_invalid','wechat_ticket')
        return value,expiry
    def reject(self):
        self.meta.update(status='school_rejected',last_error='wechat_ticket_rejected')
        self.save(self.meta)
    def close(self):self.gateway.close()


class WechatManager:
    def __init__(self,store,client=None,gateway_factory=SchoolMiniGateway,background=True):
        if client is None:
            from .yyb.auth import AuthClient
            client=AuthClient()
        self.store=store;self.client=client;self.gateway_factory=gateway_factory;self.background=background
        self.lock=threading.RLock();self.flows={};self.stopped=False;self.limits={};self.next_prune=0
    def _target(self,actor,account_id,db=None):
        if db is None:
            with self.store.db() as connection:return self._target(actor,account_id,connection)
        row=self.store._row(db,actor,account_id)
        if row['owner_id']!=actor['id']:raise WebError(403,'account_owner_required','请由账号本人完成微信授权。')
        if not row['owner_active'] or not row['enabled']:raise WebError(409,'account_disabled','账号已暂停或停用。')
        if self.store._busy(db,account_id):raise WebError(409,'account_busy','请等待当前任务结束后再更新授权。')
        return row,self.store._payload(row)
    def _live(self,flow):
        return not self.stopped and flow['status'] in ('pending','scanned','processing') and time.monotonic()<flow['deadline'] and flow['session_valid']()
    def start(self,actor,account_id,consent_version,*,session_valid=lambda:True,session_token=None):
        if consent_version!=CONSENT_VERSION:raise WebError(428,'wechat_consent_required','请先确认微信授权令牌的托管说明。')
        _,account=self._target(actor,account_id)
        with self.lock:
            stamp=time.monotonic();recent=[v for v in self.limits.get(actor['id'],[]) if stamp-v<300]
            if len(recent)>=5:raise WebError(429,'wechat_scan_cooldown','请稍后再获取二维码。',retry_after=60)
            self.limits[actor['id']]=recent+[stamp]
            for old in list(self.flows.values()):
                if old['owner']==actor['id'] and old['status'] in ('pending','scanned','processing'):
                    old.update(status='cancelled',image='')
                    if old.get('qr'):self.client.call('cancel',qr=old['qr'])
                if stamp>old['deadline']+120:self.flows.pop(old['id'],None)
            if sum(self._live(f) for f in self.flows.values())>=8:raise WebError(429,'wechat_scan_busy','当前授权人数较多，请稍后重试。',retry_after=20)
            ident=secrets.token_hex(24)
            flow={'id':ident,'owner':actor['id'],'actor':dict(actor),'account_id':account_id,'status':'pending',
                  'authorization_id':(account.get('wechat_authorization') or {}).get('id'),
                  'deadline':stamp+300,'session_valid':session_valid,'session_token':session_token,'image':'','error':None,'lock':threading.Lock()}
            self.flows[ident]=flow
        try:
            result=self.client.call('start')
            if not self._live(flow):
                self.client.call('cancel',qr=result['qr']);raise WebError(409,'wechat_scan_cancelled','本次扫码已取消。')
            flow.update(qr=result['qr'],image=result['image'])
        except Exception:
            with self.lock:self.flows.pop(ident,None)
            raise WebError(503,'wechat_scan_unavailable','二维码服务暂时不可用，请稍后重试。') from None
        if self.background:threading.Thread(target=self._poll,args=(ident,),daemon=True,name='wechat-owner-scan').start()
        return self.get(actor,ident)
    def get(self,actor,ident):
        with self.lock:
            flow=self.flows.get(ident)
            if not flow or flow['owner']!=actor['id']:raise WebError(404,'not_found','本次扫码不存在或已失效。')
            if flow['status'] in ('pending','scanned','processing') and not self._live(flow):flow.update(status='expired',image='')
            return {key:flow.get(key) for key in ('id','status','image','error')}
    def cancel(self,actor,ident):
        self.get(actor,ident)
        with self.lock:
            flow=self.flows[ident];flow.update(status='cancelled',image='')
        if flow.get('qr'):self.client.call('cancel',qr=flow['qr'])
    def _poll(self,ident):
        while not self.stopped:
            if self.advance(ident):return
            time.sleep(.5)
    def advance(self,ident):
        flow=self.flows.get(ident)
        if not flow:return True
        with flow['lock']:
            if not self._live(flow):
                if flow['status'] in ('pending','scanned','processing'):flow.update(status='expired',image='')
                if flow.get('qr'):
                    try:self.client.call('cancel',qr=flow['qr'])
                    except Exception:pass
                return True
            authorization=None;credentials=None
            try:
                result=self.client.call('poll',qr=flow['qr'])
                if result.get('status') in ('pending','scanned'):
                    flow['status']=result['status'];return False
                if result.get('status')!='authorized':raise ToolError('wechat_scan_expired','wechat_authorization')
                flow.update(status='processing',image='',deadline=time.monotonic()+120)
                if not self._live(flow):return True
                credentials=self.client.call('exchange',qr=flow['qr'])
                credentials={k:v for k,v in credentials.items() if k in ('openid','accesstoken','refreshtoken','expires_at','expires_in','logintype')}
                if not isinstance(credentials.get('refreshtoken'),str) or not credentials['refreshtoken'].strip():
                    raise ToolError('wechat_refresh_unavailable','wechat_authorization')
                _,account=self._target(flow['actor'],flow['account_id'])
                meta={'id':secrets.token_hex(16),'app_id':APP_ID,'student_id':account['student_id'],
                      'consent_version':CONSENT_VERSION,'consent_at':time.time(),'credentials':credentials,'status':'ready'}
                candidate={**account,'wechat_authorization':meta}
                authorization=OperationAuthorization(candidate,self.client,lambda updated:meta.update(updated),self.gateway_factory,bootstrap=True)
                user=authorization.prepare();authorization.ticket()
                meta.update(school_user_id=user['id'],verified_at=time.time(),status='ready')
                with self.store.db(True) as db:
                    row,current=self._target(flow['actor'],flow['account_id'],db)
                    if not self._live(flow):raise WebError(409,'wechat_scan_cancelled','本次扫码已取消。')
                    if current['student_id']!=user['username']:raise ToolError('wechat_identity_mismatch','wechat_identity')
                    if (current.get('wechat_authorization') or {}).get('id')!=flow['authorization_id']:
                        raise ToolError('wechat_authorization_changed','wechat_authorization')
                    if flow['session_token']:
                        digest=hashlib.sha256(flow['session_token'].encode()).hexdigest()
                        session=db.execute('SELECT user_id,expires_at,last_seen FROM web_sessions WHERE token_hash=?',(digest,)).fetchone()
                        if not session or session['user_id']!=flow['owner'] or session['expires_at']<time.time() or session['last_seen']<time.time()-1800:
                            raise WebError(401,'login_required','登录已失效，请重新登录。')
                    current['wechat_authorization']=meta
                    db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(current,'account:'+row['id']),row['id']))
                    self.store._audit(db,flow['actor'],'wechat_authorized',row['id'])
                flow.update(status='completed',image='')
            except (ToolError,WebError) as error:
                if flow['status'] not in ('cancelled','expired'):flow.update(status='failed',image='',error=getattr(error,'reason',getattr(error,'code','wechat_authorization_failed')))
            except Exception:
                if flow['status'] not in ('cancelled','expired'):flow.update(status='failed',image='',error='wechat_authorization_failed')
            finally:
                if authorization:authorization.close()
                if flow['status'] not in ('pending','scanned'):
                    if credentials and flow['status']!='completed':
                        try:self.client.call('forget',credentials=credentials)
                        except Exception:pass
                    try:self.client.call('cancel',qr=flow['qr'])
                    except Exception:pass
            return True
    def for_account(self,account):
        if not authorization_eligible(account):return None
        expected=account['wechat_authorization']['id'];account_id=account['id']
        def save(meta):
            with self.store.db(True) as db:
                row=db.execute('SELECT * FROM web_accounts WHERE id=?',(account_id,)).fetchone()
                if not row:raise ToolError('wechat_authorization_changed','wechat_authorization')
                current=self.store._payload(row)
                if (current.get('wechat_authorization') or {}).get('id')!=expected:raise ToolError('wechat_authorization_changed','wechat_authorization')
                current['wechat_authorization']=copy.deepcopy(meta)
                db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(current,'account:'+account_id),account_id))
        return OperationAuthorization(account,self.client,save,self.gateway_factory)
    def revoke(self,actor,account_id):
        scans=[]
        with self.store.db(True) as db:
            row,payload=self._target(actor,account_id,db)
            with self.lock:
                for flow in self.flows.values():
                    if flow['owner']==actor['id'] and flow['account_id']==account_id and flow['status'] in ('pending','scanned','processing'):
                        flow.update(status='cancelled',image='')
                        if flow.get('qr'):scans.append(flow['qr'])
            meta=payload.pop('wechat_authorization',None)
            db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(payload,'account:'+account_id),account_id))
            self.store._audit(db,actor,'wechat_revoked',account_id)
        for qr in scans:
            try:self.client.call('cancel',qr=qr)
            except Exception:pass
        if meta:
            try:self.client.call('forget',credentials=meta['credentials'])
            except Exception:pass
    def prune(self,*,force=False):
        stamp=time.monotonic()
        if not force and stamp<self.next_prune:return
        self.next_prune=stamp+30
        with self.lock:
            for ident,flow in list(self.flows.items()):
                if stamp>flow['deadline']:
                    if flow['status'] in ('pending','scanned','processing'):
                        flow.update(status='expired',image='')
                        if flow.get('qr'):
                            try:self.client.call('cancel',qr=flow['qr'])
                            except Exception:pass
                    flow['session_token']=None;flow['session_valid']=lambda:False
                    if stamp>flow['deadline']+120:self.flows.pop(ident,None)
            self.limits={key:[v for v in values if stamp-v<300] for key,values in self.limits.items() if any(stamp-v<300 for v in values)}
        codes=getattr(self.client,'codes',None)
        if codes is None:return
        with self.store.db() as db:
            rows=db.execute('SELECT a.* FROM web_accounts a JOIN web_users u ON u.id=a.owner_id WHERE a.enabled=1 AND u.active=1').fetchall()
        active=set()
        for row in rows:
            payload=self.store._payload(row)
            if authorization_eligible(payload):active.add(payload['wechat_authorization']['credentials']['openid'])
        with codes.lock:
            for openid,value in list(codes.sessions.items()):
                if openid not in active or value.get('expires',0)<=stamp:codes.sessions.pop(openid,None)
            for openid,lock in list(codes.account_locks.items()):
                if openid not in active and not lock.locked():codes.account_locks.pop(openid,None)
    def close(self):
        self.stopped=True
        with self.lock:
            for flow in self.flows.values():
                if flow['status'] in ('pending','scanned','processing'):flow.update(status='cancelled',image='')
        self.client.close()

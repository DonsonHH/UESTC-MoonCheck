"""School-verified student identity; school access is a replaceable external boundary."""
import hashlib
import json
import re
import secrets
import sqlite3
import tempfile
import time
import threading
import uuid
import os
import math
import datetime as dt
from pathlib import Path

from .client import School
from .errors import ToolError
from .policy import validate_config,SHANGHAI
from .runner import cookie_path
from .runner import account_key
from .state import State,InteractiveAuthCooldown
from .transport import Transport
from .web_errors import WebError
from .web_store import public_user
from .scheduling import reserve_slot
from .notice import VERSION as NOTICE_VERSION


def verify_school(account):
    # A new empty jar forces password authentication. Never reuse an old school
    # session to prove a supplied password, and never persist a plaintext Cookie.
    with tempfile.TemporaryDirectory(prefix='moon-school-auth-') as directory:
        transport=Transport(account['user_agent'],Path(directory)/'memory-only.lwp',timeout=15)
        request=transport.request
        deadline=time.monotonic()+45
        def bounded_request(*args,**kwargs):
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ToolError('timeout','school_verification')
            transport.timeout=min(15,remaining)
            return request(*args,**kwargs)
        transport.request=bounded_request
        School(transport,account,budget=lambda:None,emit=lambda *args,**kwargs:None).connect()
        cookies=[]
        for cookie in transport.jar:
            if cookie.is_expired():continue
            value={key:getattr(cookie,key) for key in (
                'version','name','value','port','port_specified','domain','domain_specified',
                'domain_initial_dot','path','path_specified','secure','expires','discard','comment','comment_url')}
            value.update(rest=dict(cookie._rest),rfc2109=cookie.rfc2109)
            cookies.append(value)
        return cookies


def local_auth_error(error):
    if isinstance(error,InteractiveAuthCooldown):
        minutes=(error.retry_after+59)//60
        return WebError(429,'interactive_auth_cooldown',f'本站接入保护：5 分钟内已尝试 10 次，请约 {minutes} 分钟后重试。',retry_after=error.retry_after)
    return WebError(409,'onboarding_expired','本次验证已失效，请重新登录。')

class PortalAuth:
    VERIFIED_TTL=86400

    def __init__(self,store,verifier=None):
        self.store=store
        self.verifier=verifier or verify_school
        self.school_slots=threading.BoundedSemaphore(2)
        self.require_notice=os.environ.get('MOON_REQUIRE_CONSENT','0')=='1'
        self.student_prefix=os.environ.get('MOON_STUDENT_ID_PREFIX','').strip()
        if self.student_prefix and not re.fullmatch('[0-9]{1,18}',self.student_prefix):raise ValueError('Invalid student prefix configuration')

    def default_allowed(self,student):
        return not self.student_prefix or bool(re.fullmatch(re.escape(self.student_prefix)+'[0-9]{2}',student))

    def check_notice(self,version):
        if self.require_notice and version!=NOTICE_VERSION:raise WebError(428,'privacy_consent_required','请先阅读并同意个人信息与登录凭据托管说明。')

    def require_allowed(self,student,db=None):
        if self.default_allowed(student):return
        digest=self.store.vault.digest('portal_access',student)
        if db is None:
            with self.store.db() as connection:allowed=connection.execute('SELECT 1 FROM portal_access_grants WHERE student_digest=?',(digest,)).fetchone()
        else:allowed=db.execute('SELECT 1 FROM portal_access_grants WHERE student_digest=?',(digest,)).fetchone()
        if not allowed:raise WebError(403,'student_not_allowed',f'目前开放 {self.student_prefix}** 学号段及管理员额外授权的学号，请联系管理员。')

    def _authorization(self,row):
        return {'id':row['student_digest'],'student_id':self.store.vault.open(row['payload'],'portal_access:'+row['student_digest'])['student_id'],'created_at':row['created_at']}

    def authorizations(self,actor):
        if actor['role']!='admin':raise WebError(403,'admin_required','需要管理员权限。')
        with self.store.db() as db:rows=db.execute('SELECT * FROM portal_access_grants ORDER BY created_at DESC').fetchall()
        return {'student_prefix':self.student_prefix,'authorizations':[self._authorization(row) for row in rows]}

    def authorize(self,actor,data):
        if actor['role']!='admin':raise WebError(403,'admin_required','需要管理员权限。')
        if not isinstance(data,dict) or set(data)!={'student_id'} or not isinstance(data['student_id'],str) or not re.fullmatch('[0-9]{8,20}',data['student_id']):
            raise WebError(400,'invalid_student','请输入 8–20 位数字学号。')
        student=data['student_id']
        if self.default_allowed(student):raise WebError(400,'already_allowed','此学号已在默认开放范围，无需额外授权。')
        digest=self.store.vault.digest('portal_access',student)
        with self.store.db(True) as db:
            row=db.execute('SELECT * FROM portal_access_grants WHERE student_digest=?',(digest,)).fetchone()
            if not row:
                db.execute('INSERT INTO portal_access_grants VALUES(?,?,?,?)',(digest,self.store.vault.seal({'student_id':student},'portal_access:'+digest),time.time(),actor['id']))
                self.store._audit(db,actor,'student_access_granted',digest)
                row=db.execute('SELECT * FROM portal_access_grants WHERE student_digest=?',(digest,)).fetchone()
            return self._authorization(row)

    def revoke_authorization(self,actor,grant_id):
        if actor['role']!='admin':raise WebError(403,'admin_required','需要管理员权限。')
        if not re.fullmatch('[a-f0-9]{64}',grant_id):raise WebError(404,'not_found','授权不存在。')
        with self.store.db(True) as db:
            row=db.execute('SELECT * FROM portal_access_grants WHERE student_digest=?',(grant_id,)).fetchone()
            if not row:raise WebError(404,'not_found','授权不存在。')
            student=self._authorization(row)['student_id']
            db.execute('DELETE FROM portal_access_grants WHERE student_digest=?',(grant_id,))
            if not self.default_allowed(student):
                db.execute('DELETE FROM web_sessions WHERE user_id IN (SELECT user_id FROM portal_bindings WHERE student_digest=?)',(self.store.vault.digest('student',student),))
                # Retain the plan and history, but stop future/queued school work.
                db.execute('UPDATE web_accounts SET enabled=0 WHERE student_digest=?',(self.store.vault.digest('student',student),))
            self.store._audit(db,actor,'student_access_revoked',grant_id)

    def require_allowed_user(self,user):
        if not self.student_prefix or user['role']!='user':return
        with self.store.db() as db:row=db.execute('SELECT a.* FROM web_accounts a JOIN portal_bindings b ON b.account_id=a.id WHERE b.user_id=?',(user['id'],)).fetchone()
        if not row:raise WebError(403,'student_not_allowed','当前账号暂未开放登录。')
        self.require_allowed(self.store._payload(row)['student_id'])

    def _limit(self,student,remote):
        stamp=time.time()
        buckets=[(self.store.vault.digest('portal_login_student',student),30),
                 (self.store.vault.digest('portal_login_ip',remote),150),
                 (self.store.vault.digest('portal_login_global','all'),600)]
        with self.store.db(True) as db:
            db.execute('DELETE FROM web_login_limits WHERE reset_at<=?',(stamp,))
            for key,limit in buckets:
                row=db.execute('SELECT count,reset_at FROM web_login_limits WHERE bucket=?',(key,)).fetchone()
                if row and row[0]>=limit:
                    raise WebError(429,'login_rate_limited','登录请求较多，请稍后重试。',retry_after=max(1,math.ceil(row[1]-stamp)))
            for key,_ in buckets:
                db.execute('INSERT INTO web_login_limits VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1',(key,stamp+300))
        return buckets[0][0]

    def login(self,data,remote,*,auth_flow=None,school_profile=None,device_profile=None):
        if set(data)-{'student_id','password','browser_fingerprint','user_agent','consent_version'}:
            raise WebError(400,'invalid_fields','登录只接受学号、学校密码和可信浏览器信息。')
        self.check_notice(data.get('consent_version'))
        student=data.get('student_id')
        password=data.get('password')
        if not isinstance(student,str) or not re.fullmatch(r'\d{8,20}',student):
            raise WebError(400,'invalid_student','请输入正确的学号。')
        self.require_allowed(student)
        if not isinstance(password,str) or not 1<=len(password)<=128:
            raise WebError(400,'invalid_password','请输入学校登录密码。')
        # Assisted start already applied this request guard. Its private permit
        # is single-use below; finishing that flow is not another login attempt.
        bucket=self._limit(student,remote) if auth_flow is None else self.store.vault.digest('portal_login_student',student)
        digest=self.store.vault.digest('student',student)
        with self.store.db() as db:
            link=db.execute('SELECT b.*,u.password_hash,u.active,u.role FROM portal_bindings b JOIN web_users u ON u.id=b.user_id WHERE b.student_digest=?',(digest,)).fetchone()
            account=db.execute('SELECT * FROM web_accounts WHERE student_digest=?',(digest,)).fetchone()
        if link and (not link['active'] or link['role']!='user'):
            raise WebError(403,'user_disabled','你的账号已停用，请联系管理员。')
        previous=self.store._payload(account) if account else {}
        # Existing operator-held browser trust is not onboarding proof for a new
        # student. First binding always requires the student's own trusted value.
        fingerprint=data.get('browser_fingerprint') or (previous.get('browser_fingerprint') if link else None)
        ua=(data.get('user_agent') if data.get('browser_fingerprint') else previous.get('user_agent') if link else None) or data.get('user_agent')
        if not isinstance(fingerprint,str) or not re.fullmatch(r'[a-fA-F0-9]{32}',fingerprint):
            raise WebError(428,'school_verification_required','首次使用请先完成学校验证，并填写可信浏览器指纹。')
        payload={**previous,'id':account['id'] if account else uuid.uuid4().hex,'enabled':True,
                 'student_id':student,'password':password,'browser_fingerprint':fingerprint,'user_agent':ua,
                 'location':previous.get('location',None if self.store.allowed_presets else {'mode':'preset','preset':'xuezhi_group3_amap'}),
                 'variation':previous.get('variation',{'minutes':5,'meters':10} if self.store.allowed_presets and not previous else {'minutes':0,'meters':0})}
        if auth_flow and isinstance(device_profile,str) and re.fullmatch('[a-f0-9]{24}',device_profile):payload['browser_profile']=device_profile
        try:validate_config({'version':1,'accounts':[payload]})
        except ToolError:
            raise WebError(400,'browser_information_invalid','请检查可信浏览器指纹和对应的 User-Agent。') from None
        cached=bool(auth_flow is None and link and account and link['account_id']==account['id'] and
                    link['verified_at']>time.time()-self.VERIFIED_TTL and
                    previous.get('browser_fingerprint')==fingerprint and previous.get('user_agent')==ua and
                    self.store._verify(link['password_hash'],password))
        cookies=None
        if not cached:
            if not self.school_slots.acquire(blocking=False):
                raise WebError(429,'school_auth_busy','学校验证正在处理其他请求，请稍后重试。')
            try:
                state=State(self.store.directory)
                try:
                    permit=auth_flow or state.begin_interactive_login(account_key(payload))
                    state.complete_interactive_login(permit,account_key(payload))
                finally:state.close()
                cookies=self.verifier(payload)
            except ToolError as error:
                if error.reason in ('interactive_auth_cooldown','interactive_flow_invalid'):
                    raise local_auth_error(error) from None
                if error.reason in ('need_manual_mfa','need_manual_captcha'):
                    raise WebError(428,error.reason,'请在学校认证页面完成验证，更新可信浏览器指纹后重试。') from None
                if error.reason=='login_rejected':
                    raise WebError(401,'school_login_rejected','学号或学校密码不正确，或学校尚未信任此浏览器。') from None
                raise WebError(502,'school_unavailable','学校认证暂时不可用，请稍后重试；尚未保存本次凭据。') from None
            finally:self.school_slots.release()
            if not isinstance(cookies,list):raise WebError(502,'school_unavailable','学校认证未返回有效结果。')
        encoded=None if cached else self.store.hasher.hash(password)
        token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
        stamp=time.time()
        with self.store.db(True) as db:
            # Authorization may be withdrawn while the school verifier runs.
            self.require_allowed(student,db=db)
            current_link=db.execute('SELECT * FROM portal_bindings WHERE student_digest=?',(digest,)).fetchone()
            current=db.execute('SELECT a.*,u.role AS owner_role,u.active AS owner_active FROM web_accounts a JOIN web_users u ON u.id=a.owner_id WHERE a.student_digest=?',(digest,)).fetchone()
            if current_link:
                user=db.execute('SELECT * FROM web_users WHERE id=?',(current_link['user_id'],)).fetchone()
                if not user or not user['active'] or user['role']!='user':raise WebError(403,'user_disabled','账号已停用。')
                if cached and (not link or current_link['user_id']!=link['user_id'] or user['password_hash']!=link['password_hash']):
                    raise WebError(409,'identity_changed','账号状态已改变，请重新登录。')
                if not current or current['id']!=current_link['account_id'] or current['owner_id']!=user['id']:
                    raise WebError(409,'binding_changed','账号绑定已改变，请联系管理员。')
            else:
                if cached:raise WebError(409,'binding_changed','账号绑定已改变，请重新验证。')
                if current and current['owner_role']=='user':
                    user=db.execute('SELECT * FROM web_users WHERE id=?',(current['owner_id'],)).fetchone()
                else:
                    name='student_'+digest[:24]
                    user=db.execute('SELECT * FROM web_users WHERE username_key=?',(name,)).fetchone()
                    if not user:
                        cur=db.execute("INSERT INTO web_users(username,username_key,display_name,password_hash,role,active,must_change_password,created_at) VALUES(?,?,?,?,'user',1,0,?)",
                                       (name,name,'同学 · '+student[-4:],encoded,stamp))
                        user=db.execute('SELECT * FROM web_users WHERE id=?',(cur.lastrowid,)).fetchone()
                if not user['active'] or user['role']!='user':raise WebError(403,'user_disabled','账号已停用。')
                others=db.execute('SELECT id FROM web_accounts WHERE owner_id=?',(user['id'],)).fetchall()
                if any(not current or r['id']!=current['id'] for r in others):
                    raise WebError(409,'single_account_required','该用户已绑定其他学校账号，请联系管理员。')
            aid=current['id'] if current else payload['id']
            if not cached:
                if current and self.store._busy(db,aid):raise WebError(409,'account_busy','账号正在执行任务，请完成后重新登录。')
                payload['id']=aid
                if current:
                    old_payload=self.store._payload(current)
                    # Verification owns school credentials, not newer grants or
                    # settings saved while its external request was in flight.
                    verified={key:payload[key] for key in ('id','student_id','password',
                        'browser_fingerprint','user_agent','browser_profile') if key in payload}
                    payload={**old_payload,**verified}
                    if cookie_path(self.store.directory,old_payload).name!=cookie_path(self.store.directory,payload).name:
                        db.execute('DELETE FROM web_cookies WHERE binding=?',(cookie_path(self.store.directory,old_payload).name,))
                    db.execute('UPDATE web_accounts SET owner_id=?,payload=?,updated_at=? WHERE id=?',
                               (user['id'],self.store.vault.seal(payload,'account:'+aid),stamp,aid))
                else:
                    db.execute('INSERT INTO web_accounts(id,owner_id,label,student_digest,payload,enabled,automatic,run_at,created_at,updated_at) VALUES(?,?,?,?,?,1,0,?,?,?)',
                               (aid,user['id'],'我的学校账号',digest,self.store.vault.seal(payload,'account:'+aid),'22:00',stamp,stamp))
                db.execute('UPDATE web_users SET password_hash=?,must_change_password=0 WHERE id=?',(encoded,user['id']))
                if not self.store._verify(user['password_hash'],password):
                    db.execute('DELETE FROM web_sessions WHERE user_id=?',(user['id'],))
                db.execute('INSERT INTO portal_bindings VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET verified_at=excluded.verified_at',
                           (user['id'],digest,aid,stamp))
                binding=cookie_path(self.store.directory,payload).name
                db.execute('INSERT OR REPLACE INTO web_cookies VALUES(?,?)',(binding,self.store.vault.seal(cookies,'cookie:'+binding)))
                self.store._audit(db,user,'school_identity_verified',aid)
            if auth_flow and isinstance(school_profile,dict) and school_profile.get('student_name_source')=='school_mfa_greeting':
                name=school_profile.get('student_name','')
                if isinstance(name,str) and 2<=len(name.strip())<=40 and all(c.isalpha() or c in " ·•'’-" for c in name) and any(c.isalpha() for c in name) and name.strip() not in ('同学','用户','姓名','学生姓名','统一身份认证'):
                    db.execute('UPDATE web_users SET display_name=? WHERE id=? AND role=?',(name.strip(),user['id'],'user'))
                    self.store._audit(db,user,'school_profile_updated',user['id'])
            db.execute('UPDATE web_accounts SET label=(SELECT display_name FROM web_users WHERE id=?) WHERE id=?',(user['id'],aid))
            row=db.execute('SELECT run_at FROM web_accounts WHERE id=?',(aid,)).fetchone()
            reserve_slot(db,aid,row['run_at'],self.store.execution_window,account=payload,day=dt.datetime.fromtimestamp(stamp,SHANGHAI).date().isoformat())
            if data.get('consent_version')==NOTICE_VERSION:
                db.execute('INSERT INTO portal_notices VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,accepted_at=excluded.accepted_at',(user['id'],NOTICE_VERSION,stamp))
            db.execute('DELETE FROM web_login_limits WHERE bucket=?',(bucket,))
            db.execute('DELETE FROM web_sessions WHERE expires_at<? OR last_seen<?',(stamp,stamp-1800))
            db.execute('INSERT INTO web_sessions VALUES(?,?,?,?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(),user['id'],csrf,stamp,stamp,stamp+43200))
            self.store._audit(db,user,'student_login',aid)
            result=public_user(db.execute('SELECT * FROM web_users WHERE id=?',(user['id'],)).fetchone())
        if not cached:
            state=State(self.store.directory)
            try:state.authentication_recovered(account_key(payload),dt.datetime.fromtimestamp(stamp,SHANGHAI).date().isoformat())
            finally:state.close()
        return token,csrf,result

    def identity(self,user):
        if user['role']!='user':raise WebError(403,'student_required','请使用学生账号进入个人空间。')
        with self.store.db() as db:
            link=db.execute('SELECT * FROM portal_bindings WHERE user_id=?',(user['id'],)).fetchone()
        if not link:raise WebError(409,'school_verification_required','请重新使用学校账号登录，完成身份绑定。')
        return {'account':self.store.account(user,link['account_id']),'verified_at':link['verified_at']}

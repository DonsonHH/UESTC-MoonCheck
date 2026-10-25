"""Temporary account setup: verify both identities before an explicit save."""
import copy
import hashlib
import json
import math
import re
import secrets
import threading
import time
from portal import Portal, PortalError
from wechat import WechatPortal
from storage import now


def signature(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


class AccountSetup:
    def __init__(self, service):
        self.service=service;self.store=service.store;self.lock=threading.RLock();self.proofs={}

    def owned(self, owner, aid):
        a=self.store.account(aid)
        if a['owner_id']!=owner:raise KeyError('account')
        return a

    @staticmethod
    def revision(a):
        return signature({k:v for k,v in a.items() if k not in ('state','cookies')}) if a else ''

    def candidate(self, owner, data):
        if not isinstance(data,dict):raise ValueError('账号信息格式不正确。')
        aid=data.get('id') or None
        previous=self.owned(owner,aid) if aid else None
        draft_id=data.get('draft_id')
        if draft_id:
            draft=self.service.scans.draft(owner,draft_id)
            if draft.get('target')!=aid:raise ValueError('账号信息已变化，请重新扫码。')
            a=copy.deepcopy(draft['account'])
            if previous:
                if a.get('student_id')!=previous['student_id'] or a.get('school_user_id')!=previous.get('school_user_id'):raise ValueError('重新授权的学号与原账号不一致。')
                a={**copy.deepcopy(previous),'wx_credentials':a['wx_credentials'],'school_user_id':a['school_user_id']}
        elif previous:
            a=copy.deepcopy(previous)
        else:raise ValueError('请先扫码。')
        if not a.get('wx_credentials') or not a.get('school_user_id'):raise ValueError('请先扫码。')
        name=str(data.get('name','')).strip();sid=str(data.get('student_id','')).strip()
        if not 1<=len(name)<=40:raise ValueError('请填写备注。')
        if sid!=a.get('student_id'):raise ValueError('学号与微信绑定账号不一致。')
        a.update(name=name,enabled=data.get('enabled') is True)
        for key in ('password','fingerprint'):
            value=data.get(key)
            if value:
                value=str(value)
                if len(value)>4096 or any(c in value for c in ('\r','\n','\x00')):raise ValueError('登录信息格式不正确。')
                a[key]=value.strip() if key=='fingerprint' else value
                a['cookies']=[]
        if not a.get('password'):raise ValueError('请填写学校密码。')
        if a.get('fingerprint') and not re.fullmatch(r'[0-9a-fA-F]{32}',a['fingerprint']):raise ValueError('信任浏览器需要 32 位十六进制字符。')
        mode=data.get('location_mode','preset')
        if mode not in ('manual','preset'):raise ValueError('请选择位置。')
        a.update(location_mode=mode,preset_id=str(data.get('preset_id','')) if mode=='preset' else '')
        loc=self.store.resolve_location(a) if mode=='preset' else data
        for key,low,high in (('latitude',-90,90),('longitude',-180,180),('accuracy',0,100000)):
            try:value=float(loc.get(key,50 if key=='accuracy' else ''))
            except (TypeError,ValueError):raise ValueError('请填写有效的坐标和精度。') from None
            if not math.isfinite(value) or not low<=value<=high:raise ValueError('坐标或精度超出范围。')
            a[key]=value
        coordinate=loc.get('coordinate_system','gcj02')
        if coordinate not in ('gcj02','wgs84'):raise ValueError('坐标系不正确。')
        try:duration=min(max(int(data.get('location_duration_ms') or 0),0),600000)
        except (TypeError,ValueError):raise ValueError('定位信息不正确。') from None
        a.update(coordinate_system=coordinate,browser_location=mode=='manual' and data.get('browser_location') is True,
                 location_duration_ms=duration if mode=='manual' else 0,auth_mode='wechat')
        self.unique(a)
        # Include the effective preset coordinates. An administrator changing the
        # preset invalidates an earlier successful verification.
        return a,signature({k:v for k,v in a.items() if k not in ('state','cookies')}),self.revision(previous)

    def unique(self, a):
        for other in self.store.accounts():
            if other['id']!=a['id'] and (other['student_id']==a['student_id'] or other.get('school_user_id')==a['school_user_id'] or other.get('wx_credentials',{}).get('openid')==a['wx_credentials']['openid']):
                raise ValueError('该账号已添加。')

    def verify(self, owner, data):
        a,config_hash,revision=self.candidate(owner,data)
        portal=None
        try:
            if self.service.portal_factory is Portal:
                portal=WechatPortal(a,self.service.auth,lambda updated:None)
            else:portal=self.service.portal_factory(a)
            portal.ensure();today=portal.today()
            if not isinstance(today,dict) or today.get('businessDate')!=now().date().isoformat():
                raise PortalError('暂时无法确认今日状态，请重试。','pending')
            if today.get('abnormalFlag'):raise PortalError('今日记录异常，请核对后重试。','abnormal')
            a['cookies']=portal.cookies()
            checked=today.get('recordStatusCode')=='CHECKED_IN'
            verified_state=dict(wx_health={'status':'ready','at':now().isoformat()},today=today,last_outcome='already_done' if checked else 'connected',
                last_message='登录正常，今日已打卡' if checked else '登录正常',updated_at=now().isoformat())
            if checked:verified_state['success_date']=today['businessDate']
            a.setdefault('state',{}).update(verified_state)
            token=secrets.token_hex(24)
            with self.lock:
                self.proofs={k:v for k,v in self.proofs.items() if v['expires']>time.monotonic() and v['owner']!=owner}
                self.proofs[token]=dict(owner=owner,expires=time.monotonic()+300,config_hash=config_hash,
                    revision=revision,account=copy.deepcopy(a),verified_state=copy.deepcopy(verified_state),draft_id=data.get('draft_id'))
            return {'verification_token':token,'message':'检测通过，请保存。'}
        finally:
            if portal:portal.close()

    def save(self, owner, data):
        if not isinstance(data,dict):raise ValueError('账号信息格式不正确。')
        token=data.get('verification_token','')
        with self.lock:
            if data.get('id') and not data.get('draft_id') and not data.get('password') and not data.get('fingerprint'):
                saved,_,_=self.candidate(owner,data)
                self.store.save_account(saved)
                if token:self.proofs.pop(token,None)
                return saved['id']
            proof=self.proofs.get(token)
            if not proof or proof['owner']!=owner or proof['expires']<=time.monotonic():raise ValueError('请先检测登录。')
            a,config_hash,revision=self.candidate(owner,data)
            if not secrets.compare_digest(config_hash,proof['config_hash']) or revision!=proof['revision']:
                raise ValueError('信息已修改，请重新检测登录。')
            saved=copy.deepcopy(proof['account'])
            if data.get('id'):
                saved['state']=copy.deepcopy(self.owned(owner,data['id'])['state'])
                saved['state'].update(proof['verified_state'])
            self.unique(saved)
            self.store.save_account(saved)
            self.proofs.pop(token,None)
            if proof['draft_id']:self.service.scans.consume(owner,proof['draft_id'])
            return saved['id']

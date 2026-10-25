"""User-confirmed WeChat authorization. Credentials stay in encrypted account config."""
import time
from portal import Portal, PortalError, BASE, SAFE
from storage import now
from wx_auth import AuthError
from diagnostics import STAGES


def prepare_credentials(bridge, account, save):
    creds = account.get('wx_credentials') or {}
    if not creds.get('openid') or not creds.get('accesstoken'):
        error=PortalError('请先使用微信扫码授权。', 'need_auth');error.wx_expired=True
        raise error
    if creds.get('expires_at', 0) <= time.time()+60:
        if not creds.get('refreshtoken'):
            error=PortalError('微信授权已失效，请重新扫码。', 'need_auth');error.wx_expired=True
            raise error
        try:
            rotated = bridge.call('refresh', credentials=creds)
        except AuthError as exc:
            error=PortalError(str(exc), 'need_auth' if exc.definitive else 'failed',stage='刷新微信授权')
            error.auth_code=exc.code
            error.wx_expired=exc.definitive
            raise error from None
        if rotated.get('openid') != creds['openid'] or not rotated.get('accesstoken') or rotated.get('expires_at', 0) <= time.time():
            raise PortalError('微信凭据刷新响应异常，请稍后重试。', stage='刷新微信授权')
        rotated['refresh_token_observed_at'] = creds.get('refresh_token_observed_at', int(time.time()))
        account['wx_credentials'] = rotated
        # Save rotation before any code or school request, including on later failures.
        save(account)
        creds = rotated
    return creds


class WechatPortal(Portal):
    def __init__(self, account, bridge, save):
        super().__init__({k:v for k,v in account.items() if k not in ('cookies','fingerprint','session_cookie')})
        self.original = account
        self.bridge = bridge
        self.save = save
        self.mini = Portal({})
        self.credentials = None
        self.user = None
        self.ticket = None
        self.business_source = None
        self.wx_status = None

    def code(self):
        try:
            value = self.bridge.call('code', credentials=self.credentials)
        except AuthError as exc:
            error=PortalError(str(exc), 'need_auth' if exc.definitive else 'failed',stage='获取微信登录码')
            error.auth_code=exc.code
            error.wx_expired=exc.definitive
            raise error from None
        code = value.get('code')
        if not isinstance(code, str) or not code.strip():
            raise PortalError('未获取到微信登录码，请稍后重试。', 'need_auth')
        return code

    def mini_api(self, path, method='GET', payload=None):
        stage=STAGES.get(path,'微信验证')
        try:
            r = self.mini.request(method, BASE+'/platform-app/api/auth/'+path,
                                  json=payload, headers={'platform':'mp-weixin'})
        except PortalError as exc:raise exc.contextualize(stage) from None
        try:
            j = r.json()
        except ValueError:
            raise PortalError('小程序接口返回非 JSON 数据。',stage=stage,http=r.status_code) from None
        self.check_response(r,j,stage,payload,headers={'cookies':self.mini.cookies()},mini=True)
        return j.get('data')

    @staticmethod
    def identity(data):
        user = data.get('userData') if isinstance(data,dict) else None
        if not isinstance(user,dict) or any(not isinstance(user.get(k),str) or not user[k].strip() for k in ('id','username','fullName')):
            raise PortalError('学校身份信息不完整，未保存授权。', 'need_auth')
        return {k:user[k] for k in ('id','username','fullName')}

    def bind(self):
        try:
            user=self._bind()
        except PortalError as exc:
            self.wx_status='expired' if getattr(exc,'wx_expired',False) else 'retrying'
            raise
        self.wx_status='ready'
        return user

    def _bind(self):
        self.credentials = prepare_credentials(self.bridge, self.original, self.save)
        data = self.mini_api('check-bind', 'POST', {'code':self.code(), 'sn':''})
        if not isinstance(data,dict) or data.get('bind') is not True:
            raise PortalError('请先在“成电智慧学工”小程序绑定学校账号，再扫码。', 'need_auth')
        sid = data.get('sessionId')
        if not isinstance(sid,str) or not sid or any(ord(c)<=32 or ord(c)>=127 or c in '\";,\\' for c in sid):
            raise PortalError('小程序会话信息异常。', 'need_auth')
        if not self.mini.s.cookies.get_dict().get('SESSION'):
            self.mini.s.cookies.set('SESSION', sid, domain='jzsz.uestc.edu.cn', path='/', secure=True)
        self.user = self.identity(self.mini_api('user-info'))
        expected = self.original.get('school_user_id')
        if (expected and expected != self.user['id']) or (self.original.get('student_id') and self.original['student_id'] != self.user['username']):
            raise PortalError('扫码账号与原学校账号不一致，未修改原账号。', 'need_auth')
        return self.user

    def ensure(self):
        if self.user is None:
            self.bind()
        if not (self.original.get('password') or self.original.get('cookies')):
            raise PortalError('微信已授权，请先填写学校登录信息。', 'need_auth')
        school = Portal(self.original)
        try:
            try:school.ensure()
            except PortalError as exc:raise exc.contextualize('学校登录') from None
            user = self.identity(school.api('auth/user-info'))
            if user['id'] != self.user['id'] or user['username'] != self.user['username']:
                raise PortalError('学校登录与微信绑定身份不一致，已停止提交。', 'need_auth')
            self.s.close()
            self.s, school.s = school.s, None
            self.business_source = 'school'
        finally:
            if school.s is not None:
                school.close()

    def api(self, path, method='GET', payload=None, params=None, headers=None):
        extra = dict(headers or {})
        if method=='POST' and path in ('student-checkin-record/checkin','student-checkin-record/report'):
            if not self.ticket:
                raise PortalError('缺少打卡授权票据，请稍后重试。', 'need_auth')
            extra['X-Checkin-Ticket'], self.ticket = self.ticket, None
        return super().api(path,method,payload,params,headers=extra)

    def payload(self):
        ticket = self.mini_api('checkin-ticket','POST',{'code':self.code()})
        value = ticket.get('ticket') if isinstance(ticket,dict) else None
        import re
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',value):
            raise PortalError('打卡授权票据无效，请稍后重试。', 'need_auth')
        self.ticket = value
        return super().payload()

    def today(self):
        data = self.api('student-checkin-record/today')
        if data is None:
            return {'businessDate':now().date().isoformat(),'recordStatusCode':'PENDING'}
        if not isinstance(data,dict) or data.get('recordStatusCode') not in ('PENDING','NOT_CHECKED_IN','CHECKED_IN','STUDENT_REPORTED','INSTRUCTOR_REPORTED','EXEMPT'):
            raise PortalError('今日状态无法确认，请稍后重试。', 'pending')
        if data.get('studentSn') and data['studentSn'] != self.user['username']:
            raise PortalError('今日记录的学校身份不一致。', 'need_auth')
        if data['recordStatusCode'] in ('STUDENT_REPORTED','INSTRUCTOR_REPORTED','EXEMPT'):
            raise PortalError('今日已有填报或豁免记录，无需提交。', 'reported')
        return {k:data.get(k) for k in SAFE}

    def cookies(self):
        # The school business login is separate from mini-program authorization.
        # Mini-program sessions, code and operation tickets never persist.
        return super().cookies() if self.business_source == 'school' else []

    def close(self):
        self.mini.close()
        super().close()

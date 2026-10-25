"""School authentication and daily check-in HTTP client."""
import base64
import secrets
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from storage import now
from diagnostics import safe_text, STAGES

BASE = 'https://jzsz.uestc.edu.cn'
CAS = 'https://idas.uestc.edu.cn/authserver'
LOGIN = CAS + '/login?service=https%3A%2F%2Fjzsz.uestc.edu.cn%2F'
H5 = BASE + '/daily-checkin-h5/index.html?appId=294'
API = BASE + '/daily-checkin/api/'
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
SAFE = ('businessDate', 'recordStatusCode', 'checkinTime', 'distanceMeter', 'abnormalFlag', 'checkinLocationName')

class PortalError(Exception):
    def __init__(self, message, kind='failed', stage='', code=None, http=None):
        super().__init__(message)
        self.kind = kind
        self.stage,self.code,self.http=stage,code,http

    def contextualize(self, stage):
        if not self.stage:self.stage=stage
        return self

    def __str__(self):
        message=super().__str__()
        details=[]
        if self.code is not None:details.append('业务码 '+safe_text(str(self.code),limit=40))
        if self.http is not None:details.append('HTTP '+str(self.http))
        if getattr(self,'auth_code',None):details.append('授权代码 '+safe_text(self.auth_code,limit=60))
        return (self.stage+'失败：' if self.stage else '')+message+('（'+'，'.join(details)+'）' if details else '')

class Inputs(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.values = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'input':
            for k in (a.get('name'), a.get('id')):
                if k:
                    self.values[k] = a.get('value', '')

def encrypt_password(password, salt):
    key = salt.encode()
    if len(key) != 16:
        raise PortalError('登录页加密参数发生变化')
    prefix = ''.join(secrets.choice('ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678') for _ in range(64))
    pad = PKCS7(128).padder()
    plain = pad.update((prefix + password).encode()) + pad.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(secrets.token_bytes(16))).encryptor()
    return base64.b64encode(enc.update(plain) + enc.finalize()).decode()

class Portal:
    def __init__(self, account):
        self.a = account
        self.s = requests.Session()
        self.s.headers.update({'User-Agent': UA, 'Accept-Language': 'zh-CN,zh;q=0.9'})
        for c in account.get('cookies', []):
            if c.get('domain', '').lstrip('.') in ('jzsz.uestc.edu.cn', 'idas.uestc.edu.cn'):
                self.s.cookies.set(c['name'], c['value'], domain=c['domain'], path=c.get('path', '/'), expires=c.get('expires'), secure=True)
        if account.get('fingerprint'):
            self.s.cookies.set('MULTIFACTOR_BROWSER_FINGERPRINT', account['fingerprint'], domain='idas.uestc.edu.cn', path='/', secure=True)

    def request(self, method, url, follow=False, **kw):
        for _ in range(10):
            u = urlsplit(url)
            if u.scheme != 'https' or u.hostname not in ('jzsz.uestc.edu.cn', 'idas.uestc.edu.cn'):
                raise PortalError('认证跳转到了未配置的站点，请检查平台变更')
            try:
                r = self.s.request(method, url, timeout=(8, 20), allow_redirects=False, **kw)
            except requests.Timeout:
                raise PortalError('连接或响应超时，请稍后重试。') from None
            except requests.exceptions.SSLError:
                raise PortalError('HTTPS 证书验证失败。') from None
            except requests.ConnectionError:
                raise PortalError('无法连接学校平台，请检查网络或 DNS。') from None
            except requests.RequestException:
                raise PortalError('学校平台网络请求失败。') from None
            if follow and r.is_redirect:
                url = urljoin(url, r.headers['Location'])
                method, kw = 'GET', {}
                continue
            return r
        raise PortalError('学校平台重定向过多')

    def authorized(self):
        r = self.request('GET', BASE + '/daily-checkin/checkLogin?appId=294', follow=True)
        return r.status_code == 200 and urlsplit(r.url).path.startswith('/daily-checkin-h5/')

    def warmup(self):
        r = self.request('GET', BASE + '/api/isLoginFailure', params={'_t': int(time.time()*1000)}, headers={'Referer': BASE+'/', 'X-Requested-With': 'XMLHttpRequest'})
        if r.status_code != 200:
            raise PortalError('门户预热失败，请稍后重试')

    def login(self):
        if not self.a.get('password'):
            raise PortalError('请填写学校密码。', 'need_auth')
        r = self.request('GET', LOGIN, follow=True)
        fields = Inputs(r.text).values
        salt, execution = fields.get('pwdEncryptSalt'), fields.get('execution')
        if not salt:
            m = re.search(r'''pwdEncryptSalt["']?\s*[:=]\s*["']([^"']+)''', r.text)
            salt = m.group(1) if m else None
        if not salt or not execution:
            raise PortalError('暂时无法登录，请检查账号信息。', 'need_auth')
        r = self.request('POST', LOGIN, data={'username': self.a['student_id'], 'password': encrypt_password(self.a['password'], salt), 'captcha': '', '_eventId': 'submit', 'cllt': 'userNameLogin', 'dllt': 'generalLogin', 'lt': '', 'execution': execution}, headers={'Origin': 'https://idas.uestc.edu.cn', 'Referer': LOGIN})
        dest = urljoin(LOGIN, r.headers.get('Location', ''))
        if r.is_redirect and 'ticket=' in dest:
            self.request('GET', dest, follow=True)
        else:
            raise PortalError('登录失败，请检查学校密码。', 'need_auth')
        self.warmup()
        if not self.authorized():
            raise PortalError('暂时无法打开打卡页面，请稍后再试。', 'need_auth')

    def ensure(self):
        if self.a.get('cookies'):
            if self.authorized():
                return
            self.warmup()
            if self.authorized():
                return
        self.login()

    def api(self, path, method='GET', payload=None, params=None, headers=None):
        stage=STAGES.get(path,'访问学校接口')
        try:
            r = self.request(method, API + path, json=payload, params=params, headers={'Platform': 'h5', 'Origin': BASE, 'Referer': H5, 'Accept': '*/*', **(headers or {})})
        except PortalError as exc:
            if method=='POST' and path in ('student-checkin-record/checkin','student-checkin-record/report'):
                raise PortalError('提交请求未收到明确结果；下次重试先查询今日记录。'+str(exc),'pending',stage=stage) from None
            raise exc.contextualize(stage) from None
        try:
            j = r.json()
        except ValueError:
            reason='学校登录会话无效，平台未返回 JSON 数据。' if r.status_code==401 else '平台返回非 JSON 数据，无法读取结果。'
            raise PortalError(reason,'need_auth' if r.status_code==401 else 'failed',stage=stage,http=r.status_code) from None
        self.check_response(r,j,stage,payload,headers)
        return j.get('data')

    def check_response(self,r,j,stage,payload=None,headers=None,mini=False):
        raw_code=j.get('code') if isinstance(j,dict) else None
        code=raw_code if type(raw_code) is int or (isinstance(raw_code,str) and re.fullmatch(r'-?\d{1,12}',raw_code)) else None
        source=''
        if isinstance(j,dict):
            source=next((safe_text(j[k],self.a,payload,headers,{'cookies':self.cookies()}) for k in ('msg','message') if isinstance(j.get(k),str) and j[k].strip()),'')
        ticket=code in (46001,46002,46003)
        ok=isinstance(j,dict) and (j.get('ok') is True if mini else ((type(code) is int and code==0) or j.get('status') is True))
        if r.status_code==200 and ok and not ticket:return
        kind='failed'
        if ticket:reason='打卡操作授权失效，需重新获取票据。'
        elif code==46004:reason='提交结果待确认，下次重试将先查询今日记录。';kind='pending'
        elif r.status_code==401 or code==4001 or (code==5000 and any(x in source for x in ('未登录','会话已失效'))):reason='学校登录会话无效。';kind='need_auth'
        elif r.status_code==403 or code==4003:reason='平台拒绝访问或账号权限不足。'
        elif r.status_code==429:reason='请求过于频繁。'
        elif r.status_code>=500:reason='学校平台服务异常。'
        elif not isinstance(j,dict):reason='平台响应格式异常。'
        elif mini:reason='微信小程序鉴权未通过。';kind='need_auth'
        else:reason='平台拒绝请求。'
        if source:reason+=' 平台提示：'+source
        raise PortalError(reason,kind,stage,code,r.status_code)

    def today(self):
        d = self.api('student-checkin-record/today')
        if not isinstance(d, dict) or not d.get('recordStatusCode'):
            raise PortalError('今日状态字段缺失，请检查平台接口变更')
        return {k: d.get(k) for k in SAFE}

    def schedule(self):
        d = self.api('checkin-schedule/effective')
        if not isinstance(d, dict):
            raise PortalError('平台时段数据为空')
        start, end = d.get('studentCheckinStartOffsetMinute'), d.get('studentCheckinEndOffsetMinute')
        if d.get('effective') is not True or type(start) is not int or type(end) is not int or not 0 <= start < end <= 1440:
            raise PortalError('当前无有效打卡时段或平台时段格式变化', 'out_of_window')
        return {'start': start, 'end': end, 'name': str(d.get('scheduleName') or '晚间打卡')[:100]}

    def locations(self):
        d = self.api('checkin-location/available-locations')
        if not isinstance(d, list):
            raise PortalError('平台打卡点数据格式变化')
        return [{k: x.get(k) for k in ('locationName', 'latitude', 'longitude', 'radiusMeter')} for x in d if isinstance(x, dict)]

    def reverse_geocode(self):
        data = self.api('map/reverse', params={'lat': self.a['latitude'], 'lng': self.a['longitude']})
        if isinstance(data, dict):
            data = next((data.get(k) for k in ('address', 'reverseGeocode', 'formattedAddress') if isinstance(data.get(k), str) and data[k].strip()), None)
        if not isinstance(data, str) or not data.strip():
            raise PortalError('暂时无法获取位置信息，请稍后重试。')
        return data.strip()

    def payload(self):
        a = self.a
        return {'latitude': a['latitude'], 'longitude': a['longitude'], 'reverseGeocode': self.reverse_geocode(), 'clientTime': now().strftime('%Y-%m-%d %H:%M:%S'), 'userAgent': UA, 'coordinateSystemCode': a.get('coordinate_system', 'gcj02'), 'accuracy': a.get('accuracy', 50), 'locationDurationMs': a.get('location_duration_ms', 0), 'networkTypeCode': 'wifi', 'locationEnabled': bool(a.get('browser_location')), 'locationAuthorized': 'granted' if a.get('browser_location') else '', 'locationAccuracy': '', 'errorMessage': ''}

    def cookies(self):
        return [{'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path, 'expires': c.expires} for c in self.s.cookies]

    def close(self):
        self.s.close()

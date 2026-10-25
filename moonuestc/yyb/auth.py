"""WeChat QR OAuth, YYB refresh/login-buffer and native Python code acquisition."""
import base64
import hashlib
import http.client
import json
import re
import secrets
import threading
import time
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urljoin,urlsplit
import requests
from .protocol import CodeClient, ProtocolError
from .diagnostics import safe_text

YYB='https://yybadaccess.3g.qq.com'
CALLBACK=YYB+'/pc_yyb/pcyyb_oauth'
ALLOWED={'open.weixin.qq.com','long.open.weixin.qq.com','yybadaccess.3g.qq.com'}


def definitive_rejection(code,message):
    # Only call for a parsed YYB business rejection, never HTTP/network text.
    text=re.sub(r'[_-]',' ',message.lower()).replace('refreshtoken','refresh token')
    refresh='refresh token' in text or '刷新令牌' in text
    return bool(((code==42007 or '42007' in text) and refresh)
        or ((code==40188 or '40188' in text) and 'invalid scope' in text)
        or any(x in text for x in ('relogin','re login','重新登录','重新授权'))
        or (refresh and any(x in text for x in ('invalid','expire','无效','过期','失效'))))


class AuthError(ValueError):
    def __init__(self,code,detail='',business_code=None,http=None):
        self.code=code
        self.definitive=code in ('needs_rescan','invalid_credentials')
        messages={
            'needs_rescan':'微信授权已失效，请重新扫码。',
            'exchange_failed':'微信已确认，但未取得应用宝授权凭据，请重新扫码。',
            'unexpected_redirect':'授权页面返回了非预期跳转，请重试。',
            'login_buffer_failed':'应用宝登录凭据获取失败，请稍后重试。',
            'code_unavailable':'微信已授权，但获取小程序登录码失败，请检查网络后重试。',
            'protocol_login_failed':'微信协议登录未完成，握手或设备认证失败，请稍后重试。',
            'code_transport_failed':'微信取码请求未收到有效响应，请稍后重试。',
            'network_unavailable':'授权服务连接失败，请检查网络后重试。',
            'poll_timeout':'微信授权服务响应超时，请稍后重试。',
            'refresh_failed':'微信凭据刷新暂未成功，将继续重试。',
            'invalid_response':'微信授权服务响应格式异常，请稍后重试。',
            'invalid_credentials':'微信授权凭据不完整，请重新扫码。',
            'http_failure':'微信授权服务请求失败，请稍后重试。',
            'qr_unknown_status':'微信扫码状态响应异常，请重试。',
        }
        message=messages.get(code,'微信授权暂时不可用，请稍后重试。')
        if detail:message+=' 平台提示：'+safe_text(detail)
        if business_code is not None:message+='（应用宝业务码 '+str(business_code)+'）'
        if http is not None:message+='（HTTP '+str(http)+'）'
        super().__init__(message)


def callback_cookies(jar):
    # Use the cookie policy for the actual callback URL. QQ legitimately issues
    # cookies for parent domains such as .qq.com; equality on cookie.domain loses them.
    request=requests.Request('GET',CALLBACK).prepare()
    header=requests.cookies.get_cookie_header(jar,request) or ''
    parsed=SimpleCookie()
    try:parsed.load(header)
    except CookieError:raise AuthError('exchange_failed') from None
    return {name:value.value for name,value in parsed.items()}


class AuthClient:
    def __init__(self):
        self.lock=threading.RLock();self.scans={};self.closed=False
        self.codes=CodeClient()

    @staticmethod
    def http(session,method,url,timeout=(8,25),callback=False,**kwargs):
        expected_host=urlsplit(url).hostname
        issued=set()
        for _ in range(6):
            parsed=urlsplit(url)
            if parsed.scheme!='https' or parsed.hostname not in ALLOWED or parsed.hostname!=expected_host or parsed.port not in (None,443) or parsed.username or parsed.password:
                raise AuthError('unexpected_redirect')
            try:
                response=session.request(method,url,timeout=timeout,allow_redirects=False,**kwargs)
            except requests.ReadTimeout:
                raise AuthError('poll_timeout') from None
            except requests.RequestException:
                raise AuthError('network_unavailable') from None
            if len(response.content)>2*1024*1024:raise AuthError('response_limit')
            if callback:
                issued.update(callback_cookies(response.cookies))
                if {'openid','accesstoken'}<=issued:
                    return response
            if response.is_redirect:
                if method!='GET':raise AuthError('unexpected_redirect')
                url=urljoin(url,response.headers['Location']);method='GET';kwargs={};continue
            if response.status_code!=200:raise AuthError('http_failure',http=response.status_code)
            if callback and not {'openid','accesstoken'}<=issued:raise AuthError('exchange_failed')
            return response
        raise AuthError('redirect_limit')

    @staticmethod
    def session():
        s=requests.Session();s.headers['User-Agent']='Mozilla/5.0';return s

    def start(self):
        session=self.session()
        try:
            response=self.http(session,'GET','https://open.weixin.qq.com/connect/qrconnect',params={
                'appid':'wxd44977328b36e647','redirect_uri':CALLBACK+'?login_type=WX','response_type':'code',
                'scope':'snsapi_login,snsapi_runtime_pcsdk','state':'web','fast_login':'1','self_redirect':'true'})
            match=re.search(r'/connect/qrcode/([A-Za-z0-9_-]{8,128})',response.text)
            if not match:raise AuthError('qr_unavailable')
            uuid=match[1]
            image=self.http(session,'GET','https://open.weixin.qq.com/connect/qrcode/'+uuid).content
            if not (image.startswith(b'\x89PNG\r\n\x1a\n') or image.startswith(b'\xff\xd8\xff') or image.startswith((b'GIF87a',b'GIF89a'))):
                raise AuthError('qr_invalid_image')
            with self.lock:
                for key,s in list(self.scans.items()):
                    if time.monotonic()-s['created']>=300:
                        s['cancelled']=True;s['session'].close();del self.scans[key]
                if len(self.scans)>=32:raise AuthError('qr_busy')
                ident=secrets.token_hex(16)
                self.scans[ident]=dict(session=session,uuid=uuid,created=time.monotonic(),code=None,cancelled=False,lock=threading.Lock())
            return {'qr':ident,'image':base64.b64encode(image).decode()}
        except Exception:
            session.close();raise

    def scan(self,ident):
        with self.lock:
            s=self.scans.get(ident)
            if not s or s['cancelled'] or time.monotonic()-s['created']>=300:raise AuthError('qr_expired')
            return s

    def poll(self,ident):
        scan=self.scan(ident)
        with scan['lock']:
            if scan['code']:return {'status':'authorized'}
            try:
                r=self.http(scan['session'],'GET','https://long.open.weixin.qq.com/connect/l/qrconnect',timeout=(8,35),
                            params={'uuid':scan['uuid'],'_':str(int(time.time()*1000))})
            except AuthError as exc:
                if exc.code=='poll_timeout':return {'status':'pending'}
                raise
            self.scan(ident)
            result=re.search(r'wx_errcode\s*=\s*(\d+)',r.text)
            if not result:raise AuthError('qr_unknown_status')
            status={408:'pending',404:'scanned',403:'cancelled',402:'expired',405:'authorized'}.get(int(result[1]))
            if status=='authorized':
                code=re.search(r"wx_code\s*=\s*['\"]([^'\"]+)['\"]",r.text)
                if not code:raise AuthError('qr_missing_code')
                scan['code']=code[1]
            if not status:raise AuthError('qr_unknown_status')
            return {'status':status}

    def exchange(self,ident):
        scan=self.scan(ident)
        with scan['lock']:
            if not scan['code']:raise AuthError('qr_not_authorized')
            self.http(scan['session'],'GET',CALLBACK,callback=True,params={'login_type':'WX','code':scan['code'],'state':'web'})
            values=callback_cookies(scan['session'].cookies)
            if not values.get('openid') or not values.get('accesstoken'):raise AuthError('exchange_failed')
            try:expires=int(values.get('expires_in') or 7200)
            except ValueError:raise AuthError('exchange_failed') from None
            if not 0<expires<=86400*30:raise AuthError('exchange_failed')
            credentials={k:values.get(k,'') for k in ('openid','accesstoken','refreshtoken','nickname')}
            credentials.update(logintype=values.get('logintype') or 'WX',expires_at=int(time.time())+expires,expires_in=expires)
        self.cancel(ident)
        return credentials

    def cancel(self,ident):
        with self.lock:
            scan=self.scans.pop(ident,None)
            if scan:
                scan['cancelled']=True
                # Session.close releases pools; the polling request has its own timeout.
                scan['session'].close()
        return {'ok':True}

    def signed(self,path,body,credentials=None):
        data=json.dumps(body,ensure_ascii=False,separators=(',',':')).encode()
        timestamp=str(int(time.time()*1000));nonce=str(secrets.randbelow(10000))
        signature=hashlib.md5(data+timestamp.encode()+b'wgrdg373hy26ww2'+nonce.encode()).hexdigest()
        headers={'Content-Type':'application/json','Ual-Access-Businessid':'pc_yyb_auth',
                 'Ual-Access-Timestamp':timestamp,'Ual-Access-Nonce':nonce,'Ual-Access-Signature':signature}
        session=self.session()
        try:
            if credentials:
                for key in ('openid','accesstoken','refreshtoken'):
                    value=credentials.get(key,'')
                    if not isinstance(value,str) or any(ord(c)<33 or c in ';\r\n' for c in value):raise AuthError('invalid_credentials')
                    session.cookies.set(key,value,domain='yybadaccess.3g.qq.com',path='/',secure=True)
            response=self.http(session,'POST',YYB+'/pc_yyb_auth/'+path,data=data,headers=headers)
            value=response.json()
            if not isinstance(value,dict) or type(value.get('code')) is not int:raise AuthError('invalid_response')
            if value['code']!=0:
                raw=next((value[k] for k in ('msg','message') if isinstance(value.get(k),str) and value[k].strip()),'')
                kind='needs_rescan' if definitive_rejection(value['code'],raw) else ('refresh_failed' if path=='pcyyb_refresh_token_auth' else 'login_buffer_failed')
                raise AuthError(kind,safe_text(raw,credentials,body),value['code'])
            return value
        except ValueError as exc:
            if isinstance(exc,AuthError):raise
            raise AuthError('invalid_response') from None
        finally:session.close()

    def refresh(self,credentials):
        if not credentials.get('refreshtoken'):raise AuthError('needs_rescan')
        value=self.signed('pcyyb_refresh_token_auth',{'userInfo':{
            'openId':credentials['openid'],'refreshToken':credentials['refreshtoken'],
            'accessToken':credentials['accesstoken'],'loginType':credentials.get('logintype') or 'WX'}})
        user=value.get('user_info')
        if not isinstance(user,dict) or not isinstance(user.get('access_token'),str) or not user['access_token']:raise AuthError('invalid_response')
        try:expires=int(user.get('expires_in') or 7200)
        except (TypeError,ValueError):raise AuthError('invalid_response') from None
        if not 0<expires<=86400*30:raise AuthError('invalid_response')
        return {**credentials,'accesstoken':user['access_token'],
                'refreshtoken':user.get('refresh_token') or credentials['refreshtoken'],
                'expires_in':expires,'expires_at':int(time.time())+expires}

    def login_buffer(self,credentials):
        value=self.signed('pcyyb_get_wx_login_buffer_auth',{'extInfo':{'listS':{
            'unionid':{'value':[credentials['openid']]},'user_id':{'value':[credentials['openid']]},
            'access_token':{'value':[credentials['accesstoken']]}},'listI':{'user_type':{'value':[0]}}}},credentials)
        try:buffer=value['ext_info']['list_s']['login_buffer']['value'][0]
        except (KeyError,TypeError,IndexError):raise AuthError('login_buffer_failed') from None
        if not isinstance(buffer,str) or not buffer:raise AuthError('login_buffer_failed')
        return buffer

    def call(self,op,**values):
        if self.closed:raise AuthError('auth_closed')
        if op=='start':return self.start()
        if op=='poll':return self.poll(values['qr'])
        if op=='exchange':return self.exchange(values['qr'])
        if op=='cancel':return self.cancel(values['qr'])
        if op=='refresh':return self.refresh(values['credentials'])
        if op=='code':
            credentials=values['credentials']
            try:return {'code':self.codes.get_code(credentials['openid'],self.login_buffer(credentials))}
            except AuthError:raise
            except ProtocolError as exc:
                code={'protocol login failed':'protocol_login_failed','code transport failed':'code_transport_failed'}.get(str(exc),'invalid_response')
                raise AuthError(code) from None
            except (OSError,http.client.HTTPException):raise AuthError('network_unavailable') from None
            except (ValueError,KeyError,TypeError):raise AuthError('code_unavailable') from None
        if op=='forget':self.codes.forget(values['credentials']['openid']);return {'ok':True}
        raise AuthError('unknown_operation')

    def close(self):
        self.closed=True
        with self.lock:
            for ident in list(self.scans):self.cancel(ident)
        self.codes.close()

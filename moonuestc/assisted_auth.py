"""Owner-bound, expiring assisted school authentication; secrets never reach the UI."""
import base64,hashlib,hmac,json,re,secrets,threading,time,urllib.request,urllib.error
from .web_errors import WebError
from .state import State
from .runner import account_key
from .errors import ToolError
from .portal import local_auth_error

class BrowserBridge:
    def __init__(self,url,key):self.url,self.key=url.rstrip('/'),key
    def call(self,action,data):
        try:
            request=urllib.request.Request(self.url+'/'+action,data=json.dumps(data).encode(),headers={'Authorization':'Bearer '+self.key,'Content-Type':'application/json'},method='POST')
            with urllib.request.urlopen(request,timeout=48) as response:result=json.load(response)
            if result.get('ok') is not True:raise ValueError()
            return result
        except urllib.error.HTTPError as error:
            try:code=json.load(error).get('error')
            except Exception:code=None
            mapping={'expired':(410,'onboarding_expired','校方验证会话已过期，请重新登录。'),
                'busy':(429,'onboarding_busy','校方验证正在处理其他请求，请稍后重试。'),
                'not_verified':(409,'school_not_verified','请先完成校方验证，再继续绑定。'),
                'invalid_event':(400,'invalid_event','页面已发生变化，请刷新校方页面后重试。'),
                'browser_closed':(410,'browser_closed','校方页面已关闭，请重新登录。'),
                'invalid_asset':(404,'invalid_asset','校方资源尚未就绪，请稍后重试。')}
            mapping['login_rejected']=(401,'school_login_rejected','学号或学校密码不正确，请修改后重试。')
            status,safe,message=mapping.get(code,(503,'browser_unavailable','校方页面连接暂时中断，可重试当前会话。'))
            raise WebError(status,safe,message) from None
        except Exception:raise WebError(503,'browser_unavailable','校方页面连接暂时中断，可重试当前会话。') from None

class AssistedAuth:
    def __init__(self,portal,bridge):
        self.portal,self.bridge=portal,bridge;self.pending={};self.lock=threading.RLock()
        threading.Thread(target=self._janitor,daemon=True).start()
    def _janitor(self):
        while True:
            time.sleep(10)
            with self.lock:expired=[token for token,p in self.pending.items() if p['expires']<time.monotonic()]
            for token in expired:self.close(token)
    def close(self,token):
        with self.lock:value=self.pending.pop(token,None)
        if value:
            value.pop('password',None)
            try:
                if value['id']:
                    result=self.bridge.call('close',{'id':value['id']})
                    if result.get('password_posts')==0:self._refund(value)
            except WebError:pass
    def _refund(self,value):
        if value.get('auth_flow'):
            state=State(self.portal.store.directory)
            try:state.release_unsubmitted_login(value['auth_flow'],account_key(value))
            finally:state.close()
    def get(self,token,csrf=None):
        with self.lock:value=self.pending.get(hashlib.sha256((token or '').encode()).hexdigest())
        if not value or value['expires']<time.monotonic():raise WebError(410,'onboarding_expired','这次学校验证已过期，请重新登录。')
        if csrf is not None and (len(str(csrf))>128 or not hmac.compare_digest(str(csrf).encode('utf-8'),value['csrf'].encode('ascii'))):raise WebError(403,'csrf_failed','验证会话不匹配，请重新登录。')
        return value
    def start(self,data,remote,old_token=None):
        student,password=data.get('student_id'),data.get('password')
        if set(data)-{'student_id','password','viewport','consent_version'} or not isinstance(student,str) or not re.fullmatch('[0-9]{8,20}',student) or not isinstance(password,str) or not 1<=len(password)<=128:raise WebError(400,'invalid_credentials','请填写正确的学号和学校密码。')
        self.portal.check_notice(data.get('consent_version'))
        self.portal.require_allowed(student)
        with self.portal.store.db() as db:
            bound=db.execute('SELECT a.* FROM web_accounts a JOIN portal_bindings b ON b.account_id=a.id WHERE b.student_digest=?',(self.portal.store.vault.digest('student',student),)).fetchone()
        profile=(self.portal.store._payload(bound).get('browser_profile') or self.portal.store.vault.digest('school_browser_profile',student)[:24]) if bound else secrets.token_hex(12)
        viewport=data.get('viewport',{'width':1280,'height':900})
        if not isinstance(viewport,dict) or set(viewport)!={'width','height'} or any(not isinstance(n,int) or isinstance(n,bool) for n in viewport.values()) or not 300<=viewport['width']<=1920 or not 240<=viewport['height']<=1400:raise WebError(400,'invalid_viewport','验证窗口尺寸无效。')
        if old_token:self.close(hashlib.sha256(old_token.encode()).hexdigest())
        self.portal._limit(student,remote)
        with self.lock:
            if len(self.pending)>=2:raise WebError(429,'onboarding_busy','目前有其他同学正在验证，请稍后重试。')
            token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32);digest=hashlib.sha256(token.encode()).hexdigest()
            self.pending[digest]={'id':None,'csrf':csrf,'expires':time.monotonic()+300,'student_id':student,'password':password,'remote':remote,'lock':threading.Lock(),'auth_flow':None,'device_profile':profile,'consent_version':data.get('consent_version')}
        try:
            state=State(self.portal.store.directory)
            try:permit=state.begin_interactive_login(account_key({'student_id':student}))
            finally:state.close()
            with self.lock:self.pending[digest]['auth_flow']=permit
            try:
                # Start only prepares the school form. No credential POST occurs
                # until the distinct begin command, so startup failures refund.
                reply=self.bridge.call('start',{'student_id':student,'password':password,'viewport':viewport,'device_profile':profile})
            except Exception:
                self._refund(self.pending[digest]);raise
            with self.lock:self.pending[digest]['id']=reply['id']
            stage=self.bridge.call('begin',{'id':reply['id']})
            with self.lock:self.pending[digest]['phase']=stage.get('phase','verification')
        except ToolError as error:
            self.close(digest);raise local_auth_error(error) from None
        except Exception:self.close(digest);raise
        return token,csrf
    def state(self,token,revision=''):
        value=self.get(token)
        result=self.bridge.call('state',{'id':value['id'],'revision':revision})
        # Only the passive sanitized document is public. School cookies,
        # scripts, editable values and private browser IDs stay on the server.
        return {key:result[key] for key in ['ready','loading','mode','html','revision','width','height','host','expires_in','document'] if key in result}
    def progress(self,token):
        value=self.get(token)
        try:return {'phase':self.bridge.call('progress',{'id':value['id']}).get('phase','pending')}
        except WebError as error:
            if error.code=='school_login_rejected':self.close(hashlib.sha256(token.encode()).hexdigest())
            raise
    def event(self,token,csrf,data):
        value=self.get(token,csrf)
        if not isinstance(data,dict) or len(json.dumps(data))>8192 or data.get('kind') not in ('input','select','check','click','focus','enter','gesture','scroll','resize') or not isinstance(data.get('document'),str) or (data['kind'] not in ('resize','scroll') and not isinstance(data.get('key'),str)):raise WebError(400,'invalid_event','验证操作无效。')
        self.bridge.call('event',{'id':value['id'],'event':data})
    def asset(self,token,key):
        value=self.get(token)
        if not re.fullmatch('[a-f0-9]{32}',key):raise WebError(400,'invalid_asset','验证资源无效。')
        result=self.bridge.call('asset',{'id':value['id'],'key':key})
        mime=result.get('mime','')
        if not (mime=='text/css' or mime.startswith(('image/','font/')) or mime in ('application/font-woff','application/vnd.ms-fontobject','application/octet-stream')):raise WebError(400,'invalid_asset','验证资源无效。')
        try:body=base64.b64decode(result['body'],validate=True)
        except (ValueError,KeyError):raise WebError(400,'invalid_asset','验证资源无效。') from None
        if len(body)>4_000_000:raise WebError(400,'invalid_asset','验证资源过大。')
        return mime,body
    def finish(self,token,csrf):
        value=self.get(token,csrf)
        if not value['lock'].acquire(blocking=False):raise WebError(409,'onboarding_busy','正在绑定，请稍候。')
        try:
            original={'student_id':value['student_id'],'password':value['password']}
            result=self.bridge.call('result',{'id':value['id']})
            # Fresh password validation binds the original student ID, even if
            # a user manipulated the displayed school browser to another ID.
            return self.portal.login({**original,'consent_version':value.get('consent_version'),
                'browser_fingerprint':result['browser_fingerprint'],'user_agent':result['user_agent']},value['remote'],auth_flow=value['auth_flow'],device_profile=value['device_profile'],school_profile={key:result[key] for key in ('student_name','student_name_source') if key in result})
        finally:
            value['lock'].release();self.close(hashlib.sha256(token.encode()).hexdigest())

def register_assisted_routes(app,portal,body,client_ip,secure,session_cookie,bridge):
    from flask import request,jsonify
    manager=AssistedAuth(portal,bridge);app.extensions['moon_assisted']=manager
    cookie='moon_school_onboarding'
    def owner_token():return request.cookies.get(cookie,'')
    def supplied():return request.headers.get('X-Onboarding-CSRF','')
    @app.post('/api/onboarding/start')
    def assisted_start():
        if not portal.store.initialized():raise WebError(503,'not_initialized','服务尚未初始化。')
        token,csrf=manager.start(body(),client_ip(),owner_token())
        response=jsonify({'ok':True,'onboarding_csrf':csrf,'phase':manager.get(token).get('phase','verification')})
        response.set_cookie(cookie,token,max_age=300,secure=secure,httponly=True,samesite='Strict',path='/api/onboarding')
        return response
    @app.get('/api/onboarding/state')
    def assisted_state():return jsonify({'ok':True,**manager.state(owner_token(),request.args.get('revision','')[:64])})
    @app.get('/api/onboarding/progress')
    def assisted_progress():return jsonify({'ok':True,**manager.progress(owner_token())})
    @app.post('/api/onboarding/event')
    def assisted_event():
        manager.event(owner_token(),supplied(),body());return jsonify({'ok':True})
    @app.get('/api/onboarding/assets/<key>')
    def assisted_asset(key):
        from flask import Response
        mime,data=manager.asset(owner_token(),key)
        response=Response(data,content_type=mime)
        response.headers['Content-Security-Policy']="default-src 'none'; sandbox"
        return response
    @app.post('/api/onboarding/finish')
    def assisted_finish():
        token,csrf,user=manager.finish(owner_token(),supplied())
        response=jsonify({'ok':True,'user':user,'csrf_token':csrf})
        response.set_cookie(session_cookie,token,max_age=43200,secure=secure,httponly=True,samesite='Strict',path='/')
        response.delete_cookie(cookie,path='/api/onboarding',secure=secure,httponly=True,samesite='Strict')
        return response
    @app.post('/api/onboarding/cancel')
    def assisted_cancel():
        manager.get(owner_token(),supplied());manager.close(hashlib.sha256(owner_token().encode()).hexdigest())
        response=jsonify({'ok':True});response.delete_cookie(cookie,path='/api/onboarding',secure=secure,httponly=True,samesite='Strict');return response

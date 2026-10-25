"""Exercise the actual service worker against offline school-page fixtures."""
import queue,runpy,threading,time,json,base64,re
from html.parser import HTMLParser
from concurrent.futures import Future
from urllib.parse import urlsplit,parse_qs
from playwright.sync_api import sync_playwright as real_playwright

module=runpy.run_path('/browser/service.py',run_name='regression_test')
globals_=module['worker'].__globals__
stop=threading.Event()
class TestQueue(queue.Queue):
    def get(self,*args,**kwargs):
        if stop.is_set():raise SystemExit()
        return super().get(timeout=.05)
commands=TestQueue();globals_['commands']=commands
password_posts=[]
CASE="navigation"
provider_requests=[]
contexts=[]
context_options=[]

LOGIN='''<html><head><meta charset="utf-8"></head><body><form class="m-account" method="post" action="/authserver/login"><input id="username" name="username"><input id="password" name="password" type="password"><button id="login_submit">Login</button></form></body></html>'''
class FixtureRoute:
    def __init__(self,route,request):self.route,self.request=route,request
    def abort(self):return self.route.abort()
    def continue_(self):
        url=urlsplit(self.request.url)
        if url.hostname in ('res.wx.qq.com','open.weixin.qq.com'):
            provider_requests.append((url.hostname,url.path))
            if url.hostname=='res.wx.qq.com':return self.route.fulfill(body='.hidden{display:none}.qrcode{width:180px}',content_type='text/css')
            if url.path.startswith('/connect/qrcode/'):return self.route.fulfill(body=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j1ioAAAAASUVORK5CYII='),content_type='image/png')
            return self.route.fulfill(body='<html><head><link rel="stylesheet" href="https://res.wx.qq.com/connect/qr.css"></head><body><div class="hidden">Error boilerplate</div><h1>WeChat fixture QR</h1><img class="qrcode" src="/connect/qrcode/synthetic"></body></html>',content_type='text/html')
        if self.request.method=='POST':
            password_posts.append(self.request.url)
            if CASE=='rejected':return self.route.fulfill(body=LOGIN.replace('</body>','<div id="showErrorTip">账号或密码错误</div></body>'),content_type='text/html')
            return self.route.fulfill(body="<html><body><script>location.replace('/authserver/mfa?n=0')</script></body></html>",content_type='text/html')
        if url.path.endswith('/login'):
            if CASE=='slider':return self.route.fulfill(body=LOGIN.replace('<button id="login_submit">',"""<button type="button" id="login_submit" onclick="document.querySelector('#sliderCaptchaDiv').style.display='block';document.querySelector('#sliderCaptchaDiv').innerHTML='<div class=sliderContainer style=width:300px;height:40px>Slide verification</div>'">""").replace('</body>','<iframe style="position:fixed;left:0;top:150px;width:400px;height:500px" src="https://open.weixin.qq.com/connect/qrconnect?appid=fixture&amp;redirect_uri=https%3A%2F%2Fidas.uestc.edu.cn%2Fauthserver%2Fcallback"></iframe><div id="sliderCaptchaDiv" style="display:none;position:fixed;inset:0;background:white"></div></body>'),content_type='text/html')
            return self.route.fulfill(body=LOGIN,content_type='text/html')
        if CASE in ('wechat','popup'):
            provider='https://open.weixin.qq.com/connect/qrconnect?appid=fixture&amp;redirect_uri=https%3A%2F%2Fidas.uestc.edu.cn%2Fauthserver%2Fcallback'
            if url.path=='/wechat-redirect':return self.route.fulfill(status=302,headers={'Location':provider.replace('&amp;','&')})
            action="document.querySelector('#wx').style.display='block'" if CASE=='wechat' else "window.open(this.dataset.url)"
            return self.route.fulfill(body=f'''<html><head><meta charset="utf-8"></head><body><h1>你好，虚构姓名！</h1><p>请完成二次验证。</p><button id="wechat" data-url="{provider}" onclick="{action}">WeChat</button>'''+(f'<iframe id="wx" style="display:none;width:400px;height:500px" src="{provider}"></iframe>' if CASE=='wechat' else '')+'</body></html>',content_type='text/html')
        n=int(parse_qs(url.query).get('n',['0'])[0])
        script=f"<script>setTimeout(()=>location.replace('/authserver/mfa?n={n+1}'),2)</script>" if n<24 else ''
        return self.route.fulfill(body='''<html><head><style>.popup{display:none}.popup.open{display:block}</style></head><body><h1>School verification fixture</h1><button id="sms" onclick="document.querySelector('#modal').className='popup open'">SMS verification</button><section id="modal" class="popup"><label>OTP<input id="otp" placeholder="OTP" value=""></label><label><input id="trust" type="checkbox">Trust this verification device</label><select id="method"><option value="private-one">SMS</option><option value="private-two">Email</option></select><button id="verify" onclick="if(document.querySelector('#otp').value==='synthetic-otp'&&document.querySelector('#trust').checked)document.querySelector('#status').textContent='School accepted fixture'">Verify</button></section><div class="popup"><button>SMS verification</button></div><canvas id="qrcode" width="180" height="180"></canvas><input type="hidden" value="PRIVATE-HIDDEN"><textarea id="notes"></textarea><p id="status"></p>'''+script+'</body></html>',content_type='text/html')

class Context:
    def __init__(self,real):self.real=real;self.synthetic_verified=False
    def __getattr__(self,name):return getattr(self.real,name)
    def cookies(self):return self.real.cookies()+([{'name':'MULTIFACTOR_BROWSER_FINGERPRINT','value':'0123456789abcdef0123456789abcdef','domain':'idas.uestc.edu.cn'},{'name':'SESSION','value':'synthetic-session','domain':'jzsz.uestc.edu.cn'}] if self.synthetic_verified else [])
    def new_page(self):return self.real.new_page()
    def route(self,pattern,guard):
        self.real.route(pattern,lambda route,request:guard(FixtureRoute(route,request),request))
class Browser:
    def __init__(self,real):self.real=real
    def __getattr__(self,name):return getattr(self.real,name)
    def new_context(self,**kwargs):
        context_options.append(dict(kwargs))
        value=Context(self.real.new_context(**kwargs));contexts.append(value);return value
class Chromium:
    def __init__(self,real):self.real=real;self.browser=None
    def launch(self,**kwargs):self.browser=self.real.launch(**kwargs);return Browser(self.browser)
class Factory:
    def __enter__(self):
        self.manager=real_playwright();self.real=self.manager.__enter__();self.chromium=Chromium(self.real.chromium);return self
    def __exit__(self,*args):
        if self.chromium.browser:self.chromium.browser.close()
        return self.manager.__exit__(*args)
globals_['sync_playwright']=Factory
worker=threading.Thread(target=module['worker'],daemon=True);worker.start()
def call(action,data):
    future=Future();commands.put((action,data,future));return future.result(timeout=30)
try:
    failures=[]
    prepared=call('start',{'student_id':'202600000001','password':'synthetic-only'})
    assert not password_posts,'Preparation submitted credentials before begin'
    assert call('close',{'id':prepared['id']})['password_posts']==0
    mobile=call('start',{'student_id':'202600000001','password':'synthetic-only','viewport':{'width':390,'height':700}})
    assert not password_posts
    assert call('close',{'id':mobile['id']})['password_posts']==0
    for n in range(5):
        session=call('start',{'student_id':'202600000001','password':'synthetic-only'})
        try:
            assert len(password_posts)==n,'Preparation submitted a password'
            call('begin',{'id':session['id']})
            try:call('begin',{'id':session['id']})
            except ValueError as error:assert str(error)=='invalid_action'
            else:raise AssertionError('A browser flow began twice')
            frame=call('state',{'id':session['id']})
            for _ in range(20):
                if frame.get('html') and not frame.get('loading'):break
                frame=call('state',{'id':session['id']})
            assert frame.get('html') and frame['mode']=='page' and not frame.get('loading')
            assert 'image' not in frame and 'controls' not in frame
            class Nodes(HTMLParser):
                def __init__(self,html):super().__init__();self.nodes={};self.feed(html)
                def handle_starttag(self,tag,attrs):
                    values=dict(attrs)
                    if 'id' in values:self.nodes[values['id']]=values['data-moon-node']
            nodes=Nodes(frame['html']).nodes;doc=frame['document']
            assert '<script' not in frame['html'] and 'onclick=' not in frame['html'] and 'PRIVATE-HIDDEN' not in frame['html']
            assert '<style' in frame['html'] and 'class="popup"' in frame['html']
            def event(kind,key,**extra):return call('event',{'id':session['id'],'event':{'kind':kind,'key':nodes[key],'document':doc,**extra}})
            try:call('event',{'id':session['id'],'event':{'kind':'click','key':nodes['sms'],'document':'stale-document'}})
            except ValueError as error:assert str(error)=='invalid_event'
            else:raise AssertionError('Stale document event accepted')
            event('click','sms')
            opened=call('state',{'id':session['id']});assert 'class="popup open"' in opened['html']
            event('focus','otp');event('input','otp',value='synthetic-otp');event('input','notes',value='PRIVATE-TEXTAREA')
            event('check','trust',checked=True);event('select','method',index=1);event('click','verify')
            after=call('state',{'id':session['id']})
            assert 'School accepted fixture' in after['html']
            assert 'synthetic-otp' not in after['html'] and 'PRIVATE-TEXTAREA' not in after['html'] and 'private-two' not in after['html']
            unchanged=call('state',{'id':session['id'],'revision':after['revision']})
            assert 'html' not in unchanged and len(json.dumps(unchanged))<500
            asset_key=re.search(r'<img[^>]+data-moon-node="'+nodes['qrcode']+r'"[^>]+src="/api/onboarding/assets/([a-f0-9]{32})"',after['html']).group(1)
            asset=call('asset',{'id':session['id'],'key':asset_key});assert asset['mime']=='image/png'
            assert base64.b64decode(asset['body']).startswith(b'\x89PNG')
            try:call('asset',{'id':session['id'],'key':'0'*32})
            except ValueError as error:assert str(error)=='invalid_asset'
            else:raise AssertionError('Unregistered resource fetched')

        except Exception as error:failures.append(type(error).__name__+':'+str(error))
        finally:assert call('close',{'id':session['id']})['password_posts']==1
    assert len(password_posts)==5
    CASE='slider'
    slider=call('start',{'student_id':'202600000001','password':'synthetic-only'})
    try:
        phase=call('begin',{'id':slider['id']});assert phase['phase']=='challenge','School slider was treated as a pending password response'
        frame=call('state',{'id':slider['id']});assert frame['host']=='idas.uestc.edu.cn' and 'Slide verification' in frame['html'],'A preloaded WeChat frame hid the school challenge'
    finally:assert call('close',{'id':slider['id']})['password_posts']==0
    CASE='navigation'
    LOGIN=LOGIN.replace('<body>','<body><script>document.documentElement.dataset.testEnvironment=navigator.platform.includes("MoonUESTCTest/")?"fresh":"normal"</script>')
    for _ in range(2):
        fresh=call('start',{'student_id':'202600000001','password':'synthetic-only','fresh_environment':True})
        assert 'data-test-environment="fresh"' in call('state',{'id':fresh['id']})['html']
        assert call('close',{'id':fresh['id']})['password_posts']==0
    fresh_agents=[value['user_agent'] for value in context_options if 'MoonUESTCTest/' in value.get('user_agent','')]
    assert len(fresh_agents)==2 and len(set(fresh_agents))==2,'Fresh verification reused the same browser test environment'
    LOGIN=LOGIN.replace('<body>','<body><script>document.documentElement.dataset.accountProfile=navigator.platform.includes("MoonUESTCAccount/")?"account":"none"</script>')
    for profile in ('0'*24,'1'*24):
        regular=call('start',{'student_id':'202600000001','password':'synthetic-only','device_profile':profile})
        assert 'data-account-profile="account"' in call('state',{'id':regular['id']})['html']
        assert call('close',{'id':regular['id']})['password_posts']==0
    CASE='rejected'
    rejected=call('start',{'student_id':'202600000001','password':'synthetic-only'})
    try:
        try:call('begin',{'id':rejected['id']})
        except ValueError as error:assert str(error)=='login_rejected'
        else:raise AssertionError('Rejected school credentials were allowed into the page')
    finally:assert call('close',{'id':rejected['id']})['password_posts']==1
    for CASE in ('wechat','popup'):
        session=call('start',{'student_id':'202600000001','password':'synthetic-only'})
        try:
            assert call('begin',{'id':session['id']})['phase']=='verification'
            frame=call('state',{'id':session['id']});key=re.search(r'<button[^>]+id="wechat"[^>]+data-moon-node="(n[0-9]+)"',frame['html']).group(1)
            call('event',{'id':session['id'],'event':{'kind':'click','key':key,'document':frame['document']}})
            for _ in range(15):
                qr=call('state',{'id':session['id']})
                if qr['host']=='open.weixin.qq.com':break
            assert qr['host']=='open.weixin.qq.com' and 'WeChat fixture QR' in qr['html']
            assert 'https://res.wx.qq.com' not in qr['html']
            style=re.search(r'<link[^>]+href="/api/onboarding/assets/([a-f0-9]{32})"',qr['html']).group(1)
            css=call('asset',{'id':session['id'],'key':style});assert css['mime']=='text/css' and b'display:none' in base64.b64decode(css['body'])
            contexts[-1].synthetic_verified=True
            identity=call('result',{'id':session['id']});assert identity.get('student_name')=='虚构姓名' and identity.get('student_name_source')=='school_mfa_greeting'
        finally:call('close',{'id':session['id']})
    assert any(path.startswith('/connect/qrcode/') for host,path in provider_requests)
    print({'runs':5,'pageFailures':len(failures),'safeErrors':failures,'schoolNetworkRequests':0,'onePasswordPostPerFlow':True,'preparationPosts':0,'originalCssAndHiddenModalStates':True,'staleDocumentRejected':True,'defaultImages':0,'unchangedStateBytesUnder':500,'passiveAssetsOwnerBound':True,'wechatIframeAndPopup':True,'providerCssLoaded':True,'wrongPasswordRejectedBeforePage':True},flush=True)
    assert not failures,'Real browser worker loses the page during school MFA navigation'
finally:
    stop.set();worker.join(timeout=5)

"""Private, ephemeral school browser. No port is published on the host."""
import base64,hashlib,hmac,json,logging,os,queue,re,secrets,threading,time,sys
from concurrent.futures import Future
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from page_assets import PageAssets
from access_policy import SCHOOL_HOSTS,WECHAT_HOST,allowed_request
PAGE_SCRIPT=Path(__file__).with_name("page_snapshot.js").read_text(encoding="utf-8")
AUTH_SCRIPT=Path(__file__).with_name("auth_status.js").read_text(encoding="utf-8")
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
from playwright.sync_api import sync_playwright

LOGIN='https://idas.uestc.edu.cn/authserver/login?service=https%3A%2F%2Fjzsz.uestc.edu.cn%2F'
KEY=os.environ['BROWSER_ASSIST_KEY']
commands=queue.Queue(maxsize=16)
browser_ready=threading.Event()

def frame_is_active(frame):
    try:
        element=frame.frame_element()
        if not element.is_visible():return False
        # is_visible() includes offscreen/preloaded frames and frames under a
        # school modal. Only select a frame the owner can currently reach.
        return element.evaluate('''e=>{
            const r=e.getBoundingClientRect();
            const left=Math.max(0,r.left),right=Math.min(innerWidth,r.right),top=Math.max(0,r.top),bottom=Math.min(innerHeight,r.bottom);
            if(right<=left||bottom<=top)return false;
            return [.25,.5,.75].some(x=>[.25,.5,.75].some(y=>{const hit=document.elementFromPoint(left+(right-left)*x,top+(bottom-top)*y);return hit===e||e.contains(hit)}));
        }''')
    except Exception:return False


def current_view(value):
    root=value['page'];candidates=[p for p in value.get('popups',[]) if not p.is_closed() and urlsplit(p.url).hostname in SCHOOL_HOSTS|{WECHAT_HOST}]
    host_page=candidates[-1] if candidates else root
    prior=value.get('view')
    if prior and prior!=root and prior in host_page.frames and urlsplit(prior.url).hostname in SCHOOL_HOSTS|{WECHAT_HOST}:
        if frame_is_active(prior):return prior,host_page
    for frame in host_page.frames:
        if frame==host_page.main_frame or urlsplit(frame.url).hostname!=WECHAT_HOST:continue
        if frame_is_active(frame):return frame,host_page
    return host_page,host_page

def document_id(value,view):
    ids=value.setdefault('frame_ids',{})
    if view not in ids:ids[view]=secrets.token_hex(8)
    return str(view.evaluate('performance.timeOrigin'))+':'+ids[view]

def probe(value):
    status={'phase':'pending'}
    root=value['page']
    if urlsplit(root.url).hostname=='idas.uestc.edu.cn':
        try:status=root.evaluate('('+AUTH_SCRIPT+')()')
        except Exception:return {'phase':'pending'}
        if status.get('phase')=='rejected' and value['posts']>0:raise ValueError('login_rejected')
        if status.get('phase')=='verification' and value['posts']==1 and not value.get('student_name') and status.get('student_name'):
            value['student_name']=status['student_name'];value['student_name_source']=status['student_name_source']
    if status.get('phase')=='verification':value['primary_accepted']=True
    if value.get('primary_accepted') and value.get('wechat_enabled'):status['phase']='verification'
    cookies=value['context'].cookies()
    if any(c['name']=='SESSION' and c['domain'].lstrip('.')=='jzsz.uestc.edu.cn' for c in cookies):status['phase']='ready'
    return {'phase':status.get('phase','pending')}

def snapshot(value):
    probe(value)
    page,host_page=current_view(value);value['view']=page;value['view_page']=host_page
    for attempt in range(3):
        try:
            host_page.wait_for_timeout(60)
            cookies=value['context'].cookies()
            fp=next((c['value'] for c in cookies if c['name']=='MULTIFACTOR_BROWSER_FINGERPRINT' and c['domain'].lstrip('.')=='idas.uestc.edu.cn'),None)
            ready=bool(fp and re.fullmatch('[a-fA-F0-9]{32}',fp) and any(c['name']=='SESSION' and c['domain'].lstrip('.')=='jzsz.uestc.edu.cn' for c in cookies))
            frame=page.evaluate('('+PAGE_SCRIPT+')()');frame['document']=document_id(value,page)
            value['nodes']={node['key']:node for node in frame.pop('nodes')}
            html=value['assets'].document(frame)
            frame={key:frame[key] for key in ('mode','document')}
            frame.update(html=html,revision=hashlib.sha256((frame['document']+html).encode()).hexdigest(),ready=ready,
                host=urlsplit(page.url).hostname,expires_in=max(0,int(value['expires']-time.monotonic())),
                width=host_page.viewport_size['width'],height=host_page.viewport_size['height'],loading=False)
            value['frame']=frame
            return frame
        except Exception as error:
            if host_page.is_closed():raise ValueError('browser_closed') from None
            transient=any(word in str(error).lower() for word in ('context was destroyed','cannot find context','navigation','frame was detached','timeout'))
            if not transient:raise
            host_page.wait_for_timeout(120)
    frame=dict(value.get('frame',{}))
    frame.update(ready=False,loading=True,mode='page',host=urlsplit(page.url).hostname,expires_in=max(0,int(value['expires']-time.monotonic())))
    return frame

def worker():
    sessions={}
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,
            args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--disable-extensions'])
        browser_ready.set()
        while True:
            for sid,value in list(sessions.items()):
                if value['expires']<time.monotonic():
                    value['context'].close();del sessions[sid]
            try:action,data,future=commands.get(timeout=1)
            except queue.Empty:continue
            try:
                if action=='start':
                    if len(sessions)>=2:raise ValueError('busy')
                    sid=secrets.token_urlsafe(32)
                    viewport=data.get('viewport',{'width':1280,'height':900})
                    if not isinstance(viewport,dict) or set(viewport)!={'width','height'} or any(not isinstance(n,int) or isinstance(n,bool) for n in viewport.values()) or not 300<=viewport['width']<=1920 or not 240<=viewport['height']<=1400:raise ValueError('invalid_event')
                    mobile=viewport['width']<700
                    options={'is_mobile':True,'has_touch':True,'user_agent':f'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser.version} Mobile Safari/537.36'} if mobile else {}
                    test_environment=None
                    account_profile=data.get('device_profile')
                    if account_profile is not None and (not isinstance(account_profile,str) or not re.fullmatch('[a-f0-9]{24}',account_profile)):raise ValueError('invalid_event')
                    if data.get('fresh_environment'):
                        # Change the test environment, never mint a school trust
                        # cookie. The school's own scripts issue the fingerprint.
                        base=options.get('user_agent')
                        if base is None:
                            probe_context=browser.new_context();probe_page=probe_context.new_page()
                            try:base=probe_page.evaluate('navigator.userAgent')
                            finally:probe_context.close()
                        test_environment=secrets.token_hex(12)
                        options['user_agent']=base+' MoonUESTCTest/'+test_environment
                    context=browser.new_context(viewport=viewport,locale='zh-CN',timezone_id='Asia/Shanghai',accept_downloads=False,**options)
                    if test_environment or account_profile:
                        # Bind normal device inputs to the private per-student
                        # profile; explicit tests use per-attempt entropy. The
                        # school computes its own fingerprint/trust cookie.
                        context.add_init_script('''if(location.hostname==='idas.uestc.edu.cn'){
                            const platform=navigator.platform;
                            Object.defineProperty(Navigator.prototype,'platform',{configurable:true,get:()=>platform+%s});
                        }'''%json.dumps(' MoonUESTCTest/'+test_environment if test_environment else ' MoonUESTCAccount/'+account_profile))
                    value={'context':context,'expires':time.monotonic()+300,'student':data['student_id'],'posts':0,'begun':False,'assets':PageAssets()}
                    def guard(route,request,value=value):
                        # Playwright routes only the first request of a redirect
                        # chain. Validate the final provider document before its
                        # images and JSONP polling start loading.
                        if urlsplit(request.url).hostname==WECHAT_HOST and not value.get('wechat_enabled'):
                            try:allowed_request(request.frame.url,'document',value)
                            except Exception:pass
                        if not allowed_request(request.url,request.resource_type,value):return route.abort()
                        u=urlsplit(request.url)
                        posted=parse_qs(request.post_data or '') if request.method=='POST' else {}
                        if request.method=='POST' and u.hostname=='idas.uestc.edu.cn' and (u.path in ('/authserver/login','/authserver/mobile/login') or ('username' in posted and any(name in posted for name in ('password','userPassword')))):
                            if not value['begun'] or posted.get('username')!=[value['student']] or value['posts']>=1:return route.abort()
                            value['posts']+=1
                        # The helper can authenticate, but cannot submit attendance.
                        if u.hostname=='jzsz.uestc.edu.cn' and '/student-checkin-record/checkin' in u.path:return route.abort()
                        return route.continue_()
                    context.route('**/*',guard)
                    page=context.new_page();value['page']=page;sessions[sid]=value
                    value['popups']=[]
                    page.on('popup',lambda popup,value=value:value['popups'].append(popup) if len(value['popups'])<2 else popup.close())
                    def remember(response,value=value):
                        if response.request.resource_type=='document':
                            if urlsplit(response.url).hostname==WECHAT_HOST:allowed_request(response.url,'document',value)
                            return
                        if response.request.resource_type not in ('stylesheet','image','font'):return
                        try:value['assets'].remember(response.url,response.headers.get('content-type',''),response.body())
                        except Exception:pass
                    context.on('response',remember)
                    try:
                        page.goto(LOGIN,wait_until='domcontentloaded',timeout=25000)
                        value['user_agent']=page.evaluate('navigator.userAgent')
                        if not data.get('preview'):
                            page.locator('#username:visible').fill(data['student_id'])
                            page.locator('#password:visible').fill(data['password'])
                        # If a CAPTCHA is visible the owner solves it before the
                        # first credential POST. No challenge is solved by code.
                        # Preparation never sends a password. The app authorizes
                        # the distinct begin phase after reserving a local flow.
                        value['preview']=bool(data.get('preview'))
                        value['begun']=False
                    except Exception:
                        context.close();del sessions[sid];raise
                    result={'id':sid}
                else:
                    value=sessions.get(data.get('id'))
                    if not value:raise ValueError('expired')
                    page=value['page']
                    if action=='close':
                        posts=value['posts'];value['context'].close();del sessions[data['id']];result={'password_posts':posts}
                    elif action=='begin':
                        if value['begun']:raise ValueError('invalid_action')
                        value['begun']=True
                        captcha=page.locator('#captcha:visible')
                        if not value['preview'] and not captcha.count():page.locator('#login_submit:visible').click(timeout=10000,no_wait_after=True)
                        result=probe(value)
                        if not value['preview']:
                            deadline=time.monotonic()+8
                            while result['phase']=='pending' and time.monotonic()<deadline:
                                page.wait_for_timeout(200);result=probe(value)
                    elif action=='progress':result=probe(value)
                    elif action=='state':
                        result=dict(snapshot(value))
                        if data.get('revision')==result.get('revision'):result.pop('html',None)
                    elif action=='asset':
                        result=value['assets'].get(data.get('key',''),value['context'])
                    elif action=='event':
                        event=data.get('event',{});key=event.get('key','');kind=event.get('kind')
                        current=value.get('frame',{});view,host_page=current_view(value)
                        if view!=value.get('view') or event.get('document')!=current.get('document') or document_id(value,view)!=event.get('document'):raise ValueError('invalid_event')
                        page=view
                        if kind=='resize':
                            w,h=event.get('width'),event.get('height')
                            if not isinstance(w,int) or not isinstance(h,int) or not 300<=w<=1920 or not 240<=h<=1400:raise ValueError('invalid_event')
                            host_page.set_viewport_size({'width':w,'height':h});result={}
                        elif kind=='scroll':
                            x,y=event.get('x',0),event.get('y',0)
                            if not all(isinstance(n,(int,float)) and not isinstance(n,bool) and 0<=n<=100000 for n in (x,y)):raise ValueError('invalid_event')
                            page.evaluate('p=>window.scrollTo(p[0],p[1])',[x,y]);result={}
                        else:
                            node=value.get('nodes',{}).get(key)
                            if not node or not re.fullmatch('n[0-9]{1,6}',key):raise ValueError('invalid_event')
                            field=page.locator('[data-moon-node="'+key+'"]')
                            if field.count()!=1 or not field.is_visible():raise ValueError('invalid_event')
                            if kind=='input' and node['tag'] in ('input','textarea') and not node['primary']:
                                text=event.get('value','')
                                if not isinstance(text,str) or len(text)>1024:raise ValueError('invalid_event')
                                field.fill(text,timeout=3000)
                            elif kind=='select' and node['tag']=='select':
                                index=event.get('index')
                                if not isinstance(index,int) or not 0<=index<100:raise ValueError('invalid_event')
                                field.select_option(index=index,timeout=3000)
                            elif kind=='check' and node['tag']=='input' and not node['primary']:
                                checked=event.get('checked')
                                if not isinstance(checked,bool):raise ValueError('invalid_event')
                                field.set_checked(checked,timeout=3000)
                            elif kind=='focus' and node['tag'] in ('input','textarea','select'):field.focus(timeout=3000)
                            elif kind=='click':field.click(timeout=5000,no_wait_after=True)
                            elif kind=='enter':field.press('Enter',timeout=3000)
                            elif kind=='gesture':
                                points=event.get('points',[]);box=field.bounding_box()
                                if not box or not 1<=len(points)<=40 or any(not isinstance(p,list) or len(p)!=2 or not all(isinstance(n,(int,float)) and not isinstance(n,bool) for n in p) or not(0<=p[0]<=1 and 0<=p[1]<=1) for p in points):raise ValueError('invalid_event')
                                host_page.mouse.move(box['x']+points[0][0]*box['width'],box['y']+points[0][1]*box['height']);host_page.mouse.down()
                                for point in points[1:]:host_page.mouse.move(box['x']+point[0]*box['width'],box['y']+point[1]*box['height'])
                                host_page.mouse.up()
                            else:raise ValueError('invalid_event')
                            result={}
                    elif action=='result':
                        cookies=value['context'].cookies()
                        fp=next((c['value'] for c in cookies if c['name']=='MULTIFACTOR_BROWSER_FINGERPRINT' and c['domain'].lstrip('.')=='idas.uestc.edu.cn'),None)
                        if not fp or not re.fullmatch('[a-fA-F0-9]{32}',fp) or not any(c['name']=='SESSION' and c['domain'].lstrip('.')=='jzsz.uestc.edu.cn' for c in cookies):raise ValueError('not_verified')
                        result={'browser_fingerprint':fp,'user_agent':value['user_agent'],**{key:value[key] for key in ('student_name','student_name_source') if key in value}}
                    else:raise ValueError('invalid_action')
                future.set_result(result)
            except Exception as error:
                code=str(error) if isinstance(error,ValueError) and str(error) in {'busy','expired','not_verified','invalid_event','invalid_action','browser_closed','invalid_asset','login_rejected'} else 'browser_error'
                logging.warning('Browser action=%s code=%s exception=%s',action,code,type(error).__name__)
                future.set_exception(ValueError(code))

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(200 if self.path=='/healthz' and browser_ready.is_set() else 503)
        self.end_headers();self.wfile.write(b'{}')
    def do_POST(self):
        if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+KEY):
            self.send_error(403);return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=16384:raise ValueError('invalid_request')
            data=json.loads(self.rfile.read(length));future=Future()
            action=self.path.strip('/')
            if action not in ['start','begin','progress','state','event','asset','result','close']:raise ValueError('invalid_action')
            commands.put_nowait((action,data,future));result=future.result(timeout=45)
            body=json.dumps({'ok':True,**result}).encode();self.send_response(200)
        except Exception as error:
            code=str(error) if isinstance(error,ValueError) and str(error) in {'busy','expired','not_verified','invalid_event','invalid_action','browser_closed','invalid_asset','login_rejected'} else 'browser_unavailable'
            body=json.dumps({'ok':False,'error':code}).encode();self.send_response(401 if code=='login_rejected' else 410 if code=='expired' else 429 if code=='busy' else 409 if code=='not_verified' else 400 if code in {'invalid_event','invalid_action','invalid_asset'} else 503)
        self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)

if __name__=='__main__':
    threading.Thread(target=worker,daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0',8090),Handler).serve_forever()

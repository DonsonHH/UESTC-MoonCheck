"""Authenticated dashboard. Database ownership is checked on every operation."""
import functools
import hashlib
import hmac
import ipaddress
import os
import re
from pathlib import Path
import sqlite3
import time
import urllib.parse

from flask import Flask,g,jsonify,redirect,request,send_from_directory
from werkzeug.exceptions import HTTPException

from . import __version__
from .errors import ToolError
from .locations import DEFAULT_PRESET_ID,list_presets
from .web_errors import WebError
from .web_service import WebWorker
from .web_store import WebStore

COOKIE='moon_dashboard_session'


def re_qq_callback(path):return re.fullmatch(r'/api/qq/callback/[a-f0-9]{64}',path) is not None


def normalize_origin(value,allow_http=False):
    try:
        parsed=urllib.parse.urlsplit(value)
        port=parsed.port
        host=parsed.hostname
        if (parsed.scheme not in ('http','https') or not host or parsed.username or parsed.password
                or parsed.path not in ('','/') or parsed.query or parsed.fragment): raise ValueError()
        if parsed.scheme=='http':
            try: local=ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
            except ValueError: local=host=='localhost' or host.endswith('.local')
            if not allow_http or not local: raise ValueError()
        host=host.lower()
        if ':' in host: host='['+host+']'
        authority=host+(':'+str(port) if port and port!=(443 if parsed.scheme=='https' else 80) else '')
        return parsed.scheme+'://'+authority
    except (ValueError,TypeError):
        raise ToolError('dashboard_origin_required','web_config') from None


def create_app(directory,public_url,*,allow_http=False,start_worker=False,runner=None,hasher=None,registration_enabled=None,portal_enabled=None,school_verifier=None,trusted_proxies=None,browser_bridge=None,surface=None,wechat_client=None,wechat_gateway_factory=None,wechat_background=True):
    origin=normalize_origin(public_url,allow_http)
    secure=origin.startswith('https://')
    os.umask(0o077)
    static=Path(__file__).with_name('web_static')
    app=Flask(__name__,static_folder=str(static),static_url_path='/static')
    app.config.update(MAX_CONTENT_LENGTH=32768,MAX_FORM_MEMORY_SIZE=32768,MAX_FORM_PARTS=10,
                      JSON_SORT_KEYS=False,PROPAGATE_EXCEPTIONS=False)
    app.json.ensure_ascii=False
    store=WebStore(directory,hasher)
    from .portal import PortalAuth
    portal=PortalAuth(store,school_verifier)
    worker=WebWorker(store,runner)
    from .support_service import SupportManager
    support=SupportManager(store)
    worker.support_manager=support
    app.extensions['moon_support']=support
    app.extensions['moon_store']=store
    app.extensions['moon_worker']=worker
    app.extensions['moon_portal']=portal
    app.config['MOON_PORTAL_ENABLED']=(os.environ.get('MOON_ENABLE_PORTAL','0')=='1' if portal_enabled is None else bool(portal_enabled))
    surface=surface or os.environ.get('MOON_SURFACE') or ('public' if app.config['MOON_PORTAL_ENABLED'] else 'combined')
    if surface not in ('public','admin','combined'):raise ValueError('Invalid web surface')
    app.config['MOON_SURFACE']=surface
    wechat=None
    if (store.wechat_enabled or wechat_client is not None) and surface!='admin':
        from .wechat_authorization import WechatManager
        kwargs={'client':wechat_client,'background':wechat_background}
        if wechat_gateway_factory is not None:kwargs['gateway_factory']=wechat_gateway_factory
        wechat=WechatManager(store,**kwargs)
        store.wechat_enabled=True
        worker.wechat_manager=wechat
        app.extensions['moon_wechat']=wechat
    trusted=trusted_proxies if trusted_proxies is not None else os.environ.get('MOON_TRUSTED_PROXY_CIDRS','').split(',')
    proxy_networks=[ipaddress.ip_network(value.strip()) for value in trusted if value.strip()]

    def client_ip():
        remote=request.remote_addr or 'unknown'
        try:
            if any(ipaddress.ip_address(remote) in network for network in proxy_networks):
                return str(ipaddress.ip_address(request.headers.get('CF-Connecting-IP','')))
        except ValueError:pass
        return remote
    app.config['MOON_ORIGIN']=origin
    app.config['MOON_REGISTRATION_ENABLED']=False
    if browser_bridge is None and os.environ.get('MOON_BROWSER_ASSIST_URL') and os.environ.get('MOON_BROWSER_ASSIST_KEY'):
        from .assisted_auth import BrowserBridge
        browser_bridge=BrowserBridge(os.environ['MOON_BROWSER_ASSIST_URL'],os.environ['MOON_BROWSER_ASSIST_KEY'])
    app.config['MOON_ASSIST_ENABLED']=bool(browser_bridge and app.config['MOON_PORTAL_ENABLED'])

    def response_ok(value=None,status=200):
        return jsonify({'ok':True,**(value or {})}),status

    def current():
        if not hasattr(g,'moon_identity'):
            g.moon_identity=store.session(request.cookies.get(COOKIE))
            if g.moon_identity and ((surface=='public' and g.moon_identity[0]['role']=='admin') or (surface=='admin' and g.moon_identity[0]['role']!='admin')):
                g.moon_identity=None
            if g.moon_identity and app.config['MOON_PORTAL_ENABLED']:
                try:portal.require_allowed_user(g.moon_identity[0])
                except WebError as error:
                    if error.code!='student_not_allowed':raise
                    store.logout(request.cookies.get(COOKIE))
                    g.moon_identity=None
        return g.moon_identity

    def protected(admin=False,allow_password_change=False):
        def decorate(function):
            @functools.wraps(function)
            def wrapped(*args,**kwargs):
                if admin and surface=='public':raise WebError(404,'not_found','请求地址不存在。')
                identity=current()
                if not identity: raise WebError(401,'login_required','请先登录。')
                user,csrf=identity
                if user['role']=='user' and portal.require_notice and request.method not in ('GET','HEAD','OPTIONS') and request.path not in ('/api/notice/accept','/api/logout') and not store.notice_accepted(user):
                    raise WebError(428,'privacy_consent_required','请先阅读并同意当前个人信息托管说明。')
                if request.method not in ('GET','HEAD','OPTIONS'):
                    supplied=request.headers.get('X-CSRF-Token','')
                    if len(supplied)>128 or not hmac.compare_digest(supplied.encode('utf-8'),csrf.encode('ascii')):
                        raise WebError(403,'csrf_failed','请求校验失败，请刷新页面后重试。')
                if user['must_change_password'] and not allow_password_change:
                    raise WebError(403,'password_change_required','首次登录请先修改密码。')
                if admin and user['role']!='admin': raise WebError(403,'admin_required','需要管理员权限。')
                g.moon_user=user
                return function(*args,**kwargs)
            return wrapped
        return decorate

    def body():
        if not request.is_json: raise WebError(415,'json_required','请使用 JSON 请求。')
        value=request.get_json()
        if not isinstance(value,dict): raise WebError(400,'invalid_json','参数格式不正确。')
        return value

    @app.before_request
    def checks():
        if request.path=='/healthz': return None
        path=request.path
        if surface=='public' and (path=='/admin' or path.startswith(('/admin/','/api/admin/','/api/users','/api/portal/authorizations')) or path in ('/api/login','/api/me/password')):
            raise WebError(404,'not_found','请求地址不存在。')
        if surface=='admin' and (path.startswith(('/app','/api/onboarding/','/api/registration/')) or path in ('/register','/api/register','/api/portal/login','/api/portal/me')):
            raise WebError(404,'not_found','请求地址不存在。')
        try:
            received=normalize_origin(('https' if secure else 'http')+'://'+request.host,not secure)
        except ToolError:
            received=None
        if received!=origin:
            raise WebError(400,'host_not_allowed','请使用配置的访问地址。')
        if request.path.startswith('/api/') and request.method not in ('GET','HEAD','OPTIONS') and not re_qq_callback(request.path):
            try:
                sent=normalize_origin(request.headers.get('Origin'),not secure)
            except ToolError:
                sent=None
            if sent!=origin:
                raise WebError(403,'origin_not_allowed','访问来源不匹配，请使用系统配置的地址。')

    @app.after_request
    def headers(response):
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='same-origin'
        response.headers['X-Robots-Tag']='noindex, nofollow'
        response.headers['Permissions-Policy']='geolocation=(), camera=(), microphone=()'
        # Radix positioning and Sonner set inline CSS properties. Keep script
        # execution same-origin and retain the stricter legacy-page policy.
        style_policy="'self' 'unsafe-inline'" if app.config['MOON_PORTAL_ENABLED'] else "'self'"
        response.headers['Content-Security-Policy']="default-src 'none'; sandbox" if request.path.startswith('/api/onboarding/assets/') else "default-src 'self'; script-src 'self'; style-src "+style_policy+"; img-src 'self' data:; connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
        if request.path=='/api/onboarding/state' and request.accept_encodings['gzip']>0 and len(response.get_data())>2048:
            import gzip
            response.set_data(gzip.compress(response.get_data(),compresslevel=3))
            response.headers['Content-Encoding']='gzip'
            response.vary.add('Accept-Encoding')
        if secure: response.headers['Strict-Transport-Security']='max-age=31536000'
        return response

    @app.errorhandler(WebError)
    def web_error(error):
        detail={'code':error.code,'message':error.message}
        if error.retry_after is not None:detail['retry_after']=int(error.retry_after)
        response=jsonify({'ok':False,'error':detail})
        response.status_code=error.status
        if error.status==429: response.headers['Retry-After']=str(int(error.retry_after)) if error.retry_after is not None else '900' if error.code in ('login_rate_limited','registration_rate_limited','captcha_rate_limited') else '20'
        return response

    from .qq_bot import QQError
    @app.errorhandler(QQError)
    def qq_error(error):
        messages={40034142:'QQ 的 @全体成员次数已达上限，本次未触发 @全体。',40034143:'QQ 要求机器人拥有群管理员身份，才能 @全体成员。',40034105:'请群主开启机器人的主动发言权限。'}
        return jsonify({'ok':False,'error':{'code':'qq_delivery_failed','message':messages.get(error.code,'QQ 未确认本次操作，请检查机器人与群的消息权限。'),'platform_code':error.code}}),502

    @app.errorhandler(ToolError)
    def tool_error(error):
        return jsonify({'ok':False,'error':{'code':error.reason,'message':'服务器数据或配置不可用，请联系管理员。'}}),500

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify({'ok':False,'error':{'code':'http_'+str(error.code),'message':'请求地址或格式不正确。'}}),error.code

    @app.errorhandler(Exception)
    def internal_error(error):
        app.logger.error('Dashboard failure type=%s',type(error).__name__)
        return jsonify({'ok':False,'error':{'code':'internal_error','message':'操作失败，请联系管理员。'}}),500

    @app.get('/healthz')
    def health(): return jsonify({'ok':True})

    @app.get('/api/interface')
    def interface():return response_ok({'surface':surface,'adminInterface':surface=='admin','backgroundWorker':worker.thread is not None})

    @app.post('/api/qq/callback/<callback_key>')
    def qq_callback(callback_key):
        if surface=='admin':raise WebError(404,'not_found','请求地址不存在。')
        return jsonify(support.callback(callback_key,request.headers,request.get_data(cache=False)))

    @app.get('/api/support/features')
    @protected()
    def support_features():return response_ok(support.feature_summary(g.moon_user))

    @app.get('/api/qq/settings')
    @protected(admin=True)
    def qq_settings():return response_ok(support.bot_summary(origin if surface!='admin' else os.environ.get('MOON_STUDENT_PUBLIC_URL',origin)))

    @app.patch('/api/qq/settings')
    @protected(admin=True)
    def qq_configure():support.configure_bot(body());return response_ok()

    @app.post('/api/qq/probe')
    @protected(admin=True)
    def qq_probe():return response_ok(support.probe_bot())

    @app.get('/api/qq/operator')
    @protected(admin=True)
    def operator_summary():return response_ok(support.operator.summary())

    @app.patch('/api/qq/operator')
    @protected(admin=True)
    def operator_configure():return response_ok(support.operator.configure(body()))

    @app.get('/api/class/<account_id>')
    @protected(admin=True)
    def class_snapshot(account_id):return response_ok(support.class_snapshot(g.moon_user,account_id))

    @app.patch('/api/class/<account_id>')
    @protected(admin=True)
    def class_configure(account_id):return response_ok({'settings':support.configure_class(g.moon_user,account_id,body())})

    @app.post('/api/class/<account_id>/group-binding')
    @protected(admin=True)
    def class_group_binding(account_id):
        support.data.owner(g.moon_user,account_id)
        value=body()
        if value:raise WebError(400,'invalid_fields','请刷新管理端后重新生成班级群绑定码。')
        return response_ok({'code':support.data.new_code('group',account_id=account_id),'expires_in':600})

    @app.post('/api/class/<account_id>/test-message')
    @protected(admin=True)
    def class_test_message(account_id):
        support.data.owner(g.moon_user,account_id)
        value=body()
        if value.get('confirm') is not True or set(value)-{'confirm'}:raise WebError(400,'confirmation_required','请确认向已绑定的班级群发送连接检查消息。')
        config=support.data.cadre(account_id)
        target=config.get('group_openid')
        if not target or target==support.data.get('qq_test_destination').get('group_openid'):raise WebError(409,'group_not_bound','请先绑定班级群。')
        message='晚安成电：班级群连接正常。此消息仅检查连接，不触发 @全体。已开启的提醒将按管理端设置执行。'
        support.client_for_bot().send('group',target,message)
        return response_ok({'sent':True})

    @app.get('/api/notice')
    def hosting_notice():
        from .notice import NOTICE
        return response_ok({'notice':NOTICE,'consent_required':portal.require_notice})

    @app.post('/api/notice/accept')
    @protected()
    def accept_hosting_notice():
        value=body()
        if set(value)!={'version'}:raise WebError(400,'invalid_fields','告知确认参数不正确。')
        store.accept_notice(g.moon_user,value['version'])
        return response_ok()

    @app.get('/')
    def index():
        if surface=='admin':return redirect('/admin' if current() else '/admin/login')
        if app.config['MOON_PORTAL_ENABLED']:
            identity=current()
            return redirect('/admin' if identity and identity[0]['role']=='admin' else '/app' if identity else '/login')
        if not current(): return redirect('/login')
        return send_from_directory(static/'ui','index.html')

    @app.get('/login')
    def login_page():
        if surface=='admin':return redirect('/admin/login')
        if app.config['MOON_PORTAL_ENABLED']:return send_from_directory(static/'ui','index.html')
        if current(): return redirect('/')
        return send_from_directory(static/'ui','index.html')

    @app.get('/admin')
    @app.get('/admin/login')
    @app.get('/admin/accounts')
    @app.get('/admin/users')
    @app.get('/admin/history')
    @app.get('/admin/class-bot')
    def admin_page():
        identity=current()
        if identity and identity[0]['role']!='admin':raise WebError(403,'admin_required','需要管理员权限。')
        return send_from_directory(static/'ui','index.html')

    @app.get('/app')
    @app.get('/app/history')
    @app.get('/app/settings')
    @app.get('/app/authorization')
    def student_page():
        if not app.config['MOON_PORTAL_ENABLED']:raise WebError(404,'not_found','用户端尚未启用。')
        return send_from_directory(static/'ui','index.html')

    @app.get('/api/session')
    def session_info():
        identity=current()
        if not identity:
            return response_ok({'authenticated':False,'initialized':store.initialized(),'https':secure,'version':__version__,'portal_enabled':app.config['MOON_PORTAL_ENABLED'],'onboarding_available':app.config['MOON_ASSIST_ENABLED'],'registration_enabled':app.config['MOON_REGISTRATION_ENABLED'] and store.initialized()})
        user,csrf=identity
        return response_ok({'authenticated':True,'user':user,'csrf_token':csrf,'notice_required':portal.require_notice and not store.notice_accepted(user),'https':secure,'version':__version__,'portal_enabled':app.config['MOON_PORTAL_ENABLED'],'onboarding_available':app.config['MOON_ASSIST_ENABLED'],'registration_enabled':app.config['MOON_REGISTRATION_ENABLED'] and store.initialized()})

    @app.get('/register')
    @app.post('/api/register')
    @app.get('/api/registration/challenge')
    def registration_disabled():
        raise WebError(403,'registration_disabled','请使用学校账号登录并完成身份验证。')

    @app.post('/api/login')
    @app.post('/api/admin/login')
    def login():
        value=body()
        if set(value)-{'username','password'}: raise WebError(400,'invalid_fields','登录参数不正确。')
        if not store.initialized(): raise WebError(503,'not_initialized','管理员尚未初始化，请先在服务器执行 init-admin。')
        admin_only=request.path=='/api/admin/login' or app.config['MOON_PORTAL_ENABLED']
        token,csrf,user=store.login(value.get('username'),value.get('password'),client_ip(),admin_only=admin_only)
        response=jsonify({'ok':True,'user':user,'csrf_token':csrf})
        response.set_cookie(COOKIE,token,max_age=43200,secure=secure,httponly=True,samesite='Strict',path='/')
        return response

    @app.post('/api/portal/login')
    def portal_login():
        if not app.config['MOON_PORTAL_ENABLED']:raise WebError(404,'not_found','用户端尚未启用。')
        if not store.initialized():raise WebError(503,'not_initialized','服务尚未初始化。')
        token,csrf,user=portal.login(body(),client_ip())
        response=jsonify({'ok':True,'user':user,'csrf_token':csrf})
        response.set_cookie(COOKIE,token,max_age=43200,secure=secure,httponly=True,samesite='Strict',path='/')
        return response

    @app.get('/api/portal/me')
    @protected()
    def portal_me():return response_ok(portal.identity(g.moon_user))

    @app.post('/api/portal/reauthenticate')
    @protected()
    def portal_reauthenticate():
        if g.moon_user['role']!='user':raise WebError(403,'student_required','请由学生本人更新学校认证。')
        value=body()
        if set(value)-{'viewport'}:raise WebError(400,'invalid_fields','重新验证只接受当前账号，不接受其他学号或凭据。')
        manager=app.extensions.get('moon_assisted')
        if manager is None:raise WebError(503,'browser_unavailable','学校验证服务暂时不可用。')
        with store.db() as db:
            link=db.execute('SELECT account_id FROM portal_bindings WHERE user_id=?',(g.moon_user['id'],)).fetchone()
            if not link:raise WebError(409,'school_verification_required','请重新登录并完成学校账号绑定。')
            row=store._row(db,g.moon_user,link['account_id'])
            if store._busy(db,row['id']):raise WebError(409,'account_busy','请等待当前任务结束后再更新学校认证。')
            payload=store._payload(row)
        from .notice import VERSION
        data={'student_id':payload['student_id'],'password':payload['password'],'consent_version':VERSION}
        if 'viewport' in value:data['viewport']=value['viewport']
        token,csrf=manager.start(data,client_ip(),request.cookies.get('moon_school_onboarding'))
        response=jsonify({'ok':True,'onboarding_csrf':csrf,'phase':manager.get(token).get('phase','verification')})
        response.set_cookie('moon_school_onboarding',token,max_age=300,secure=secure,httponly=True,samesite='Strict',path='/api/onboarding')
        return response

    @app.get('/api/portal/authorizations')
    @protected(admin=True)
    def portal_authorizations():return response_ok(portal.authorizations(g.moon_user))

    @app.post('/api/portal/authorizations')
    @protected(admin=True)
    def portal_authorize():return response_ok({'authorization':portal.authorize(g.moon_user,body())})

    @app.delete('/api/portal/authorizations/<grant_id>')
    @protected(admin=True)
    def portal_revoke_authorization(grant_id):
        portal.revoke_authorization(g.moon_user,grant_id)
        return response_ok()

    @app.post('/api/logout')
    @protected(allow_password_change=True)
    def logout():
        store.logout(request.cookies.get(COOKIE))
        response=jsonify({'ok':True})
        response.delete_cookie(COOKIE,path='/',secure=secure,httponly=True,samesite='Strict')
        return response

    @app.post('/api/me/password')
    @protected(allow_password_change=True)
    def change_password():
        with store.db() as db:
            if db.execute('SELECT 1 FROM portal_bindings WHERE user_id=?',(g.moon_user['id'],)).fetchone():
                raise WebError(409,'school_password_managed','学校密码请在学校系统修改，再回到用户端重新验证。')
        value=body()
        if set(value)-{'current_password','new_password'}: raise WebError(400,'invalid_fields','密码参数不正确。')
        store.change_password(g.moon_user,value.get('current_password'),value.get('new_password'))
        response=jsonify({'ok':True})
        response.delete_cookie(COOKIE,path='/',secure=secure,httponly=True,samesite='Strict')
        return response

    @app.get('/api/locations')
    @protected()
    def locations():
        presets=[p for p in list_presets() if not store.allowed_presets or p['id'] in store.allowed_presets]
        return response_ok({'locations':presets,'default_preset_id':presets[0]['id'] if store.allowed_presets else DEFAULT_PRESET_ID,'execution_window':store.execution_window,'custom_allowed':not bool(store.allowed_presets)})

    @app.get('/api/accounts')
    @protected()
    def accounts(): return response_ok({'accounts':store.accounts(g.moon_user)})

    @app.post('/api/accounts')
    @protected()
    def create_account(): return response_ok({'account':store.save_account(g.moon_user,body())},201)

    @app.get('/api/accounts/<account_id>')
    @protected()
    def get_account(account_id): return response_ok({'account':store.account(g.moon_user,account_id)})

    @app.get('/api/wechat/notice')
    @protected()
    def wechat_notice():
        if wechat is None:raise WebError(404,'not_found','微信授权暂未启用。')
        from .wechat_authorization import AUTHORIZATION_NOTICE
        return response_ok({'notice':AUTHORIZATION_NOTICE})

    @app.post('/api/accounts/<account_id>/wechat/scans')
    @protected()
    def wechat_scan_start(account_id):
        if wechat is None:raise WebError(404,'not_found','微信授权暂未启用。')
        value=body()
        if set(value)!={'consent_version'}:raise WebError(400,'invalid_fields','扫码仅接受当前账号的授权确认。')
        actor=dict(g.moon_user);token=request.cookies.get(COOKIE)
        def session_valid():
            with store.db() as db:
                row=db.execute('SELECT s.user_id,s.expires_at,s.last_seen,u.active FROM web_sessions s JOIN web_users u ON u.id=s.user_id WHERE s.token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
                return bool(row and row['user_id']==actor['id'] and row['active'] and row['expires_at']>time.time() and row['last_seen']>time.time()-1800)
        return response_ok({'scan':wechat.start(actor,account_id,value['consent_version'],session_valid=session_valid,session_token=token)},201)

    @app.get('/api/wechat/scans/<scan_id>')
    @protected()
    def wechat_scan_state(scan_id):
        if wechat is None:raise WebError(404,'not_found','微信授权暂未启用。')
        return response_ok({'scan':wechat.get(g.moon_user,scan_id)})

    @app.delete('/api/wechat/scans/<scan_id>')
    @protected()
    def wechat_scan_cancel(scan_id):
        if wechat is None:raise WebError(404,'not_found','微信授权暂未启用。')
        wechat.cancel(g.moon_user,scan_id)
        return response_ok()

    @app.delete('/api/accounts/<account_id>/wechat')
    @protected()
    def wechat_revoke(account_id):
        if wechat is None:raise WebError(404,'not_found','微信授权暂未启用。')
        wechat.revoke(g.moon_user,account_id)
        return response_ok({'account':store.account(g.moon_user,account_id)})

    @app.patch('/api/accounts/<account_id>')
    @protected()
    def edit_account(account_id): return response_ok({'account':store.save_account(g.moon_user,body(),account_id)})

    @app.delete('/api/accounts/<account_id>')
    @protected()
    def remove_account(account_id):
        store.delete_account(g.moon_user,account_id)
        return response_ok()

    @app.post('/api/accounts/<account_id>/jobs')
    @protected()
    def create_job(account_id):
        value=body()
        if set(value)-{'mode','confirm'}: raise WebError(400,'invalid_fields','任务参数不正确。')
        if value.get('mode')=='checkin' and value.get('confirm') is not True:
            raise WebError(400,'submission_confirmation_required','请明确确认向学校提交打卡。')
        jid=store.enqueue(g.moon_user,account_id,value.get('mode'))
        return response_ok({'job':store.jobs(g.moon_user,jid)},202)

    @app.get('/api/jobs')
    @protected()
    def jobs(): return response_ok({'jobs':store.jobs(g.moon_user)})

    @app.get('/api/jobs/history')
    @protected()
    def job_history():
        if set(request.args)-{'cursor'} or len(request.args.getlist('cursor'))>1:raise WebError(400,'invalid_fields','运行记录查询参数不正确。')
        return response_ok(store.job_history(g.moon_user,request.args.get('cursor')))

    @app.get('/api/jobs/<job_id>')
    @protected()
    def job(job_id): return response_ok({'job':store.jobs(g.moon_user,job_id)})

    @app.get('/api/users')
    @protected(admin=True)
    def users(): return response_ok({'users':store.users()})

    @app.post('/api/users')
    @protected(admin=True)
    def create_user(): return response_ok({'user':store.create_user(g.moon_user,body())},201)

    @app.patch('/api/users/<int:user_id>')
    @protected(admin=True)
    def edit_user(user_id): return response_ok({'user':store.update_user(g.moon_user,user_id,body())})

    @app.delete('/api/users/<int:user_id>')
    @protected(admin=True)
    def remove_user(user_id):
        store.delete_user(g.moon_user,user_id)
        return response_ok()

    if app.config['MOON_ASSIST_ENABLED']:
        from .assisted_auth import register_assisted_routes
        register_assisted_routes(app,portal,body,client_ip,secure,COOKIE,browser_bridge)
    if start_worker and surface!='admin': worker.start()
    return app


def serve_dashboard(directory,public_url,*,host='0.0.0.0',port=8080,allow_http=False):
    from waitress import create_server
    from .state import execution_lock
    import signal
    surface=os.environ.get('MOON_SURFACE') or ('public' if os.environ.get('MOON_ENABLE_PORTAL')=='1' else 'combined')
    with execution_lock(Path(directory)/('web-instance-admin' if surface=='admin' else 'web-instance')):
        app=create_app(directory,public_url,allow_http=allow_http,start_worker=surface!='admin',surface=surface)
        server=create_server(app,host=host,port=port,threads=4,connection_limit=64,
                             max_request_body_size=32768,clear_untrusted_proxy_headers=True,
                             expose_tracebacks=False)
        previous={}
        def stop(signum,frame): server.close()
        for value in (signal.SIGTERM,signal.SIGINT):
            previous[value]=signal.signal(value,stop)
        try: server.run()
        finally:
            app.extensions['moon_worker'].stop()
            server.close()
            for value,handler in previous.items(): signal.signal(value,handler)

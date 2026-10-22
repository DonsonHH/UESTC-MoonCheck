import csv
import io
import math
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, render_template, request, session, redirect, url_for, Response, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from storage import Store, now, DEFAULT_SETTINGS, preparation_start
from service import Service, minutes
from planning import daily_plan, plan_datetime

def create_app(data_dir=None, start_scheduler=False, portal_factory=None):
    app = Flask(__name__)
    store = Store(data_dir or os.environ.get('MOONCHECK_DATA_DIR') or Path(__file__).parent / 'data')
    service = Service(store, **({'portal_factory': portal_factory} if portal_factory else {}))
    app.extensions.update(store=store, service=service)
    app.config.update(SECRET_KEY=store.get('session_secret'), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=os.environ.get('MOONCHECK_SECURE_COOKIE') == '1', PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=64*1024)
    app.config['TRUSTED_HOSTS'] = [x.strip() for x in os.environ.get('MOONCHECK_TRUSTED_HOSTS', 'localhost,127.0.0.1,[::1]').split(',') if x.strip()]
    failures = {}
    failures_lock = threading.Lock()

    @contextmanager
    def mutation():
        if not service.gate.acquire(blocking=False):
            raise ValueError('正在处理任务，请稍后保存。')
        try:
            yield
        finally:
            service.gate.release()

    @app.before_request
    def protect():
        session.setdefault('csrf', secrets.token_urlsafe(32))
        # Recheck identity and active state on every request (including old sessions).
        uid = session.get('user_id') or ('root' if session.get('admin') else None)
        g.user = store.user(uid=uid) if uid else None
        if g.user and (not g.user['active'] or session.get('auth_version', 0) != g.user['auth_version']):
            g.user = None
            session.pop('user_id', None)
            session.pop('admin', None)
        if g.user:
            session['user_id'] = g.user['id']
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf', '')
            if not secrets.compare_digest(token, session['csrf']):
                return jsonify(error='页面已过期，请刷新后重试'), 403
        if request.path.startswith('/api/') and not g.user:
            return jsonify(error='请先登录'), 401
        if request.path.startswith('/api/admin/') and g.user['role'] != 'superadmin':
            return jsonify(error='仅总管理员可执行此操作'), 403

    @app.after_request
    def headers(r):
        r.headers['X-Content-Type-Options'] = 'nosniff'
        r.headers['X-Frame-Options'] = 'DENY'
        r.headers['Referrer-Policy'] = 'same-origin'
        r.headers['Cache-Control'] = 'no-store'
        r.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        return r

    @app.errorhandler(ValueError)
    def invalid(e):
        return jsonify(error=str(e)), 400

    @app.errorhandler(404)
    def missing(e):
        return jsonify(error='资源不存在或无权访问'), 404

    @app.get('/healthz')
    def health():
        return jsonify(status='ok' if not service.scheduler_error else 'degraded')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        return auth_page(False)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        return auth_page(True)

    def auth_page(registering):
        setup = not store.users()
        if registering and setup:
            return redirect(url_for('login'))
        if registering and not store.get('registration_enabled', True):
            return render_template('login.html', setup=False, registering=True, closed=True, error='管理员已关闭注册'), 403
        error = None
        if request.method == 'POST':
            password = request.form.get('password', '')
            username = request.form.get('username', 'admin').strip().lower()
            user = None
            ip = request.remote_addr or 'unknown'
            with failures_lock:
                attempts = [t for t in failures.get(ip, []) if time.monotonic() - t < 900]
                failures[ip] = attempts
                limited = len(attempts) >= 8
            if limited:
                error = '尝试次数过多，请 15 分钟后重试'
            elif not re.fullmatch(r'[a-z0-9_.-]{3,32}', username):
                error = '用户名需要 3–32 位字母、数字、下划线、点或短横线'
            elif setup or registering:
                setup_token = os.environ.get('MOONCHECK_SETUP_TOKEN')
                local = ip in ('127.0.0.1', '::1')
                if setup and setup_token and not secrets.compare_digest(request.form.get('setup_token', ''), setup_token):
                    error = '初始设置令牌不正确'
                elif setup and not local and not setup_token:
                    error = '首次设置请通过服务器本地访问，或设置 MOONCHECK_SETUP_TOKEN'
                elif len(password) < 12 or len(password) > 256:
                    error = '请设置 12–256 位登录密码'
                elif registering and password != request.form.get('confirm_password', ''):
                    error = '两次密码不一致'
                else:
                    with mutation():
                        if registering and not store.get('registration_enabled', True):
                            error = '管理员已关闭注册'
                        else:
                            try:
                                user = store.create_user(username, generate_password_hash(password), superadmin=setup)
                            except ValueError as e:
                                error = str(e)
            else:
                user = store.user(username=username)
                valid = user and len(password) <= 256 and check_password_hash(user['password_hash'], password)
                if not valid or not user['active']:
                    error = '用户名或密码不正确，或账号已被停用'
            if error:
                with failures_lock:
                    failures[ip].append(time.monotonic())
            else:
                session.clear()
                session.update(user_id=user['id'], auth_version=user['auth_version'], csrf=secrets.token_urlsafe(32))
                session.permanent = True
                return redirect(url_for('index'))
        return render_template('login.html', setup=setup, registering=registering, error=error, token_required=bool(os.environ.get('MOONCHECK_SETUP_TOKEN')), registration_enabled=store.get('registration_enabled', True))

    @app.get('/')
    def index():
        if not g.user:
            return redirect(url_for('login'))
        return render_template('index.html', user=g.user)

    @app.post('/api/logout')
    def logout():
        session.clear()
        return jsonify(ok=True)

    def public(a):
        try:
            resolved = store.resolve_location(a)
        except ValueError:
            resolved = {**a, 'location_unavailable': True}
        current = now()
        plan = daily_plan(store.random_key,a,g.user['settings'],current.date().isoformat())
        planned = plan_datetime(current,plan)
        next_retry = None
        state = a.get('state',{})
        if state.get('attempt_date') == current.date().isoformat() and state.get('last_attempt'):
            next_retry = (datetime.fromisoformat(state['last_attempt']) + timedelta(minutes=g.user['settings']['retry_minutes'],seconds=plan['retry_delay_seconds'])).isoformat()
        return {k: v for k, v in resolved.items() if k not in ('password', 'session_cookie', 'cookies', 'fingerprint', 'address')} | {'has_password': bool(a.get('password')), 'has_fingerprint': bool(a.get('fingerprint')), 'planned_checkin_at':planned.isoformat(), 'next_retry_at':next_retry}

    def owned(aid):
        a = store.account(aid)
        if a.get('owner_id') != g.user['id']:
            abort(404)
        return a

    @app.get('/api/state')
    def state():
        uid = g.user['id']
        own_accounts = store.accounts(uid)
        busy = service.busy if service.busy and service.busy['account_id'] in {a['id'] for a in own_accounts} else None
        return jsonify(user={k:g.user[k] for k in ('id','username','role')}, accounts=[public(a) for a in own_accounts], settings=g.user['settings'], events=store.events(owner_id=uid), presets=[p for p in store.presets() if p.get('enabled') or g.user['role']=='superadmin'], busy=busy, server_busy=bool(service.busy), server_time=now().isoformat(), scheduler_running=bool(service.scheduler_thread and service.scheduler_thread.is_alive()), scheduler_error=service.scheduler_error)

    @app.post('/api/accounts')
    def save_account():
        data = request.get_json() or {}
        with mutation():
            aid = data.get('id')
            a = owned(aid) if aid else {'id': secrets.token_hex(8), 'state': {}, 'owner_id': g.user['id']}
            name = str(data.get('name', '')).strip()
            sid = str(data.get('student_id', '')).strip()
            if not name or len(name) > 40:
                raise ValueError('备注名称需要 1–40 个字符')
            if not re.fullmatch(r'[0-9A-Za-z_-]{4,32}', sid):
                raise ValueError('请输入有效学号（4–32 位）')
            if any(x['student_id'] == sid and x['id'] != a['id'] for x in store.accounts(g.user['id'])):
                raise ValueError('该学号已经添加')
            if a.get('student_id') and a['student_id'] != sid:
                a = {'id': a['id'], 'state': {}, 'owner_id': g.user['id']}
            a.update(name=name, student_id=sid, enabled=data.get('enabled') is True)
            credentials_changed = False
            for k in ('password', 'fingerprint'):
                if data.get('clear_' + k):
                    a[k] = ''
                    credentials_changed = True
                elif data.get(k):
                    value = str(data[k])
                    if len(value) > 4096 or '\r' in value or '\n' in value:
                        raise ValueError('凭据格式不正确')
                    a[k] = value if k == 'password' else value.strip()
                    credentials_changed = True
            if credentials_changed:
                a['cookies'] = []
            a.pop('session_cookie', None)
            a.pop('address', None)
            if a.get('fingerprint') and not re.fullmatch(r'[0-9a-fA-F]{32}', a['fingerprint']):
                raise ValueError('可信浏览器指纹需要 32 位十六进制字符')
            if not a.get('password'):
                raise ValueError('请填写学校密码。')
            mode = data.get('location_mode', 'manual')
            if mode not in ('manual', 'preset'):
                raise ValueError('请选择系统预设或手动填写')
            a.update(location_mode=mode, preset_id=str(data.get('preset_id', '')) if mode == 'preset' else '')
            loc = store.resolve_location(a) if mode == 'preset' else data
            for key, low, high in (('latitude', -90, 90), ('longitude', -180, 180), ('accuracy', 0, 100000)):
                try:
                    value = float(loc.get(key, 50 if key == 'accuracy' else ''))
                except (TypeError, ValueError):
                    raise ValueError('请输入有效坐标和精度') from None
                if not math.isfinite(value) or not low <= value <= high:
                    raise ValueError('坐标或精度超出有效范围')
                a[key] = value
            if loc.get('coordinate_system', 'gcj02') not in ('gcj02', 'wgs84'):
                raise ValueError('坐标系不正确')
            # Browser coordinates are WGS84. Client converts them to GCJ02 before saving.
            a.update(coordinate_system=loc.get('coordinate_system', 'gcj02'), browser_location=mode == 'manual' and data.get('browser_location') is True, location_duration_ms=min(max(int(data.get('location_duration_ms') or 0), 0), 600000) if mode == 'manual' else 0)
            a['state'].pop('blocked_date', None)
            store.save_account(a)
        return jsonify(ok=True, id=a['id'])

    @app.delete('/api/accounts/<aid>')
    def delete_account(aid):
        with mutation():
            owned(aid)
            store.delete(aid)
        return jsonify(ok=True)

    @app.post('/api/settings')
    def settings():
        d = request.get_json() or {}
        cfg = dict(DEFAULT_SETTINGS)
        for k in ('time', 'window_end'):
            v = str(d.get(k, cfg[k]))
            if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', v):
                raise ValueError('时间格式需要为 HH:MM')
            cfg[k] = v
        cfg['window_start'] = preparation_start(cfg['time'])
        if minutes(cfg['time']) >= minutes(cfg['window_end']):
            raise ValueError('最晚重试时间需要晚于打卡时间。')
        cfg['enabled'] = d.get('enabled') is True
        for k, low, high in (('retry_minutes', 3, 60), ('max_attempts', 1, 30), ('time_jitter_seconds',0,300), ('location_jitter_meters',0,10)):
            try:
                cfg[k] = int(d.get(k, cfg[k]))
            except (ValueError, TypeError):
                raise ValueError('重试设置需要为整数') from None
            if not low <= cfg[k] <= high:
                raise ValueError('重试间隔为 3–60 分钟、次数为 1–30；时间浮动为 0–300 秒、位置浮动为 0–10 米。')
        with mutation():
            store.user_settings(g.user['id'], cfg)
        return jsonify(ok=True)

    @app.post('/api/accounts/<aid>/<action>')
    def run(aid, action):
        owned(aid)
        d = request.get_json(silent=True) or {}
        if action == 'checkin' and d.get('confirm') is not True:
            raise ValueError('请确认提交真实打卡')
        service.enqueue(aid, action)
        return jsonify(ok=True, message='任务已开始'), 202

    @app.get('/api/history.csv')
    def export():
        out = io.StringIO(newline='')
        writer = csv.writer(out)
        writer.writerow(['时间', '账号备注', '操作', '结果', '说明'])
        for r in store.events(10000, owner_id=g.user['id']):
            values = [r[k] for k in ('at', 'name', 'action', 'outcome', 'message')]
            writer.writerow(["'" + v if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@')) else v for v in values])
        return Response('\ufeff' + out.getvalue(), mimetype='text/csv; charset=utf-8', headers={'Content-Disposition': 'attachment; filename=mooncheck-history.csv'})

    @app.get('/api/admin/state')
    def admin_state():
        users = store.users()
        accounts = store.accounts()
        for u in users:
            u['account_count'] = sum(a['owner_id'] == u['id'] for a in accounts)
        return jsonify(users=users, presets=store.presets(), registration_enabled=store.get('registration_enabled', True))

    @app.post('/api/admin/registration')
    def registration():
        with mutation():
            store.set('registration_enabled', (request.get_json() or {}).get('enabled') is True)
        return jsonify(ok=True)

    @app.post('/api/admin/users/<uid>/active')
    def active_user(uid):
        with mutation():
            target = store.user(uid=uid)
            if not target:
                abort(404)
            if target['role'] == 'superadmin':
                raise ValueError('总管理员不能被停用')
            store.set_user_active(uid, (request.get_json() or {}).get('active') is True)
        return jsonify(ok=True)

    @app.post('/api/admin/presets')
    def presets():
        d = request.get_json() or {}
        name = str(d.get('name', '')).strip()
        if not 1 <= len(name) <= 60:
            raise ValueError('预设名称需要 1–60 个字符')
        p = {'id': str(d.get('id') or secrets.token_hex(12)), 'name': name, 'enabled': d.get('enabled') is True, 'coordinate_system': d.get('coordinate_system', 'gcj02')}
        if p['coordinate_system'] not in ('gcj02', 'wgs84'):
            raise ValueError('坐标系不正确')
        for k, low, high in (('latitude',-90,90),('longitude',-180,180),('accuracy',0,100000)):
            try:
                v = float(d.get(k,50 if k == 'accuracy' else ''))
            except (TypeError, ValueError):
                raise ValueError('请输入有效经纬度和精度') from None
            if not math.isfinite(v) or not low <= v <= high:
                raise ValueError('坐标或精度超出有效范围')
            p[k] = v
        with mutation():
            if d.get('id') and not any(x['id'] == p['id'] for x in store.presets()):
                abort(404)
            store.save_preset(p)
        return jsonify(ok=True, id=p['id'])

    if start_scheduler:
        service.start()
    return app

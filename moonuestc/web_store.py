"""Dashboard records, identity, ownership checks and durable background jobs."""
import contextlib
import copy
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError,InvalidHashError

from .errors import ToolError
from .diagnostics import ACTIONS,error_details,school_message,submission_details,verification_details
from .locations import DEFAULT_PRESET_ID,location_details,upgrade_group3_location
from .policy import build_payload,clock_minutes,now,validate_config
from .runner import account_key,cookie_path
from .state import State
from .vault import Vault
from .web_errors import WebError
from .daily_plan import normalize_variation,planned_time
from .scheduling import reserve_slot,slot_description,slot_target,retry_reservation
from .notice import VERSION as NOTICE_VERSION
from .school_policy import explain_result


def text(value,field,minimum=1,maximum=80):
    if not isinstance(value,str) or not minimum<=len(value.strip())<=maximum:
        raise WebError(400,'invalid_'+field,'请检查'+field+'的格式。')
    return value.strip()


def login_password(value):
    if not isinstance(value,str) or not 12<=len(value)<=128:
        raise WebError(400,'password_length','登录密码需要 12–128 个字符。')
    return value


def flag(value,field):
    if type(value) is not bool:
        raise WebError(400,'invalid_'+field,'开关参数必须为布尔值。')
    return value


def public_user(row):
    return {k:row[k] for k in ('id','username','display_name','role','created_at')} | {
        'active':bool(row['active']),'must_change_password':bool(row['must_change_password'])}


class WebStore:
    def __init__(self,directory,hasher=None):
        self.directory=Path(directory)
        self.vault=Vault(self.directory)
        self.require_notice=os.environ.get('MOON_REQUIRE_CONSENT','0')=='1'
        self.wechat_enabled=os.environ.get('MOON_ENABLE_WECHAT_AUTH','0')=='1'
        self.path=self.directory/'dashboard.sqlite3'
        self.hasher=hasher or PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
        self.allowed_presets=tuple(x.strip() for x in os.environ.get('MOON_ALLOWED_PRESETS','').split(',') if x.strip())
        self.execution_window=tuple(os.environ.get('MOON_RUN_WINDOW','').split(',')) if os.environ.get('MOON_RUN_WINDOW') else None
        if self.execution_window:
            if len(self.execution_window)!=2 or clock_minutes(self.execution_window[0])>=clock_minutes(self.execution_window[1]):raise ValueError('Invalid execution window')
        self.dummy_hash=self.hasher.hash(secrets.token_urlsafe(24))
        with self.db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS web_users(
                    id INTEGER PRIMARY KEY, username TEXT NOT NULL, username_key TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','user')), active INTEGER NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS web_sessions(
                    token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
                    csrf TEXT NOT NULL,created_at REAL NOT NULL,last_seen REAL NOT NULL,expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS web_accounts(
                    id TEXT PRIMARY KEY,owner_id INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
                    label TEXT NOT NULL,student_digest TEXT UNIQUE NOT NULL,payload BLOB NOT NULL,
                    enabled INTEGER NOT NULL,automatic INTEGER NOT NULL,run_at TEXT NOT NULL,
                    created_at REAL NOT NULL,updated_at REAL NOT NULL,last_result TEXT,last_run_at REAL);
                CREATE TABLE IF NOT EXISTS web_jobs(
                    id TEXT PRIMARY KEY,account_id TEXT REFERENCES web_accounts(id) ON DELETE CASCADE,
                    requested_by INTEGER REFERENCES web_users(id) ON DELETE SET NULL,
                    mode TEXT NOT NULL,source TEXT NOT NULL,business_date TEXT NOT NULL,
                    state TEXT NOT NULL,result TEXT,created_at REAL NOT NULL,started_at REAL,finished_at REAL);
                CREATE UNIQUE INDEX IF NOT EXISTS web_scheduled_once ON web_jobs(account_id,business_date) WHERE source='schedule';
                CREATE INDEX IF NOT EXISTS web_jobs_state ON web_jobs(state,created_at);
                CREATE TABLE IF NOT EXISTS web_login_limits(bucket TEXT PRIMARY KEY,count INTEGER NOT NULL,reset_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS web_cookies(binding TEXT PRIMARY KEY,payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS web_audit(id INTEGER PRIMARY KEY,actor_id INTEGER,event TEXT,target TEXT,created_at REAL);
                CREATE TABLE IF NOT EXISTS web_migrations(name TEXT PRIMARY KEY,applied_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS web_job_diagnostics(job_id TEXT PRIMARY KEY REFERENCES web_jobs(id) ON DELETE CASCADE,payload TEXT NOT NULL,updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS portal_bindings(user_id INTEGER PRIMARY KEY REFERENCES web_users(id) ON DELETE CASCADE,
                    student_digest TEXT UNIQUE NOT NULL,account_id TEXT UNIQUE NOT NULL REFERENCES web_accounts(id) ON DELETE CASCADE,verified_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS portal_access_grants(student_digest TEXT PRIMARY KEY,payload BLOB NOT NULL,
                    created_at REAL NOT NULL,created_by INTEGER REFERENCES web_users(id) ON DELETE SET NULL);
                CREATE TABLE IF NOT EXISTS web_schedule_slots(account_id TEXT PRIMARY KEY REFERENCES web_accounts(id) ON DELETE CASCADE,minute INTEGER NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS web_schedule_retries(job_id TEXT PRIMARY KEY REFERENCES web_jobs(id) ON DELETE CASCADE,business_date TEXT NOT NULL,minute INTEGER NOT NULL,UNIQUE(business_date,minute));
                CREATE TABLE IF NOT EXISTS portal_notices(user_id INTEGER PRIMARY KEY REFERENCES web_users(id) ON DELETE CASCADE,version TEXT NOT NULL,accepted_at REAL NOT NULL);
            ''')
            columns={r[1] for r in db.execute('PRAGMA table_info(web_jobs)')}
            if 'attempt' not in columns:db.execute('ALTER TABLE web_jobs ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0')
            if 'available_at' not in columns:db.execute('ALTER TABLE web_jobs ADD COLUMN available_at REAL NOT NULL DEFAULT 0')
            if 'execute_before' not in columns:db.execute('ALTER TABLE web_jobs ADD COLUMN execute_before REAL NOT NULL DEFAULT 0')
            if 'business_date' not in {r[1] for r in db.execute('PRAGMA table_info(web_schedule_slots)')}:db.execute("ALTER TABLE web_schedule_slots ADD COLUMN business_date TEXT NOT NULL DEFAULT ''")
        self._upgrade_group3_accounts()
        self._sync_student_labels()
        self._upgrade_variation_radius()
        self.ensure_slots()

    def _upgrade_variation_radius(self):
        with self.db(True) as db:
            name='daily_radius_10m_v1'
            if db.execute('SELECT 1 FROM web_migrations WHERE name=?',(name,)).fetchone():return
            stamp=time.time()
            for row in db.execute('SELECT * FROM web_accounts').fetchall():
                payload=self._payload(row);variation=normalize_variation(payload.get('variation'))
                if 0<variation['meters']<10:
                    payload['variation']={**variation,'meters':10}
                    db.execute('UPDATE web_accounts SET payload=?,updated_at=? WHERE id=?',(self.vault.seal(payload,'account:'+row['id']),stamp,row['id']))
            db.execute('INSERT INTO web_migrations VALUES(?,?)',(name,stamp))

    def ensure_slots(self,day=None):
        if not self.execution_window:return
        day=day or now().date().isoformat()
        with self.db(True) as db:
            rows=db.execute('SELECT * FROM web_accounts ORDER BY created_at,id').fetchall()
            for row in rows:reserve_slot(db,row['id'],row['run_at'],self.execution_window,school=(json.loads(row['last_result']) if row['last_result'] else {}).get('checkinWindow'),account=self._payload(row),day=day)

    def _sync_student_labels(self):
        with self.db(True) as db:
            migration='student_label_matches_name_v1'
            if db.execute('SELECT 1 FROM web_migrations WHERE name=?',(migration,)).fetchone():return
            db.execute("UPDATE web_accounts SET label=(SELECT u.display_name FROM web_users u WHERE u.id=web_accounts.owner_id) WHERE owner_id IN (SELECT id FROM web_users WHERE role='user')")
            db.execute('INSERT INTO web_migrations VALUES(?,?)',(migration,time.time()))

    def _upgrade_group3_accounts(self):
        # One atomic transaction; keep IDs, password hashes, account secrets,
        # ownership, schedules, cookies and verification state unchanged.
        migration='group3_gcj02_v050'
        with self.db(True) as db:
            if db.execute('SELECT 1 FROM web_migrations WHERE name=?',(migration,)).fetchone():
                return
            for row in db.execute('SELECT * FROM web_accounts').fetchall():
                payload=self._payload(row)
                old=payload.get('location')
                updated=upgrade_group3_location(old,migrate_named=True)
                if old==updated:
                    continue
                payload['location']=updated
                db.execute('UPDATE web_accounts SET payload=? WHERE id=?',
                           (self.vault.seal(payload,'account:'+row['id']),row['id']))
                self._audit(db,None,'account_location_migrated',row['id'])
            db.execute('INSERT INTO web_migrations VALUES(?,?)',(migration,time.time()))

    @contextlib.contextmanager
    def db(self,write=False):
        db=sqlite3.connect(str(self.path),timeout=15)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        try:
            if write: db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except Exception:
            db.rollback(); raise
        finally: db.close()

    def _audit(self,db,actor,event,target):
        db.execute('INSERT INTO web_audit(actor_id,event,target,created_at) VALUES(?,?,?,?)',
                   (actor['id'] if actor else None,event,str(target),time.time()))

    def initialized(self):
        with self.db() as db:
            return db.execute('SELECT 1 FROM web_users LIMIT 1').fetchone() is not None

    def create_user(self,actor,data,bootstrap=False):
        if not bootstrap and (actor is None or actor['role']!='admin'):
            raise WebError(403,'admin_required','需要管理员权限。')
        if not isinstance(data,dict) or set(data)-{'username','display_name','password','role','active'}:
            raise WebError(400,'invalid_fields','用户参数不正确。')
        username=text(data.get('username'),'用户名',3,48)
        if not re.fullmatch(r'[\w.@-]+',username):
            raise WebError(400,'invalid_username','用户名可用中英文、数字、点、短横线或下划线。')
        display=text(data.get('display_name',username),'显示名称',1,60)
        role=data.get('role','user')
        if role not in ('admin','user') or (bootstrap and role!='admin'):
            raise WebError(400,'invalid_role','角色不正确。')
        active=flag(data.get('active',True),'active')
        encoded=self.hasher.hash(login_password(data.get('password')))
        with self.db(True) as db:
            if bootstrap and db.execute('SELECT 1 FROM web_users LIMIT 1').fetchone():
                raise WebError(409,'already_initialized','管理员已经初始化，不能再次创建初始管理员。')
            try:
                cur=db.execute('INSERT INTO web_users(username,username_key,display_name,password_hash,role,active,must_change_password,created_at) VALUES(?,?,?,?,?,?,?,?)',
                    (username,username.casefold(),display,encoded,role,int(active),int(not bootstrap),time.time()))
            except sqlite3.IntegrityError:
                raise WebError(409,'username_exists','用户名已存在。') from None
            row=db.execute('SELECT * FROM web_users WHERE id=?',(cur.lastrowid,)).fetchone()
            self._audit(db,actor,'user_created',row['id'])
            return public_user(row)

    def _verify(self,encoded,password):
        try: return bool(self.hasher.verify(encoded,password))
        except (VerificationError,InvalidHashError,TypeError): return False

    def login(self,username,password,remote_ip,admin_only=False):
        username=username if isinstance(username,str) else ''
        password=password if isinstance(password,str) and len(password)<=128 else ''
        buckets=[(self.vault.digest('login_user',username.casefold()),8),
                 (self.vault.digest('login_ip',remote_ip),40)]
        stamp=time.time()
        with self.db(True) as db:
            for bucket,limit in buckets:
                row=db.execute('SELECT * FROM web_login_limits WHERE bucket=?',(bucket,)).fetchone()
                if row and row['reset_at']>stamp and row['count']>=limit:
                    raise WebError(429,'login_rate_limited','尝试次数过多，请 15 分钟后再试。')
            user=db.execute('SELECT * FROM web_users WHERE username_key=?',(username.casefold(),)).fetchone()
            # Reserve attempts atomically before Argon2; simultaneous requests
            # must not bypass the rate limit while password checks are running.
            for bucket,_ in buckets:
                db.execute('INSERT INTO web_login_limits VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN reset_at<=? THEN 1 ELSE count+1 END, reset_at=CASE WHEN reset_at<=? THEN ? ELSE reset_at END',
                           (bucket,stamp+900,stamp,stamp,stamp+900))
        valid=self._verify(user['password_hash'] if user else self.dummy_hash,password)
        if not valid or not user or not user['active'] or (admin_only and user['role']!='admin'):
            raise WebError(401,'invalid_credentials','用户名或密码不正确。')
        token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
        with self.db(True) as db:
            current=db.execute('SELECT * FROM web_users WHERE id=?',(user['id'],)).fetchone()
            if not current or not current['active'] or current['password_hash']!=user['password_hash']:
                raise WebError(401,'invalid_credentials','用户名或密码不正确。')
            db.execute('DELETE FROM web_login_limits WHERE bucket=?',(buckets[0][0],))
            db.execute('DELETE FROM web_sessions WHERE expires_at<? OR last_seen<?',(stamp,stamp-1800))
            db.execute('INSERT INTO web_sessions VALUES(?,?,?,?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(),user['id'],csrf,stamp,stamp,stamp+43200))
            self._audit(db,user,'login',user['id'])
        return token,csrf,public_user(user)

    def session(self,token):
        if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,100}',token): return None
        digest=hashlib.sha256(token.encode()).hexdigest()
        stamp=time.time()
        with self.db(True) as db:
            row=db.execute('SELECT s.*,u.username,u.display_name,u.role,u.active,u.must_change_password,u.id AS id,u.created_at AS user_created FROM web_sessions s JOIN web_users u ON u.id=s.user_id WHERE s.token_hash=?',(digest,)).fetchone()
            if not row or not row['active'] or row['expires_at']<stamp or row['last_seen']<stamp-1800:
                db.execute('DELETE FROM web_sessions WHERE token_hash=?',(digest,)); return None
            db.execute('UPDATE web_sessions SET last_seen=? WHERE token_hash=?',(stamp,digest))
            user={'id':row['user_id'],'username':row['username'],'display_name':row['display_name'],
                  'role':row['role'],'active':True,'must_change_password':bool(row['must_change_password']),
                  'created_at':row['user_created']}
            return user,row['csrf']

    def logout(self,token):
        if token:
            with self.db(True) as db:
                db.execute('DELETE FROM web_sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))

    def change_password(self,user,current,new):
        encoded=self.hasher.hash(login_password(new))
        with self.db(True) as db:
            row=db.execute('SELECT * FROM web_users WHERE id=?',(user['id'],)).fetchone()
            if not self._verify(row['password_hash'],current):
                raise WebError(403,'wrong_current_password','当前密码不正确。')
            db.execute('UPDATE web_users SET password_hash=?,must_change_password=0 WHERE id=?',(encoded,user['id']))
            db.execute('DELETE FROM web_sessions WHERE user_id=?',(user['id'],))
            self._audit(db,user,'password_changed',user['id'])

    def users(self):
        with self.db() as db:
            return [public_user(r) for r in db.execute('SELECT * FROM web_users ORDER BY id')]

    def update_user(self,actor,user_id,data):
        if actor['role']!='admin': raise WebError(403,'admin_required','需要管理员权限。')
        if not isinstance(data,dict) or set(data)-{'display_name','role','active','password'}:
            raise WebError(400,'invalid_fields','用户参数不正确。')
        encoded=self.hasher.hash(login_password(data['password'])) if data.get('password') else None
        with self.db(True) as db:
            row=db.execute('SELECT * FROM web_users WHERE id=?',(user_id,)).fetchone()
            if not row: raise WebError(404,'not_found','用户不存在。')
            role=data.get('role',row['role'])
            active=flag(data.get('active',bool(row['active'])),'active')
            if role not in ('admin','user'): raise WebError(400,'invalid_role','角色不正确。')
            if row['role']=='admin' and row['active'] and (role!='admin' or not active):
                if db.execute("SELECT COUNT(*) FROM web_users WHERE role='admin' AND active=1").fetchone()[0]<=1:
                    raise WebError(409,'last_admin','至少需要保留一位启用的管理员。')
            display=text(data.get('display_name',row['display_name']),'显示名称',1,60)
            db.execute('UPDATE web_users SET display_name=?,role=?,active=? WHERE id=?',(display,role,int(active),user_id))
            if role=='user':db.execute('UPDATE web_accounts SET label=? WHERE owner_id=?',(display,user_id))
            if encoded:
                db.execute('UPDATE web_users SET password_hash=?,must_change_password=1 WHERE id=?',(encoded,user_id))
            if encoded or not active or role!=row['role']:
                db.execute('DELETE FROM web_sessions WHERE user_id=?',(user_id,))
            self._audit(db,actor,'user_updated',user_id)
            return public_user(db.execute('SELECT * FROM web_users WHERE id=?',(user_id,)).fetchone())

    def reset_password_local(self,username,password):
        encoded=self.hasher.hash(login_password(password))
        with self.db(True) as db:
            row=db.execute('SELECT * FROM web_users WHERE username_key=?',(username.casefold(),)).fetchone()
            if not row: raise WebError(404,'not_found','用户不存在。')
            db.execute('UPDATE web_users SET password_hash=?,must_change_password=0 WHERE id=?',(encoded,row['id']))
            db.execute('DELETE FROM web_sessions WHERE user_id=?',(row['id'],))
            self._audit(db,None,'local_password_reset',row['id'])

    def _row(self,db,actor,account_id):
        row=db.execute('SELECT a.*,u.username AS owner_username,u.display_name AS owner_name,u.active AS owner_active,u.role AS owner_role FROM web_accounts a JOIN web_users u ON u.id=a.owner_id WHERE a.id=?',(account_id,)).fetchone()
        if not row or (actor['role']!='admin' and row['owner_id']!=actor['id']):
            raise WebError(404,'not_found','打卡账号不存在。')
        return row

    def _busy(self,db,account_id):
        return db.execute("SELECT 1 FROM web_jobs WHERE account_id=? AND state IN ('queued','running')",(account_id,)).fetchone() is not None

    def _payload(self,row): return self.vault.open(row['payload'],'account:'+row['id'])

    def location_open(self,payload):
        return not self.allowed_presets or (isinstance(payload.get('location'),dict) and payload['location'].get('mode')=='preset' and payload['location'].get('preset') in self.allowed_presets)

    def _configuration_revision(self,row,payload):
        # Grant rotation and run results are independent of editable configuration.
        # Keep credential/config values opaque while detecting actual form conflicts.
        configuration={key:row[key] for key in ('id','owner_id','label','enabled','automatic','run_at')}
        configuration.update({key:payload.get(key) for key in ('student_id','password','browser_fingerprint',
            'user_agent','browser_profile','location','variation_seed')})
        configuration['variation']=normalize_variation(payload.get('variation'))
        return self.vault.digest('account_configuration',json.dumps(configuration,sort_keys=True,separators=(',',':')))

    def _public_account(self,row):
        payload=self._payload(row)
        from .wechat_authorization import authorization_summary
        wechat=authorization_summary(payload)
        state=State(self.directory)
        try:
            ready=state.ready(account_key(payload))
            claim=state.db.execute('SELECT outcome FROM claims WHERE account=? AND day=?',
                                   (account_key(payload),now().date().isoformat())).fetchone()
            confirmed_today=bool(claim and claim[0]=='confirmed')
            auth_reason=state.auth_requirement(account_key(payload))
            checkin_reason=state.school_client_requirement()
        finally: state.close()
        variation=normalize_variation(payload.get('variation'))
        last=explain_result(json.loads(row['last_result'])) if row['last_result'] else None
        school_window=(last or {}).get('checkinWindow')
        try:target=planned_time(payload,row['run_at'],now().date().isoformat(),self.execution_window,school_window)
        except (ToolError,KeyError,ValueError):target=None
        with self.db() as db:
            reservation=db.execute('SELECT minute FROM web_schedule_slots WHERE account_id=?',(row['id'],)).fetchone()
            verified=db.execute('SELECT verified_at FROM portal_bindings WHERE account_id=?',(row['id'],)).fetchone()
            today_job=db.execute("SELECT id,state,source,result,created_at FROM web_jobs WHERE account_id=? AND business_date=? AND mode='checkin' ORDER BY created_at DESC,id DESC LIMIT 1",(row['id'],now().date().isoformat())).fetchone()
        today_result=explain_result(json.loads(today_job['result'])) if today_job and today_job['result'] else None
        recorded_today=confirmed_today or bool(today_result and today_result.get('result') in ('confirmed','already_recorded') and today_result.get('status') in ('CHECKED_IN','EXEMPT','STUDENT_REPORTED','INSTRUCTOR_REPORTED'))
        if not auth_reason and row['last_run_at'] and row['last_run_at']>=(verified[0] if verified else 0) and (last or {}).get('reason') in ('need_manual_captcha','need_manual_mfa','login_rejected','daily_login_limit','school_sync_login_required'):
            auth_reason=last['reason']
        if self.execution_window:target=slot_target(payload,now().date().isoformat(),reservation[0]) if reservation else None
        return {'id':row['id'],'owner_id':row['owner_id'],'owner_name':row['owner_name'],'owner_username':row['owner_username'],
                'label':row['label'],'student_id':payload['student_id'],'enabled':bool(row['enabled']),
                'automatic':bool(row['automatic']),'run_at':row['run_at'],'user_agent':payload['user_agent'],
                'configuration_revision':self._configuration_revision(row,payload),
                'location':payload.get('location'),'has_password':bool(payload.get('password')),
                'has_browser_fingerprint':bool(payload.get('browser_fingerprint')),'ready_for_automation':ready,
                'confirmed_today':confirmed_today,
                'recorded_today':recorded_today,'business_date':now().date().isoformat(),'server_time':now().timestamp(),
                'today_job':({'id':today_job['id'],'state':today_job['state'],'source':today_job['source'],'result':today_result,'created_at':today_job['created_at']} if today_job else None),
                'variation':variation,'planned_run_at':target,'location_open':self.location_open(payload),'execution_window':self.execution_window,
                'schedule_slot':slot_description(reservation[0]) if reservation else None,
                'school_auth_required':bool(auth_reason),'school_auth_reason':auth_reason,
                'school_checkin_required':(not wechat['eligible']) if self.wechat_enabled else bool(checkin_reason),
                'wechat_auth_enabled':self.wechat_enabled,'wechat_authorization':wechat,
                'hosting_notice_accepted':self.notice_accepted({'id':row['owner_id'],'role':row['owner_role']}),'hosting_notice_required':self.require_notice,
                'configuration_checked':bool(row['last_run_at'] and row['last_run_at']>=row['updated_at'] and (last or {}).get('result') in ('dry_run_ready','confirmed')),
                'last_result':last,
                'last_run_at':row['last_run_at'],**location_details(payload)}

    def accounts(self,actor):
        self.ensure_slots()
        with self.db() as db:
            rows=db.execute('SELECT a.*,u.username AS owner_username,u.display_name AS owner_name,u.role AS owner_role FROM web_accounts a JOIN web_users u ON u.id=a.owner_id'+
                ('' if actor['role']=='admin' else ' WHERE a.owner_id=?')+' ORDER BY a.created_at',
                () if actor['role']=='admin' else (actor['id'],)).fetchall()
        return [self._public_account(r) for r in rows]

    def account(self,actor,account_id):
        with self.db() as db: row=self._row(db,actor,account_id)
        return self._public_account(row)

    def save_account(self,actor,data,account_id=None):
        allowed={'label','student_id','password','browser_fingerprint','user_agent','location','enabled','automatic','run_at','owner_id','variation','if_match'}
        if not isinstance(data,dict) or set(data)-allowed: raise WebError(400,'invalid_fields','账号参数不正确。')
        with self.db(True) as db:
            old=self._row(db,actor,account_id) if account_id else None
            if old and self._busy(db,account_id): raise WebError(409,'account_busy','账号正在排队或执行，请稍后编辑。')
            previous=self._payload(old) if old else {}
            if 'if_match' in data:
                revision=data['if_match']
                if not old or not isinstance(revision,str) or not re.fullmatch('[a-f0-9]{64}',revision):
                    raise WebError(400,'invalid_configuration_revision','配置版本无效，请刷新后重试。')
                if not secrets.compare_digest(revision,self._configuration_revision(old,previous)):
                    raise WebError(409,'configuration_changed','配置已在其他页面更新，请载入最新配置后再保存。')
            owner=data.get('owner_id',old['owner_id'] if old else actor['id'])
            if type(owner) is not int or (actor['role']!='admin' and owner!=actor['id']):
                raise WebError(403,'owner_forbidden','不能为其他用户管理账号。')
            target=db.execute('SELECT * FROM web_users WHERE id=?',(owner,)).fetchone()
            if not target or not target['active']: raise WebError(400,'invalid_owner','请选择已启用的所属用户。')
            if target['role']=='user' and db.execute('SELECT 1 FROM web_accounts WHERE owner_id=? AND id!=?',(owner,account_id or '')).fetchone():
                raise WebError(409,'single_account_required','每位普通用户只能绑定一个学校账号。')
            aid=account_id or uuid.uuid4().hex
            payload=copy.deepcopy(previous)
            for key in ('student_id','password','browser_fingerprint','user_agent','location'):
                if key in data:
                    if key in ('password','browser_fingerprint') and data[key]=='' and old: continue
                    payload[key]=copy.deepcopy(data[key])
            payload.setdefault('location',{'mode':'preset','preset':DEFAULT_PRESET_ID})
            try:payload['variation']=normalize_variation(data.get('variation',payload.get('variation')))
            except ToolError:raise WebError(400,'invalid_daily_variation','每日时间浮动最多 5 分钟，位置浮动最多 10 米。') from None
            if any(payload['variation'].values()):payload.setdefault('variation_seed',secrets.token_hex(32))
            if not self.location_open(payload):raise WebError(400,'location_not_open','目前只开放学知二组团和学知五组团，请重新选择位置。')
            linked=db.execute('SELECT 1 FROM portal_bindings WHERE account_id=?',(account_id or '',)).fetchone()
            if linked and (payload.get('student_id')!=previous.get('student_id') or owner!=old['owner_id']):
                raise WebError(409,'student_identity_locked','已验证的学号和所属用户不能直接修改。')
            if linked and actor['role']!='admin' and any(key in data and data[key] and data[key]!=previous.get(key) for key in ('password','browser_fingerprint','user_agent')):
                raise WebError(409,'school_verification_required','更新学校凭据请重新登录并通过学校验证。')
            payload['location']=upgrade_group3_location(payload['location'])
            payload['id']=aid; payload['enabled']=True
            try:
                validate_config({'version':1,'accounts':[payload]})
                build_payload(payload,now())
            except ToolError as error:
                raise WebError(400,error.reason,'请检查学号、凭据和位置配置：'+error.reason) from None
            label=text(data.get('label',old['label'] if old else '我的打卡账号'),'账号名称',1,64)
            if target['role']=='user':label=target['display_name']
            enabled=flag(data.get('enabled',bool(old['enabled']) if old else True),'enabled')
            automatic=flag(data.get('automatic',bool(old['automatic']) if old else False),'automatic')
            run_at=data.get('run_at',old['run_at'] if old else '22:00')
            try: clock_minutes(run_at)
            except ToolError: raise WebError(400,'invalid_run_time','请选择有效的每日执行时间。') from None
            if self.execution_window and not self.execution_window[0]<=run_at<=self.execution_window[1]:raise WebError(400,'invalid_run_time','每日时间须在 21:06–23:24 内。')
            if automatic:
                state=State(self.directory)
                try: ready=state.ready(account_key(payload))
                finally: state.close()
                if not ready: raise WebError(409,'first_verified_checkin_required','先用本工具完成一次经学校确认的手动打卡，再开启自动运行。')
            digest=self.vault.digest('student',payload['student_id'])
            encrypted=self.vault.seal(payload,'account:'+aid)
            stamp=time.time()
            try:
                if old:
                    db.execute('UPDATE web_accounts SET owner_id=?,label=?,student_digest=?,payload=?,enabled=?,automatic=?,run_at=?,updated_at=? WHERE id=?',
                        (owner,label,digest,encrypted,int(enabled),int(automatic),run_at,stamp,aid))
                    if cookie_path(self.directory,previous).name!=cookie_path(self.directory,payload).name:
                        db.execute('DELETE FROM web_cookies WHERE binding=?',(cookie_path(self.directory,previous).name,))
                    if linked and any(previous.get(k)!=payload.get(k) for k in ('password','browser_fingerprint','user_agent')):
                        db.execute('UPDATE portal_bindings SET verified_at=0 WHERE account_id=?',(aid,))
                else:
                    db.execute('INSERT INTO web_accounts(id,owner_id,label,student_digest,payload,enabled,automatic,run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                        (aid,owner,label,digest,encrypted,int(enabled),int(automatic),run_at,stamp,stamp))
            except sqlite3.IntegrityError:
                raise WebError(409,'student_exists','该学号已添加，请由管理员核对所属用户。') from None
            assigned=reserve_slot(db,aid,run_at,self.execution_window,replace=bool(old and (old['run_at']!=run_at or self._payload(old).get('variation')!=payload.get('variation'))),school=(json.loads(old['last_result']) if old and old['last_result'] else {}).get('checkinWindow'),account=payload,day=now().date().isoformat())
            if automatic and self.execution_window and assigned is None:raise WebError(409,'schedule_slots_full','偏好时间附近没有空闲时段，请调整时间后再开启每日计划。')
            self._audit(db,actor,'account_updated' if old else 'account_created',aid)
        return self.account(actor,aid)

    def delete_account(self,actor,account_id):
        with self.db(True) as db:
            row=self._row(db,actor,account_id)
            if self._busy(db,account_id): raise WebError(409,'account_busy','账号正在排队或执行，请稍后删除。')
            payload=self._payload(row)
            if db.execute('SELECT 1 FROM portal_bindings WHERE account_id=?',(account_id,)).fetchone():
                db.execute('DELETE FROM web_sessions WHERE user_id=?',(row['owner_id'],))
            db.execute('DELETE FROM web_cookies WHERE binding=?',(cookie_path(self.directory,payload).name,))
            db.execute('DELETE FROM web_accounts WHERE id=?',(account_id,))
            self._audit(db,actor,'account_deleted',account_id)

    def delete_user(self,actor,user_id):
        if actor['role']!='admin': raise WebError(403,'admin_required','需要管理员权限。')
        if actor['id']==user_id: raise WebError(409,'cannot_delete_self','不能删除当前登录的用户。')
        with self.db(True) as db:
            row=db.execute('SELECT * FROM web_users WHERE id=?',(user_id,)).fetchone()
            if not row: raise WebError(404,'not_found','用户不存在。')
            if row['role']=='admin' and row['active'] and db.execute("SELECT COUNT(*) FROM web_users WHERE role='admin' AND active=1").fetchone()[0]<=1:
                raise WebError(409,'last_admin','至少需要保留一位启用的管理员。')
            accounts=db.execute('SELECT * FROM web_accounts WHERE owner_id=?',(user_id,)).fetchall()
            for account in accounts:
                if self._busy(db,account['id']): raise WebError(409,'account_busy','该用户仍有执行中的任务，请稍后删除。')
                db.execute('DELETE FROM web_cookies WHERE binding=?',(cookie_path(self.directory,self._payload(account)).name,))
            db.execute('DELETE FROM web_users WHERE id=?',(user_id,))
            self._audit(db,actor,'user_deleted',user_id)

    def cookie_load(self,binding):
        with self.db() as db: row=db.execute('SELECT payload FROM web_cookies WHERE binding=?',(binding,)).fetchone()
        return self.vault.open(row['payload'],'cookie:'+binding) if row else None

    def cookie_save(self,binding,values):
        with self.db(True) as db:
            db.execute('INSERT OR REPLACE INTO web_cookies VALUES(?,?)',(binding,self.vault.seal(values,'cookie:'+binding)))

    def enqueue(self,actor,account_id,mode,source='manual',business_date=None,*,available_at=0,execute_before=0):
        if mode not in ('diagnose','prepare','checkin'): raise WebError(400,'invalid_mode','任务类型不正确。')
        day=business_date or now().date().isoformat()
        with self.db(True) as db:
            row=self._row(db,actor,account_id)
            if not row['enabled'] or not row['owner_active']: raise WebError(409,'account_disabled','账号或所属用户已停用。')
            if self._busy(db,account_id): raise WebError(409,'account_busy','该账号已有排队或执行中的任务。')
            if db.execute("SELECT COUNT(*) FROM web_jobs WHERE state IN ('queued','running')").fetchone()[0]>=500:
                raise WebError(429,'queue_full','队列已满，请稍后重试。')
            recent=db.execute('SELECT created_at FROM web_jobs WHERE account_id=? ORDER BY created_at DESC LIMIT 1',(account_id,)).fetchone()
            if source=='manual' and recent and time.time()-recent['created_at']<20:
                raise WebError(429,'job_cooldown','同一账号的操作间隔至少 20 秒，请稍后重试。')
            jid=uuid.uuid4().hex
            try:
                db.execute('INSERT INTO web_jobs(id,account_id,requested_by,mode,source,business_date,state,created_at,available_at,execute_before) VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (jid,account_id,actor['id'],mode,source,day,'queued',time.time(),available_at,execute_before))
            except sqlite3.IntegrityError:
                raise WebError(409,'already_scheduled','当天已经安排过自动任务。') from None
            self._audit(db,actor,'job_queued',jid)
        return jid

    def jobs(self,actor,job_id=None,*,since=None,before=None,limit=100):
        sql="SELECT j.*,a.label,a.owner_id,u.display_name AS owner_name,d.payload AS diagnostic_payload,(SELECT count(*) FROM web_jobs q WHERE q.state IN ('queued','running') AND (max(q.available_at,q.created_at)<max(j.available_at,j.created_at) OR (max(q.available_at,q.created_at)=max(j.available_at,j.created_at) AND q.id<=j.id))) AS queue_position FROM web_jobs j JOIN web_accounts a ON a.id=j.account_id JOIN web_users u ON u.id=a.owner_id LEFT JOIN web_job_diagnostics d ON d.job_id=j.id"
        where=[]; params=[]
        if actor['role']!='admin': where.append('a.owner_id=?'); params.append(actor['id'])
        if job_id: where.append('j.id=?'); params.append(job_id)
        if since is not None:where.append('j.created_at>=?');params.append(since)
        if before is not None:
            where.append('(j.created_at<? OR (j.created_at=? AND j.id<?))');params.extend((before[0],before[0],before[1]))
        if where: sql+=' WHERE '+' AND '.join(where)
        with self.db() as db: rows=db.execute(sql+' ORDER BY j.created_at DESC,j.id DESC LIMIT ?',params+[limit]).fetchall()
        result=[]
        for r in rows:
            result.append({key:r[key] for key in ('id','account_id','label','owner_name','mode','source','business_date','state','created_at','started_at','finished_at','attempt','available_at','execute_before')} |
                          {'queue_position':r['queue_position'] if r['state']=='queued' else None,'result':explain_result(json.loads(r['result'])) if r['result'] else None,'diagnostics':json.loads(r['diagnostic_payload']) if r['diagnostic_payload'] else None})
        if job_id and not result: raise WebError(404,'not_found','任务不存在。')
        return result[0] if job_id else result

    def job_history(self,actor,cursor=None):
        from .job_history import PAGE_SIZE,recent_start,encode_cursor,decode_cursor
        cutoff=recent_start(now());before=decode_cursor(cursor) if cursor is not None else None
        rows=self.jobs(actor,since=cutoff if before is None else None,before=before,limit=PAGE_SIZE)
        boundary=(rows[-1]['created_at'],rows[-1]['id']) if rows else before or (cutoff,'')
        more=bool(self.jobs(actor,before=boundary,limit=1))
        return {'jobs':rows,'next_cursor':encode_cursor(*boundary) if more else None,'recent_since':cutoff}

    def record_job_event(self,job,event,values,account=None):
        if event not in ('run_started','submission_action','submission_result','verification','run_error','geocode'):return
        with self.db(True) as db:
            row=db.execute('SELECT payload FROM web_job_diagnostics WHERE job_id=?',(job['id'],)).fetchone()
            value=json.loads(row['payload']) if row else {'action':'not_submitted','submission':None,'verification':[]}
            if event=='geocode':
                if values.get('source') in ('cache','school','cached_after_failure') and type(values.get('attempts')) is int and 0<=values['attempts']<=2:
                    value['addressLookup']={'source':values['source'],'attempts':values['attempts']}
            elif event=='submission_action':
                action=values.get('action')
                if isinstance(action,str) and action in ACTIONS:value['action']=action
                value['submission']=submission_details(values.get('submission'),account)
                if type(values.get('priorAttempt')) is bool:value['priorAttempt']=values['priorAttempt']
            elif event=='submission_result':value['submission']=submission_details(values.get('submission'),account)
            elif event=='verification':
                observation=verification_details(values.get('observation'),account)
                if observation:value['verification']=(value.get('verification',[])+[observation])[-4:]
            elif event=='run_error':
                error=values.get('error')
                if isinstance(error,ToolError):value['error']=error_details(error,account)
            db.execute('INSERT INTO web_job_diagnostics VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at',
                       (job['id'],json.dumps(value,ensure_ascii=False,allow_nan=False),time.time()))
        if (event=='submission_result' and (value.get('submission') or {}).get('outcome')!='accepted') or event=='run_error':
            safe={'jobId':job['id'],'event':event,'action':value['action']}
            safe['submission' if event=='submission_result' else 'error']=value.get('submission' if event=='submission_result' else 'error')
            logging.getLogger('moonuestc.diagnostics').warning('School diagnostic %s',json.dumps(safe,ensure_ascii=False,allow_nan=False))

    def claim_job(self):
        with self.db(True) as db:
            row=db.execute("SELECT * FROM web_jobs WHERE state='queued' AND available_at<=? ORDER BY max(available_at,created_at),created_at,id LIMIT 1",(time.time(),)).fetchone()
            if not row: return None
            db.execute("UPDATE web_jobs SET state='running',started_at=? WHERE id=?",(time.time(),row['id']))
            return dict(row)

    def job_payload(self,job):
        with self.db() as db:
            row=db.execute('SELECT a.*,u.active AS owner_active,u.role AS owner_role FROM web_accounts a JOIN web_users u ON u.id=a.owner_id WHERE a.id=?',(job['account_id'],)).fetchone()
        if not row or not row['enabled'] or not row['owner_active']:
            raise WebError(409,'account_disabled','账号或用户已停用。')
        if self.require_notice and not self.notice_accepted({'id':row['owner_id'],'role':row['owner_role']}):raise WebError(428,'privacy_consent_required','用户尚未确认当前托管说明，未联系学校。')
        payload=self._payload(row)
        payload['_allowed_presets']=self.allowed_presets
        payload['_execution_window']=self.execution_window
        if job.get('execute_before'):payload['_job_deadline']=job['execute_before']
        return payload

    def finish_job(self,job,result):
        safe_keys={'result','reason','stage','apiCode','businessDate','status','abnormalFlag','checkinWindow','locationConfigured','payloadConfigured','locationSource','locationName','presetId','inputCoordinateSystem','outputCoordinateSystem','coordinateConversion','httpStatus','schoolMessage','submissionAction','priorAttempt','submission','verification','retryExhausted','retryUnavailable','retryAt'}
        result={k:v for k,v in result.items() if k in safe_keys}
        with self.db() as db:account=db.execute('SELECT a.* FROM web_accounts a JOIN web_jobs j ON j.account_id=a.id WHERE j.id=?',(job['id'],)).fetchone()
        if account and 'checkinWindow' not in result:
            previous=json.loads(account['last_result']) if account['last_result'] else {}
            if previous.get('checkinWindow'):result['checkinWindow']=previous['checkinWindow']
        context=self._payload(account) if account else None
        if 'submissionAction' in result and (not isinstance(result['submissionAction'],str) or result['submissionAction'] not in ACTIONS):result.pop('submissionAction')
        if 'submission' in result:result['submission']=submission_details(result['submission'],context)
        if 'verification' in result:result['verification']=[x for v in result['verification'][-4:] if (x:=verification_details(v,context))]
        if 'schoolMessage' in result:result['schoolMessage']=school_message(result['schoolMessage'],context)
        status='done' if result.get('result') in {'confirmed','already_recorded','auth_ready','dry_run_ready'} else 'failed'
        encoded=json.dumps(result,ensure_ascii=False,allow_nan=False)
        with self.db(True) as db:
            db.execute('UPDATE web_jobs SET state=?,result=?,finished_at=? WHERE id=?',(status,encoded,time.time(),job['id']))
            db.execute('UPDATE web_accounts SET last_result=?,last_run_at=? WHERE id=?',(encoded,time.time(),job['account_id']))

    def defer_scheduled_retry(self,job,result,stamp):
        if job['source']!='schedule' or job.get('attempt',0):return False
        with self.db(True) as db:
            due=retry_reservation(db,job,stamp,self.execution_window)
            if due is None:return False
            row=db.execute('SELECT last_result FROM web_accounts WHERE id=?',(job['account_id'],)).fetchone()
            value={'result':'retry_pending','reason':result.get('reason','record_not_confirmed'),'retryAt':due}
            previous=json.loads(row['last_result']) if row and row['last_result'] else {}
            if previous.get('checkinWindow'):value['checkinWindow']=previous['checkinWindow']
            pending=json.dumps(value,ensure_ascii=False)
            db.execute("UPDATE web_jobs SET state='queued',attempt=1,available_at=?,execute_before=?,result=?,finished_at=NULL WHERE id=?",(due,due+30,pending,job['id']))
            db.execute('UPDATE web_accounts SET last_result=?,last_run_at=? WHERE id=?',(pending,stamp,job['account_id']))
            self._audit(db,{'id':job['requested_by']},'scheduled_retry_reserved',job['id'])
        return True

    def recover_jobs(self):
        with self.db(True) as db:
            result=json.dumps({'result':'error','reason':'worker_interrupted','stage':'worker'})
            db.execute("UPDATE web_jobs SET state='failed',result=?,finished_at=? WHERE state='running'",(result,time.time()))

    def automatic_accounts(self,business_day=None):
        with self.db() as db:
            query="SELECT a.id,a.run_at,a.payload,a.owner_id,a.last_result,s.minute AS slot_minute FROM web_accounts a JOIN web_users u ON u.id=a.owner_id LEFT JOIN web_schedule_slots s ON s.account_id=a.id WHERE a.automatic=1 AND a.enabled=1 AND u.active=1"
            params=[]
            if self.require_notice:
                query+=" AND (u.role='admin' OR EXISTS (SELECT 1 FROM portal_notices n WHERE n.user_id=u.id AND n.version=?))";params.append(NOTICE_VERSION)
            if business_day:
                query+=" AND NOT EXISTS (SELECT 1 FROM web_jobs j WHERE j.account_id=a.id AND j.source='schedule' AND j.business_date=?)";params.append(business_day)
                query+=" AND NOT EXISTS (SELECT 1 FROM web_jobs j WHERE j.account_id=a.id AND j.mode='checkin' AND j.business_date=? AND j.state='done' AND json_extract(j.result,'$.result') IN ('confirmed','already_recorded'))";params.append(business_day)
            return [dict(r) for r in db.execute(query,params)]

    def notice_accepted(self,user):
        if user['role']!='user':return True
        with self.db() as db:return db.execute('SELECT 1 FROM portal_notices WHERE user_id=? AND version=?',(user['id'],NOTICE_VERSION)).fetchone() is not None

    def accept_notice(self,user,version):
        if version!=NOTICE_VERSION:raise WebError(428,'privacy_consent_required','请阅读当前版本的个人信息托管说明。')
        with self.db(True) as db:
            db.execute('INSERT INTO portal_notices VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,accepted_at=excluded.accepted_at',(user['id'],version,time.time()))
            self._audit(db,user,'hosting_notice_accepted',user['id'])

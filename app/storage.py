import json
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from cryptography.fernet import Fernet
from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo('Asia/Shanghai')

def now():
    return datetime.now(TZ)

def stamp():
    return now().isoformat(timespec='seconds')

DEFAULT_SETTINGS = {'enabled': False, 'time': '22:00', 'window_start': '21:30', 'window_end': '23:30', 'retry_minutes': 5, 'max_attempts': 12, 'time_jitter_seconds':120, 'location_jitter_meters':5}

def preparation_start(target):
    value = (int(target[:2]) * 60 + int(target[3:]) - 30) % 1440
    return f'{value // 60:02d}:{value % 60:02d}'

def normalized_settings(settings):
    cfg = {**DEFAULT_SETTINGS, **settings}
    cfg['window_start'] = preparation_start(cfg['time'])
    return cfg

class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        key_path = self.directory / 'master.key'
        if not key_path.exists():
            if (self.directory / 'mooncheck.db').exists():
                raise RuntimeError('数据库存在但 master.key 丢失，请恢复原密钥。')
            try:
                with key_path.open('xb') as f:
                    f.write(Fernet.generate_key())
                key_path.chmod(0o600)
            except FileExistsError:
                pass
        self.random_key = key_path.read_bytes().strip()
        self.cipher = Fernet(self.random_key)
        with self.db() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, config TEXT NOT NULL, state TEXT NOT NULL DEFAULT '{}');
                CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, account_id TEXT, name TEXT, action TEXT, outcome TEXT, message TEXT);
                CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, settings TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS presets (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS notifications (owner_id TEXT PRIMARY KEY, config TEXT NOT NULL, last_status TEXT NOT NULL DEFAULT '', last_at TEXT NOT NULL DEFAULT '');
            ''')
            if 'auth_version' not in {r['name'] for r in db.execute('PRAGMA table_info(users)')}:
                db.execute('ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0')
            for table in ('accounts', 'events'):
                columns = {r['name'] for r in db.execute('PRAGMA table_info(' + table + ')')}
                if 'owner_id' not in columns:
                    db.execute('ALTER TABLE ' + table + " ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'root'")
                db.execute('CREATE INDEX IF NOT EXISTS idx_' + table + '_owner ON ' + table + '(owner_id)')
            db.execute("INSERT OR IGNORE INTO meta VALUES ('settings', ?)", (json.dumps(DEFAULT_SETTINGS),))
            db.execute("INSERT OR IGNORE INTO meta VALUES ('session_secret', ?)", (json.dumps(secrets.token_hex(32)),))
            db.execute("INSERT OR IGNORE INTO meta VALUES ('registration_enabled', 'true')")
            legacy = db.execute("SELECT value FROM meta WHERE key='admin_hash'").fetchone()
            if legacy and not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                cfg = db.execute("SELECT value FROM meta WHERE key='settings'").fetchone()[0]
                db.execute('INSERT INTO users(id,username,password_hash,role,active,created_at,settings) VALUES (?,?,?,?,?,?,?)', ('root', 'admin', json.loads(legacy[0]), 'superadmin', 1, stamp(), cfg))

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.directory / 'mooncheck.db', timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, key, default=None):
        with self.db() as db:
            row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value)))

    def accounts(self, owner_id=None):
        with self.db() as db:
            rows = db.execute('SELECT * FROM accounts' + (' WHERE owner_id=?' if owner_id is not None else '') + ' ORDER BY rowid', (owner_id,) if owner_id is not None else ()).fetchall()
        return [{'id': r['id'], **json.loads(self.cipher.decrypt(r['config'].encode())), 'owner_id': r['owner_id'], 'state': json.loads(r['state'])} for r in rows]

    def account(self, aid):
        for a in self.accounts():
            if a['id'] == aid:
                return a
        raise ValueError('账号不存在')

    def save_account(self, account):
        cfg = {k: v for k, v in account.items() if k not in ('id', 'state', 'owner_id')}
        encrypted = self.cipher.encrypt(json.dumps(cfg, ensure_ascii=False).encode()).decode()
        with self.db() as db:
            db.execute('INSERT INTO accounts(id,config,state,owner_id) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET config=excluded.config, state=excluded.state', (account['id'], encrypted, json.dumps(account.get('state', {}), ensure_ascii=False), account.get('owner_id', 'root')))

    def delete(self, aid):
        with self.db() as db:
            db.execute('DELETE FROM accounts WHERE id=?', (aid,))

    def event(self, a, action, outcome, message):
        with self.db() as db:
            db.execute('INSERT INTO events(at,account_id,name,action,outcome,message,owner_id) VALUES (?,?,?,?,?,?,?)', (stamp(), a['id'], a['name'], action, outcome, message, a.get('owner_id', 'root')))

    def events(self, limit=100, owner_id=None):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT * FROM events' + (' WHERE owner_id=?' if owner_id is not None else '') + ' ORDER BY id DESC LIMIT ?', (owner_id, limit) if owner_id is not None else (limit,))]

    def users(self):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT id,username,role,active,created_at FROM users ORDER BY created_at,id')]

    def user(self, uid=None, username=None):
        with self.db() as db:
            row = db.execute('SELECT * FROM users WHERE ' + ('id=?' if uid is not None else 'username=? COLLATE NOCASE'), (uid if uid is not None else username,)).fetchone()
        if not row:
            return None
        u = dict(row)
        u['settings'] = normalized_settings(json.loads(u['settings']))
        return u

    def create_user(self, username, password_hash, superadmin=False):
        uid = 'root' if superadmin else secrets.token_hex(16)
        with self.db() as db:
            if superadmin and db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise ValueError('总管理员已经创建，请登录')
            try:
                db.execute('INSERT INTO users(id,username,password_hash,role,active,created_at,settings) VALUES (?,?,?,?,?,?,?)', (uid, username, password_hash, 'superadmin' if superadmin else 'user', 1, stamp(), json.dumps(DEFAULT_SETTINGS)))
            except sqlite3.IntegrityError:
                raise ValueError('该用户名已被使用') from None
        return self.user(uid=uid)

    def user_settings(self, uid, cfg):
        with self.db() as db:
            db.execute('UPDATE users SET settings=? WHERE id=?', (json.dumps(normalized_settings(cfg)), uid))

    def set_user_active(self, uid, active):
        with self.db() as db:
            db.execute("UPDATE users SET active=?,auth_version=auth_version+1 WHERE id=? AND role!='superadmin'", (int(active), uid))

    def notification_settings(self, uid):
        with self.db() as db:
            row = db.execute('SELECT * FROM notifications WHERE owner_id=?', (uid,)).fetchone()
        if not row:
            return {'enabled': False, 'webhook': '', 'secret': '', 'last_status': '', 'last_at': ''}
        config = json.loads(self.cipher.decrypt(row['config'].encode()))
        return {**config, 'last_status': row['last_status'], 'last_at': row['last_at']}

    def save_notification_settings(self, uid, config):
        encrypted = self.cipher.encrypt(json.dumps({k:config[k] for k in ('enabled', 'webhook', 'secret')}, ensure_ascii=False).encode()).decode()
        with self.db() as db:
            db.execute("INSERT INTO notifications(owner_id,config) VALUES (?,?) ON CONFLICT(owner_id) DO UPDATE SET config=excluded.config,last_status='',last_at=''", (uid, encrypted))

    def notification_status(self, uid, status):
        with self.db() as db:
            db.execute('UPDATE notifications SET last_status=?,last_at=? WHERE owner_id=?', (status, stamp(), uid))

    def presets(self):
        with self.db() as db:
            return [{'id': r['id'], **json.loads(r['data'])} for r in db.execute('SELECT * FROM presets ORDER BY rowid')]

    def save_preset(self, preset):
        with self.db() as db:
            db.execute('INSERT INTO presets VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data', (preset['id'], json.dumps({k:v for k,v in preset.items() if k != 'id'}, ensure_ascii=False)))

    def resolve_location(self, account):
        if account.get('location_mode', 'manual') != 'preset':
            return dict(account)
        preset = next((p for p in self.presets() if p['id'] == account.get('preset_id') and p.get('enabled')), None)
        if not preset:
            raise ValueError('所选系统预设不可用，请重新选择位置或手动填写')
        return {**account, **{k:preset[k] for k in ('latitude', 'longitude', 'accuracy', 'coordinate_system')}, 'preset_name': preset['name'], 'browser_location': False, 'location_duration_ms': 0}

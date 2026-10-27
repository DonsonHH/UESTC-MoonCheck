"""Encrypted class/notification configuration and durable side-effect claims."""
import json
import re
import secrets
import time

from .web_errors import WebError


class SupportStore:
    def __init__(self,store):
        self.store=store
        with store.db(True) as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS web_support_settings(
                    name TEXT PRIMARY KEY,account_id TEXT REFERENCES web_accounts(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES web_users(id) ON DELETE CASCADE,payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS web_support_runs(
                    ident TEXT PRIMARY KEY,account_id TEXT REFERENCES web_accounts(id) ON DELETE SET NULL,
                    kind TEXT NOT NULL,business_date TEXT NOT NULL,state TEXT NOT NULL,payload BLOB NOT NULL,
                    created_at REAL NOT NULL,updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS web_support_tokens(
                    digest TEXT PRIMARY KEY,kind TEXT NOT NULL,account_id TEXT REFERENCES web_accounts(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES web_users(id) ON DELETE CASCADE,expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS web_qq_events(digest TEXT PRIMARY KEY,created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS web_qq_contacts(digest TEXT PRIMARY KEY,payload BLOB NOT NULL,updated_at REAL NOT NULL);
            ''')

    def get(self,name,default=None,db=None):
        if db is None:
            with self.store.db() as connection:return self.get(name,default,connection)
        row=db.execute('SELECT payload FROM web_support_settings WHERE name=?',(name,)).fetchone()
        return self.store.vault.open(row['payload'],'support:'+name) if row else (default if default is not None else {})

    def put(self,name,value,*,account_id=None,user_id=None,db=None):
        if db is None:
            with self.store.db(True) as connection:return self.put(name,value,account_id=account_id,user_id=user_id,db=connection)
        db.execute('INSERT INTO web_support_settings VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload,account_id=excluded.account_id,user_id=excluded.user_id',
            (name,account_id,user_id,self.store.vault.seal(value,'support:'+name)))

    def cadre(self,account_id):return self.get('cadre:'+account_id)

    def cadres(self):
        with self.store.db() as db:
            rows=db.execute("SELECT s.name,a.id,a.owner_id,a.enabled,a.automatic,u.active,u.role FROM web_support_settings s JOIN web_accounts a ON a.id=s.account_id JOIN web_users u ON u.id=a.owner_id WHERE s.name LIKE 'cadre:%'").fetchall()
            return [(dict(row),self.get(row['name'],db=db)) for row in rows]

    def reminder(self,user_id):return self.get('reminder:'+str(user_id),{'enabled':False})

    def reminders(self):
        with self.store.db() as db:
            rows=db.execute("SELECT s.name,u.id FROM web_support_settings s JOIN web_users u ON u.id=s.user_id WHERE s.name LIKE 'reminder:%' AND u.active=1").fetchall()
            return [(row['id'],self.get(row['name'],db=db)) for row in rows]

    def new_code(self,kind,*,account_id=None,user_id=None):
        if kind!='group':raise WebError(400,'invalid_binding_kind','不支持此绑定方式。')
        code=secrets.token_hex(8).upper();digest=self.store.vault.digest('support_binding',code)
        with self.store.db(True) as db:
            db.execute('DELETE FROM web_support_tokens WHERE expires_at<?',(time.time(),))
            db.execute('DELETE FROM web_support_tokens WHERE kind=? AND account_id IS ? AND user_id IS ?',(kind,account_id,user_id))
            db.execute('INSERT INTO web_support_tokens VALUES(?,?,?,?,?)',(digest,kind,account_id,user_id,time.time()+600))
        return code

    def bind_code(self,code,context):
        if not isinstance(code,str) or not re.fullmatch('[A-Fa-f0-9]{16}',code):return False
        digest=self.store.vault.digest('support_binding',code.upper())
        with self.store.db(True) as db:
            row=db.execute('SELECT * FROM web_support_tokens WHERE digest=? AND expires_at>?',(digest,time.time())).fetchone()
            if not row:return False
            if row['kind']=='group':
                if context['kind']!='group':return False
                name='cadre:'+row['account_id'];value=self.get(name,db=db)
                if not value:return False
                if self.get('qq_test_destination',db=db).get('group_openid')==context['target']:return False
                if value.get('group_openid')!=context['target']:value['members']={}
                value['group_openid']=context['target']
                self.put(name,value,account_id=row['account_id'],db=db)
            else:return False
            db.execute('DELETE FROM web_support_tokens WHERE digest=?',(digest,))
        return row['kind']

    def once_event(self,event_id):
        digest=self.store.vault.digest('qq_event',event_id)
        with self.store.db(True) as db:
            db.execute('DELETE FROM web_qq_events WHERE created_at<?',(time.time()-86400*7,))
            return db.execute('INSERT OR IGNORE INTO web_qq_events VALUES(?,?)',(digest,time.time())).rowcount==1

    def contact(self,context):
        value={key:context[key] for key in ('kind','target','sender')}
        digest=self.store.vault.digest('qq_contact',json.dumps(value,sort_keys=True))
        with self.store.db(True) as db:
            db.execute('DELETE FROM web_qq_contacts WHERE updated_at<?',(time.time()-86400*7,))
            db.execute('INSERT INTO web_qq_contacts VALUES(?,?,?) ON CONFLICT(digest) DO UPDATE SET updated_at=excluded.updated_at',
                (digest,self.store.vault.seal(value,'qq_contact:'+digest),time.time()))
            db.execute('DELETE FROM web_qq_contacts WHERE digest NOT IN (SELECT digest FROM web_qq_contacts ORDER BY updated_at DESC LIMIT 300)')

    def contacts(self):
        with self.store.db() as db:
            return [{**self.store.vault.open(r['payload'],'qq_contact:'+r['digest']),'last_seen':r['updated_at']} for r in db.execute('SELECT * FROM web_qq_contacts WHERE updated_at>=? ORDER BY updated_at DESC LIMIT 100',(time.time()-86400*7,))]

    def prune(self):
        with self.store.db(True) as db:
            db.execute('DELETE FROM web_support_tokens WHERE expires_at<?',(time.time(),))
            db.execute('DELETE FROM web_qq_contacts WHERE updated_at<?',(time.time()-86400*7,))
            db.execute('DELETE FROM web_qq_events WHERE created_at<?',(time.time()-86400*7,))

    def run_id(self,scope,kind,day):return self.store.vault.digest('support_run',kind+'\0'+scope+'\0'+day)

    def begin(self,scope,kind,day,*,account_id=None,initial=None,retry_cancelled=False):
        ident=self.run_id(scope,kind,day)
        with self.store.db(True) as db:
            row=db.execute('SELECT * FROM web_support_runs WHERE ident=?',(ident,)).fetchone()
            if row:
                previous=self.store.vault.open(row['payload'],'support_run:'+ident)
                if not retry_cancelled or kind not in ('operator_alert','operator_success') or row['state']!='done' or previous.get('result')!='reminder_cancelled':
                    return ident,False,previous
            stamp=time.time();value=initial or {}
            if row:
                # Only a known pre-send cancellation can rearm; sent, failed or
                # unknown deliveries and school-write claims remain final.
                db.execute("UPDATE web_support_runs SET account_id=?,state='started',payload=?,updated_at=? WHERE ident=?",
                    (account_id,self.store.vault.seal(value,'support_run:'+ident),stamp,ident))
            else:
                db.execute('INSERT INTO web_support_runs VALUES(?,?,?,?,?,?,?,?)',
                    (ident,account_id,kind,day,'started',self.store.vault.seal(value,'support_run:'+ident),stamp,stamp))
        return ident,True,value

    def finish(self,ident,result,state='done'):
        with self.store.db(True) as db:
            db.execute('UPDATE web_support_runs SET state=?,payload=?,updated_at=? WHERE ident=?',
                (state,self.store.vault.seal(result,'support_run:'+ident),time.time(),ident))

    def runs(self,account_id=None,*,with_ident=False):
        with self.store.db() as db:
            rows=db.execute('SELECT * FROM web_support_runs'+(' WHERE account_id=?' if account_id else '')+' ORDER BY created_at DESC LIMIT 30',
                (account_id,) if account_id else ()).fetchall()
            return [{'kind':r['kind'],'business_date':r['business_date'],'state':r['state'],'created_at':r['created_at'],
                'result':self.store.vault.open(r['payload'],'support_run:'+r['ident']),
                **({'_ident':r['ident']} if with_ident else {})} for r in rows]

    def owner(self,actor,account_id,*,require_cadre=True):
        with self.store.db() as db:row=self.store._row(db,actor,account_id)
        if actor['role']!='admin' and row['owner_id']!=actor['id']:raise WebError(404,'not_found','账号不存在。')
        if require_cadre and not self.cadre(account_id):raise WebError(403,'class_access_required','此账号尚未配置班级权限。')
        if not row['owner_active'] or not row['enabled']:raise WebError(409,'account_disabled','账号已暂停或停用。')
        return dict(row)

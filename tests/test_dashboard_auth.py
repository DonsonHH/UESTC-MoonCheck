import hashlib
import time
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import patch
from argon2 import PasswordHasher
from dashboard_helpers import WebCase,ORIGIN,ADMIN_PASS,USER_PASS
from moonuestc.errors import ToolError
from moonuestc.web_app import COOKIE,normalize_origin
from moonuestc.web_errors import WebError
from moonuestc.web_store import WebStore


class DashboardIdentity(WebCase):
    def test_anonymous_cannot_enter_pages_or_private_apis(self):
        client=self.app.test_client()
        self.assertEqual(client.get('/',base_url=ORIGIN).status_code,302)
        with client.get('/login',base_url=ORIGIN) as response:
            self.assertEqual(response.status_code,200)
        self.assertEqual(client.get('/static/app.html',base_url=ORIGIN).status_code,404)
        self.assertEqual(client.get('/static/../web_pages/app.html',base_url=ORIGIN).status_code,404)
        for path in ('/api/accounts','/api/jobs','/api/users','/api/locations'):
            self.assertEqual(client.get(path,base_url=ORIGIN).status_code,401,path)
        self.assertFalse(client.get('/api/session',base_url=ORIGIN).get_json()['authenticated'])

    def test_unknown_hosts_and_cross_origin_login_are_rejected(self):
        client=self.app.test_client()
        self.assertEqual(client.get('/login',base_url='https://evil.example').status_code,400)
        response=client.post('/api/login',base_url=ORIGIN,headers={'Origin':'https://evil.example'},json={'username':'admin','password':ADMIN_PASS})
        self.assertEqual(response.status_code,403)
        self.assertEqual(client.post('/api/login',base_url=ORIGIN,json={'username':'admin','password':ADMIN_PASS}).status_code,403)

    def test_cookie_is_secure_httponly_and_samesite_and_db_only_keeps_digest(self):
        client=self.app.test_client()
        response=client.post('/api/login',base_url=ORIGIN,headers={'Origin':ORIGIN},json={'username':'admin','password':ADMIN_PASS})
        cookie=SimpleCookie();cookie.load(response.headers['Set-Cookie'])
        value=cookie[COOKIE]
        self.assertTrue(value['secure']);self.assertTrue(value['httponly']);self.assertEqual(value['samesite'],'Strict')
        with self.store.db() as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM web_sessions WHERE token_hash=?',(hashlib.sha256(value.value.encode()).hexdigest(),)).fetchone())
            self.assertIsNone(db.execute('SELECT 1 FROM web_sessions WHERE token_hash=?',(value.value,)).fetchone())

    def test_csrf_token_is_mandatory_for_authenticated_writes(self):
        response=self.req(self.c1,'wrong','/api/accounts','POST',self.account_fields())
        self.assertEqual(response.status_code,403)
        self.assertEqual(response.get_json()['error']['code'],'csrf_failed')
        response=self.req(self.c1,self.t1,'/api/accounts','POST',self.account_fields(),origin='https://evil.example')
        self.assertEqual(response.status_code,403)

    def test_non_ascii_and_oversized_csrf_headers_are_cleanly_rejected(self):
        for token in ('é', 'x'*129):
            response=self.req(self.c1,token,'/api/accounts','POST',self.account_fields())
            self.assertEqual(response.status_code,403,response.get_json())
            self.assertEqual(response.get_json()['error']['code'],'csrf_failed')

    def test_public_registration_can_be_disabled_and_no_default_password(self):
        client=self.app.test_client()
        self.app.config['MOON_REGISTRATION_ENABLED']=False
        self.assertEqual(client.post('/api/register',base_url=ORIGIN,headers={'Origin':ORIGIN},json={}).status_code,403)
        with self.assertRaises(WebError):
            self.store.create_user(None,{'username':'newadmin','password':ADMIN_PASS,'role':'admin'},bootstrap=True)
        response=client.post('/api/login',base_url=ORIGIN,headers={'Origin':ORIGIN},json={'username':'admin','password':'admin'})
        self.assertEqual(response.status_code,401)

    def test_regular_users_cannot_manage_users_or_promote_themselves(self):
        self.assertEqual(self.req(self.c1,self.t1,'/api/users').status_code,403)
        self.assertEqual(self.req(self.c1,self.t1,'/api/users','POST',{'username':'evil','password':ADMIN_PASS,'role':'admin'}).status_code,403)
        self.assertEqual(self.req(self.c1,self.t1,'/api/users/'+str(self.u1['id']),'PATCH',{'role':'admin'}).status_code,403)

    def test_last_active_admin_cannot_be_demoted_or_disabled(self):
        for data in ({'role':'user'},{'active':False}):
            response=self.req(self.ac,self.at,'/api/users/'+str(self.admin['id']),'PATCH',data)
            self.assertEqual(response.status_code,409,response.get_json())
            self.assertEqual(response.get_json()['error']['code'],'last_admin')
        self.assertEqual(self.req(self.ac,self.at,'/api/users/'+str(self.admin['id']),'DELETE').status_code,409)

    def test_admin_creates_and_disables_user_and_sessions_are_invalidated(self):
        created=self.req(self.ac,self.at,'/api/users','POST',{'username':'student3','display_name':'第三位同学','password':USER_PASS,'role':'user'})
        self.assertEqual(created.status_code,201,created.get_json())
        self.assertTrue(created.get_json()['user']['must_change_password'])
        self.assertNotIn('password_hash',created.get_data(as_text=True))
        response=self.req(self.ac,self.at,'/api/users/'+str(self.u1['id']),'PATCH',{'active':False})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts').status_code,401)

    def test_admin_reset_password_revokes_sessions_and_requires_change(self):
        new='A-New-Temporary-Pass-2026!'
        response=self.req(self.ac,self.at,'/api/users/'+str(self.u1['id']),'PATCH',{'password':new})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts').status_code,401)
        client,token=self.login_client('alice',new)
        self.assertEqual(self.req(client,token,'/api/accounts').status_code,403)
        changed=self.req(client,token,'/api/me/password','POST',{'current_password':new,'new_password':'Final-New-Login-Pass-2026!'})
        self.assertEqual(changed.status_code,200,changed.get_json())
        final,ft=self.login_client('alice','Final-New-Login-Pass-2026!')
        self.assertEqual(self.req(final,ft,'/api/accounts').status_code,200)

    def test_password_change_needs_current_password_and_invalidates_all_sessions(self):
        second,token=self.login_client('alice',USER_PASS)
        wrong=self.req(self.c1,self.t1,'/api/me/password','POST',{'current_password':'wrong','new_password':'A-New-Account-Pass-2026!'})
        self.assertEqual(wrong.status_code,403)
        good=self.req(self.c1,self.t1,'/api/me/password','POST',{'current_password':USER_PASS,'new_password':'A-New-Account-Pass-2026!'})
        self.assertEqual(good.status_code,200)
        self.assertEqual(self.req(second,token,'/api/accounts').status_code,401)
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts').status_code,401)

    def test_logout_revokes_server_side_session(self):
        self.assertEqual(self.req(self.c1,self.t1,'/api/logout','POST',{}).status_code,200)
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts').status_code,401)

    def test_expired_and_idle_sessions_are_rejected(self):
        with self.store.db(True) as db:db.execute('UPDATE web_sessions SET expires_at=0 WHERE user_id=?',(self.u1['id'],))
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts').status_code,401)
        with self.store.db(True) as db:db.execute('UPDATE web_sessions SET last_seen=? WHERE user_id=?',(time.time()-1900,self.u2['id']))
        self.assertEqual(self.req(self.c2,self.t2,'/api/accounts').status_code,401)

    def test_login_rate_limit_and_generic_unknown_user_error(self):
        client=self.app.test_client()
        payload={'username':'not-an-existing-user','password':'Unknown-Wrong-Pass-2026!'}
        for _ in range(8):
            response=client.post('/api/login',base_url=ORIGIN,headers={'Origin':ORIGIN},json=payload)
            self.assertEqual(response.status_code,401)
            self.assertEqual(response.get_json()['error']['message'],'用户名或密码不正确。')
        self.assertEqual(client.post('/api/login',base_url=ORIGIN,headers={'Origin':ORIGIN},json=payload).status_code,429)

    def test_password_hash_and_ciphertext_not_plaintext(self):
        with self.store.db() as db:
            row=db.execute('SELECT password_hash FROM web_users WHERE id=?',(self.admin['id'],)).fetchone()
        self.assertTrue(row[0].startswith('$argon2id$'))
        self.assertNotIn(ADMIN_PASS,row[0])
        vault=self.store.vault
        encrypted=vault.seal({'password':'a-secret-value'},'account:one')
        self.assertNotIn(b'a-secret-value',encrypted)
        self.assertEqual(vault.open(encrypted,'account:one')['password'],'a-secret-value')
        with self.assertRaises(ToolError):vault.open(encrypted,'account:two')
        with self.assertRaises(ToolError):vault.open(encrypted[:-1]+bytes([encrypted[-1]^1]),'account:one')

    def test_security_headers_and_json_request_size_limits(self):
        response=self.ac.get('/',base_url=ORIGIN)
        self.assertEqual(response.headers['X-Frame-Options'],'DENY')
        self.assertIn("script-src 'self'",response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertIn('max-age=',response.headers['Strict-Transport-Security'])
        response.close()
        response=self.req(self.c1,self.t1,'/api/accounts','POST',{'label':'x'*40000})
        self.assertEqual(response.status_code,413)

    def test_https_ip_certificate_origin_and_lan_http_are_supported(self):
        self.assertEqual(normalize_origin(ORIGIN),ORIGIN)
        self.assertEqual(normalize_origin('https://203.0.113.10:443'),'https://203.0.113.10')
        self.assertEqual(normalize_origin('http://192.168.1.20:8088',True),'http://192.168.1.20:8088')
        for value in ('http://8.8.8.8:8088','https://user:pass@203.0.113.10','https://203.0.113.10/path','https://203.0.113.10?x=1'):
            with self.subTest(value=value),self.assertRaises(ToolError):normalize_origin(value,True)
        with self.assertRaises(ToolError):normalize_origin('http://127.0.0.1:8088')

    def test_default_https_port_is_canonicalized_for_ip_host_and_origin(self):
        from moonuestc.web_app import create_app
        from dashboard_helpers import FAST_HASHER
        other=self.root/'default-port'
        app=create_app(other,'https://203.0.113.10',hasher=FAST_HASHER)
        client=app.test_client()
        response=client.get('/login',base_url='https://203.0.113.10:443')
        self.assertEqual(response.status_code,200,response.get_json(silent=True))
        response.close()
        response=client.post('/api/login',base_url='https://203.0.113.10:443',headers={'Origin':'https://203.0.113.10:443'},json={})
        self.assertEqual(response.status_code,503)

    def test_no_school_request_on_initial_pages_or_account_lists(self):
        with self.ac.get('/',base_url=ORIGIN) as response:
            self.assertEqual(response.status_code,200)
        self.req(self.ac,self.at,'/api/accounts')
        self.req(self.ac,self.at,'/api/users')
        self.assertEqual(self.calls,[])

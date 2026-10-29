"""Public HTTP entry must upgrade before any Moon business handler runs."""
import tempfile
import unittest
from pathlib import Path

from dashboard_helpers import FAST_HASHER
from moonuestc.web_app import create_app

HTTPS='https://moon.example.test'
HTTP='http://moon.example.test'
TRUSTED='192.0.2.10'


class HttpsRedirect(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.verifications=[]
        self.app=create_app(Path(self.temp.name),HTTPS,portal_enabled=True,surface='public',hasher=FAST_HASHER,
            trusted_proxies=[TRUSTED+'/32'],school_verifier=lambda data:self.verifications.append(data))
        self.client=self.app.test_client()
    def tearDown(self):
        self.app.extensions['moon_worker'].stop();self.temp.cleanup()
    def test_public_http_preserves_path_and_query_but_serves_no_page(self):
        response=self.client.get('/app/settings?from=mail&next=%2Fapp%2Fhistory',base_url=HTTP,
            environ_overrides={'REMOTE_ADDR':TRUSTED},headers={'CF-Visitor':'{"scheme":"http"}'})
        self.assertEqual(response.status_code,308)
        self.assertEqual(response.headers['Location'],'https://moon.example.test/app/settings?from=mail&next=%2Fapp%2Fhistory')
        self.assertNotIn(b'id="root"',response.data)
    def test_https_tunnel_request_does_not_loop_and_keeps_hsts(self):
        response=self.client.get('/login',base_url=HTTP,environ_overrides={'REMOTE_ADDR':TRUSTED},
            headers={'CF-Visitor':'{"scheme":"https"}'})
        self.assertEqual(response.status_code,200)
        self.assertNotIn('Location',response.headers)
        self.assertEqual(response.headers['Strict-Transport-Security'],'max-age=31536000')
        response.close()
    def test_encoded_reserved_path_characters_stay_encoded_in_redirect(self):
        for path in ('/app/a%3Fb%23c?from=%2Fsettings','/app/a%252Fb?x=1'):
            with self.subTest(path=path):
                response=self.client.get(path,base_url=HTTP)
                self.assertEqual(response.status_code,308)
                self.assertEqual(response.headers['Location'],HTTPS+path)
    def test_untrusted_forwarding_headers_cannot_allow_plain_http(self):
        response=self.client.get('/api/session',base_url=HTTP,environ_overrides={'REMOTE_ADDR':'198.51.100.17'},
            headers={'X-Forwarded-Proto':'https','CF-Visitor':'{"scheme":"https"}','X-Forwarded-Host':'evil.example'})
        self.assertEqual(response.status_code,308)
        self.assertEqual(response.headers['Location'],'https://moon.example.test/api/session')
        self.assertIsNone(response.json)
    def test_http_login_and_callback_redirect_before_business_processing(self):
        for path in ('/api/portal/login','/api/qq/callback/'+'a'*64):
            with self.subTest(path=path):
                response=self.client.post(path,base_url=HTTP,environ_overrides={'REMOTE_ADDR':TRUSTED},
                    headers={'Origin':HTTP,'CF-Visitor':'{"scheme":"http"}'},json={})
                self.assertEqual(response.status_code,308)
                self.assertEqual(response.headers['Location'],HTTPS+path)
                self.assertNotIn('Set-Cookie',response.headers)
        self.assertEqual(self.verifications,[])
    def test_unexpected_host_is_rejected_instead_of_becoming_redirect_target(self):
        response=self.client.get('/login',base_url='http://evil.example',headers={'X-Forwarded-Host':'moon.example.test'})
        self.assertEqual(response.status_code,400)
        self.assertNotIn('Location',response.headers)
    def test_trusted_standard_scheme_and_malformed_header_are_handled(self):
        response=self.client.get('/login',base_url=HTTP,environ_overrides={'REMOTE_ADDR':TRUSTED},headers={'X-Forwarded-Proto':'https'})
        self.assertEqual(response.status_code,200)
        response.close()
        for headers in ({'X-Forwarded-Proto':'https,http'},{'CF-Visitor':'invalid'},{'CF-Visitor':'[]'}):
            with self.subTest(headers=headers):
                response=self.client.get('/login',base_url=HTTP,environ_overrides={'REMOTE_ADDR':TRUSTED},headers=headers)
                self.assertEqual(response.status_code,308)
    def test_only_container_local_health_probe_can_use_loopback_http(self):
        response=self.client.get('/healthz',base_url='http://127.0.0.1:8080',environ_overrides={'REMOTE_ADDR':'127.0.0.1'})
        self.assertEqual(response.status_code,200)
        response=self.client.get('/healthz',base_url=HTTP,environ_overrides={'REMOTE_ADDR':TRUSTED},headers={'CF-Visitor':'{"scheme":"http"}'})
        self.assertEqual(response.status_code,308)
    def test_private_admin_remains_only_on_its_explicit_loopback_origin(self):
        other=create_app(Path(self.temp.name)/'private','http://127.0.0.1:4497',allow_http=True,portal_enabled=True,
            surface='admin',hasher=FAST_HASHER)
        try:
            client=other.test_client();response=client.get('/admin/login',base_url='http://127.0.0.1:4497')
            self.assertEqual(response.status_code,200)
            self.assertNotIn('Strict-Transport-Security',response.headers)
            response.close()
            self.assertEqual(self.client.get('/admin',base_url=HTTPS).status_code,404)
        finally:other.extensions['moon_worker'].stop()
    def test_actual_waitress_preserves_cloudflare_scheme_without_trusting_standard_spoofing(self):
        import threading,urllib.request,urllib.error
        from waitress import create_server
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        app=create_app(Path(self.temp.name)/'waitress',HTTPS,portal_enabled=True,surface='public',hasher=FAST_HASHER,
            trusted_proxies=['127.0.0.1/32'])
        server=create_server(app,host='127.0.0.1',port=0,threads=1,clear_untrusted_proxy_headers=True)
        thread=threading.Thread(target=server.run,daemon=True);thread.start()
        try:
            for protocol,status in (('http',308),('https',200)):
                request=urllib.request.Request('http://127.0.0.1:'+str(server.effective_port)+'/login',
                    headers={'Host':'moon.example.test','X-Forwarded-Proto':'https','CF-Visitor':'{"scheme":"'+protocol+'"}'})
                try:response=opener.open(request,timeout=3)
                except urllib.error.HTTPError as error:response=error
                with response:self.assertEqual(response.status,status)
            request=urllib.request.Request('http://127.0.0.1:'+str(server.effective_port)+'/app/a%3Fb%23c?from=%2Fsettings',
                headers={'Host':'moon.example.test','CF-Visitor':'{"scheme":"http"}'})
            try:response=opener.open(request,timeout=3)
            except urllib.error.HTTPError as error:response=error
            with response:self.assertEqual(response.headers['Location'],'https://moon.example.test/app/a%3Fb%23c?from=%2Fsettings')
        finally:
            server.close();thread.join(timeout=2);app.extensions['moon_worker'].stop()

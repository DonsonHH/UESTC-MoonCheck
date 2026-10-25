"""Passive resource routing must never become a general credentialed proxy."""
import base64,importlib.util,pathlib,os,sys,unittest

path=pathlib.Path(os.environ['MOON_BROWSER_SOURCE'])/'page_assets.py' if os.environ.get('MOON_BROWSER_SOURCE') else pathlib.Path(__file__).resolve().parents[1]/'browser_assist/page_assets.py'
if path.exists():
    sys.path.insert(0,str(path.parent))
    spec=importlib.util.spec_from_file_location('passive_assets',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

@unittest.skipUnless(path.exists(),'browser helper source is tested in its separate native image')
class PassiveAssets(unittest.TestCase):
    def test_official_wechat_resources_are_registered_without_broad_domain_access(self):
        assets=module.PageAssets()
        self.assertTrue(assets.reference('https://res.wx.qq.com/connect/zh_CN/htmledition/style/impowerApp.css'))
        self.assertTrue(assets.reference('https://open.weixin.qq.com/connect/qrcode/synthetic'))
        for url in ['https://evil.qq.com/image.png','https://res.wx.qq.com.evil.example/image.png','https://open.weixin.qq.com.evil.example/connect/qrcode/x']:
            self.assertEqual(assets.reference(url),'')
    def test_host_scope_and_session_isolation(self):
        a,b=module.PageAssets(),module.PageAssets()
        for url in ['http://idas.uestc.edu.cn/a.css','https://evil.example/a.css','https://idas.uestc.edu.cn@evil.example/a.css','https://idas.uestc.edu.cn:444/a.css','file:///etc/passwd']:
            self.assertEqual(a.reference(url),'')
        self.assertNotEqual(a.reference('https://idas.uestc.edu.cn/a.css'),b.reference('https://idas.uestc.edu.cn/a.css'))
        with self.assertRaises(ValueError):a.get('0'*32,None)
    def test_css_references_are_registered_and_qr_cannot_be_refetched(self):
        assets=module.PageAssets()
        css=assets.stylesheet('@import "other.css";a{background:url(../qr.png)}','https://idas.uestc.edu.cn/styles/main.css')
        self.assertNotIn('other.css',css);self.assertNotIn('../qr.png',css)
        key=assets.reference('https://idas.uestc.edu.cn/qrcode.png').split('/')[-1]
        with self.assertRaises(ValueError):assets.get(key,None)
        assets.remember('https://idas.uestc.edu.cn/qrcode.png','image/png',b'fixture')
        key=assets.reference('https://idas.uestc.edu.cn/qrcode.png').split('/')[-1]
        self.assertEqual(base64.b64decode(assets.get(key,None)['body']),b'fixture')
    def test_executable_payload_and_cache_quota(self):
        assets=module.PageAssets()
        assets.remember('https://idas.uestc.edu.cn/app.js','application/javascript',b'alert(1)')
        self.assertEqual(assets.cached,{})
        assets.remember('https://idas.uestc.edu.cn/image','image/png',b'x'*4_000_001)
        self.assertEqual(assets.size,0)

if __name__=='__main__':unittest.main()

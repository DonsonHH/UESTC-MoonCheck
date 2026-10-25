import importlib.util,os,pathlib,unittest
root=pathlib.Path(os.environ['MOON_BROWSER_SOURCE']) if os.environ.get('MOON_BROWSER_SOURCE') else pathlib.Path(__file__).resolve().parents[1]/'browser_assist'
source=root/'access_policy.py'
if source.exists():
    spec=importlib.util.spec_from_file_location('wechat_policy',source);policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
@unittest.skipUnless(source.exists(),'helper source is validated in its native image')
class WechatPolicy(unittest.TestCase):
    def test_provider_redirect_needs_a_school_callback(self):
        scope={}
        self.assertFalse(policy.allowed_request('https://open.weixin.qq.com/connect/qrcode/x','image',scope))
        self.assertFalse(policy.allowed_request('https://open.weixin.qq.com/connect/qrconnect?redirect_uri=https%3A%2F%2Fevil.example%2Fcb','document',scope))
        self.assertFalse(scope.get('wechat_enabled',False))
        self.assertTrue(policy.allowed_request('https://open.weixin.qq.com/connect/qrconnect?redirect_uri=https%3A%2F%2Fidas.uestc.edu.cn%2Fauthserver%2Fcb','document',scope))
        self.assertTrue(policy.allowed_request('https://open.weixin.qq.com/connect/qrcode/x','image',scope))
        self.assertTrue(policy.allowed_request('https://lp.open.weixin.qq.com/connect/l/qrconnect','script',scope))
    def test_no_local_wechat_helper_or_unrelated_qq_hosts(self):
        for url in ['https://localhost.weixin.qq.com/api/check-login','https://support.weixin.qq.com/a','https://res.wx.qq.com.evil.example/a','https://127.0.0.1/a']:
            self.assertFalse(policy.allowed_request(url,'xhr',{'wechat_enabled':True}))
        self.assertFalse(policy.allowed_request('https://res.wx.qq.com/a','document',{'wechat_enabled':True}))
        self.assertFalse(policy.school_callback('https://idas.uestc.edu.cn@evil.example/cb'))
if __name__=='__main__':unittest.main()

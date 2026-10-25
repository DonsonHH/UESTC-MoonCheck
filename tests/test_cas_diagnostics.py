"""CAS diagnostics keep actionable messages without forms, tickets or cookies."""
import copy
from types import SimpleNamespace
import unittest

import test_workflows as f
from moonuestc.cas_diagnostics import response_hints
from moonuestc.client import School
from moonuestc.errors import ToolError


class CasDiagnostics(unittest.TestCase):
    def test_visible_errors_exclude_hidden_inputs_scripts_and_hidden_panels(self):
        raw='''<div class="error">认证服务繁忙<br><span>请稍后重试</span>
        <input name="execution" value="hidden-form-value"><script>script-private-value</script>
        <span hidden>hidden-value</span><span style="display:none">invisible-value</span></div>
        <div class="error d-none">another-hidden-value</div>'''
        result=response_hints(f.response('https://idas.uestc.edu.cn/authserver/login',text=raw),f.ACCOUNT)
        self.assertIn('认证服务繁忙',result['school_message']);self.assertIn('请稍后重试',result['school_message'])
        for secret in ('hidden-form-value','script-private-value','hidden-value','invisible-value','another-hidden-value'):
            self.assertNotIn(secret,result['school_message'])
    def test_nested_json_message_retains_code_but_redacts_account_and_cookie(self):
        response=f.response('https://idas.uestc.edu.cn/authserver/login',{'code':9001,'data':{
            'error_description':'认证失败 '+f.ACCOUNT['password']+' short-cookie-value'}})
        value=response_hints(response,f.ACCOUNT,extra_secrets=('short-cookie-value',))
        self.assertEqual(value['api_code'],9001);self.assertIn('认证失败',value['school_message'])
        self.assertNotIn(f.ACCOUNT['password'],str(value));self.assertNotIn('short-cookie-value',str(value))
    def test_redirect_query_and_unmarked_body_are_never_persisted(self):
        response=f.response('https://idas.uestc.edu.cn/authserver/login?ticket=private-ticket',
            text='<title>Private profile title</title>unmarked-private-value',status=302,location='/?ticket=another-private-ticket')
        value=response_hints(response,f.ACCOUNT)
        self.assertIsNone(value['school_message']);self.assertEqual(value['http_status'],302)
        for token in ('Private profile','private-value','private-ticket'):self.assertNotIn(token,str(value))
    def test_real_login_error_preserves_safe_hint_and_hides_form_and_jar_values(self):
        class Rejected(f.FakeTransport):
            jar=[SimpleNamespace(value='short-cookie-value')]
            def request(self,method,url,**values):
                if values['stage']=='cas_submit':
                    return f.response(url,text='<div class="error">用户名或密码错误 '+f.ACCOUNT['password']+
                        ' short-cookie-value e1s1 '+values['form']['password']+'</div>')
                return super().request(method,url,**values)
        school=School(Rejected(),copy.deepcopy(f.ACCOUNT),lambda:None)
        with self.assertRaises(ToolError) as caught:school.connect()
        error=caught.exception
        self.assertEqual(error.reason,'login_rejected');self.assertIn('用户名或密码错误',error.school_message)
        for secret in (f.ACCOUNT['password'],'short-cookie-value','e1s1'):self.assertNotIn(secret,error.school_message)

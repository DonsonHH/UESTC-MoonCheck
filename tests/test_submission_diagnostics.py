"""Synthetic response fixtures exercise diagnostics without contacting the school."""
import base64
import copy
import datetime
import json
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from dashboard_helpers import WebCase,ORIGIN,FAST_HASHER
import test_workflows as f
from moonuestc.diagnostics import school_message,submission_details,verification_details
from moonuestc.errors import ToolError
from moonuestc.policy import now
from moonuestc.runner import run_account,account_key
from moonuestc.state import State


class DiagnosticTransport(f.FakeTransport):
    def __init__(self,instant=f.INSTANT):
        super().__init__();self.instant=instant;self.failure=None;self.network=None
        self.keep_pending=False;self.raw_response=None;self.before_post=None;self.save_failure=False
    def request(self,method,url,**kw):
        stage=kw['stage']
        if stage=='today':
            self.calls.append((method,stage));data=f.record(self.status)
            data['businessDate']=self.instant.date().isoformat()
            data['checkinTime']=self.instant.isoformat() if self.status=='CHECKED_IN' else None
            return f.response(url,{'code':0,'ok':True,'data':data})
        if stage=='checkin_post':
            self.calls.append((method,stage));self.post_count+=1
            if self.before_post:self.before_post()
            if self.network:raise ToolError(self.network,stage)
            if self.raw_response is not None:return f.response(url,text=self.raw_response)
            if self.failure:
                status,code,message,ok=self.failure
                return f.response(url,{'code':code,'ok':ok,'msg':message,'data':None},status=status)
            if not self.keep_pending:self.status='CHECKED_IN'
            return f.response(url,{'code':0,'ok':True,'msg':'操作成功','data':True})
        return super().request(method,url,**kw)
    def save(self):
        if self.save_failure:raise ToolError('encrypted_cookie_invalid','cookies')
        return super().save()


class DiagnosticsFlows(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('MOON_TEST_TMP'));self.root=Path(self.temp.name)
        self.state=State(self.root);self.transport=DiagnosticTransport();self.events=[]
    def tearDown(self):self.state.close();self.temp.cleanup()
    def run_mode(self,mode='checkin'):
        return run_account(copy.deepcopy(f.ACCOUNT),mode,self.state,self.root,clock=lambda:f.INSTANT,sleep=lambda _:None,emit=lambda e,**v:self.events.append((e,v)),transport_factory=lambda *args:self.transport)
    def test_business_code_and_redacted_message_survive_pending_verification(self):
        secret=f.ACCOUNT['password'];student=f.ACCOUNT['student_id'];fp=f.ACCOUNT['browser_fingerprint']
        self.transport.failure=(200,4709,'学校拒绝：位置校验失败 '+secret+' '+student+' '+fp,False)
        result=self.run_mode();self.assertEqual(result['result'],'submission_rejected');self.assertEqual(result['reason'],'business_error')
        self.assertEqual(result['submissionAction'],'first_submit');error=result['submission']
        self.assertEqual((error['httpStatus'],error['apiCode'],error['reason']),(200,4709,'business_error'))
        self.assertIn('位置校验失败',error['schoolMessage'])
        for value in (secret,student,fp):self.assertNotIn(value,json.dumps(error,ensure_ascii=False))
        self.assertEqual([x['status'] for x in result['verification']],['PENDING'])
        self.assertEqual(self.transport.post_count,1)
    def test_recheck_reuses_original_error_after_database_reopen_and_never_reposts(self):
        self.transport.failure=(200,4709,'学校拒绝',False);first=self.run_mode()
        self.state.close();self.state=State(self.root);second=self.run_mode()
        self.assertEqual(second['submissionAction'],'recheck');self.assertEqual(first['submission'],second['submission']);self.assertEqual(self.transport.post_count,1)
    def test_submit_auth_rejection_is_not_replaced_by_generic_pending_reason(self):
        self.transport.failure=(403,5000,'请重新登录',False);result=self.run_mode()
        self.assertEqual(result['submission']['httpStatus'],403);self.assertEqual(result['submission']['apiCode'],5000)
        self.assertEqual(result['submission']['reason'],'session_rejected');self.assertEqual(result['reason'],'session_rejected')
    def test_non_200_json_preserves_school_code_separately_from_http_status(self):
        self.transport.failure=(500,4701,'业务暂不可用',False);result=self.run_mode()
        self.assertEqual((result['submission']['httpStatus'],result['submission']['apiCode']),(500,4701));self.assertEqual(result['submission']['outcome'],'error')
    def test_code_zero_with_ok_false_still_records_rejection(self):
        self.transport.failure=(200,0,'操作被拒绝',False);result=self.run_mode()
        self.assertEqual(result['submission']['apiCode'],0);self.assertEqual(result['submission']['outcome'],'rejected')
    def test_timeout_preserves_no_response_and_does_not_retry_post(self):
        self.transport.network='timeout';result=self.run_mode();again=self.run_mode()
        self.assertEqual(result['submission']['reason'],'timeout');self.assertNotIn('httpStatus',result['submission']);self.assertEqual(again['submissionAction'],'recheck');self.assertEqual(self.transport.post_count,1)
    def test_invalid_json_never_logs_raw_response(self):
        self.transport.raw_response='<html>'+f.ACCOUNT['password']+'</html>';result=self.run_mode()
        self.assertEqual(result['submission']['reason'],'invalid_json');self.assertNotIn(f.ACCOUNT['password'],json.dumps(result));self.assertNotIn('<html>',json.dumps(result))
    def test_success_response_is_still_unconfirmed_when_readback_is_pending(self):
        self.transport.keep_pending=True;result=self.run_mode()
        self.assertEqual(result['submission']['outcome'],'accepted');self.assertEqual(result['result'],'submission_unknown')
    def test_success_and_later_recheck_are_distinct(self):
        first=self.run_mode();second=self.run_mode()
        self.assertEqual(first['submissionAction'],'first_submit');self.assertEqual(second['submissionAction'],'recheck');self.assertEqual(second['result'],'confirmed');self.assertEqual(self.transport.post_count,1)
    def test_old_claim_without_diagnostics_is_not_fabricated_or_resent(self):
        self.state.claim(account_key(f.ACCOUNT),f.DAY);result=self.run_mode()
        self.assertEqual(result['submissionAction'],'recheck');self.assertIsNone(result['submission']);self.assertTrue(result['priorAttempt']);self.assertEqual(self.transport.post_count,0)
    def test_claim_and_attempt_header_exist_before_network_call(self):
        def before():
            self.assertTrue(self.state.claimed(account_key(f.ACCOUNT),f.DAY))
            self.assertEqual(self.state.submission(account_key(f.ACCOUNT),f.DAY)['outcome'],'attempting')
        self.transport.before_post=before;self.run_mode()
    def test_cookie_save_error_does_not_erase_durable_original_error(self):
        self.transport.failure=(200,4709,'拒绝提交',False);self.transport.save_failure=True
        with self.assertRaises(ToolError):self.run_mode()
        self.assertEqual(self.state.submission(account_key(f.ACCOUNT),f.DAY)['apiCode'],4709)
    def test_existing_checked_in_record_is_only_read(self):
        self.transport.status='CHECKED_IN';result=self.run_mode()
        self.assertEqual(result['submissionAction'],'recheck');self.assertEqual(result['result'],'already_recorded');self.assertFalse(result['priorAttempt']);self.assertEqual(self.transport.post_count,0)
    def test_diagnose_and_prepare_do_not_create_submission_diagnostics(self):
        for mode in ('diagnose','prepare'):
            result=self.run_mode(mode);self.assertNotIn('submissionAction',result)
        self.assertIsNone(self.state.submission(account_key(f.ACCOUNT),f.DAY));self.assertEqual(self.transport.post_count,0)


class Redaction(unittest.TestCase):
    def test_known_secrets_raw_urlencoded_base64_and_escaped_are_hidden(self):
        account={**f.ACCOUNT,'password':'密码+Secret&123'}
        values=[account['password'],urllib.parse.quote(account['password'],safe=''),urllib.parse.quote_plus(account['password']),base64.b64encode(account['password'].encode()).decode(),json.dumps(account['password'],ensure_ascii=True)[1:-1],account['student_id'],account['browser_fingerprint'].lower()]
        result=school_message('拒绝 '+ ' '.join(values),account)
        for value in values:self.assertNotIn(value,result)
    def test_unknown_cookie_authorization_email_phone_and_identifiers_are_hidden(self):
        raw='学校拒绝\nCookie: SESSION=unknown-cookie; CASTGC=another-secret\nAuthorization: Bearer xyz-private\n邮箱 person@example.test 手机号=13812345678 token=abc-secret id=abcdef0123456789abcdef0123456789ab'
        result=school_message(raw)
        for value in ('unknown-cookie','another-secret','xyz-private','person@example.test','13812345678','abc-secret','abcdef0123456789abcdef0123456789ab'):self.assertNotIn(value,result)
        self.assertIn('学校拒绝',result)
    def test_html_controls_and_oversized_messages_are_not_persisted(self):
        result=school_message('&lt;script&gt;private-script&lt;/script&gt;失败\n\x1b[31m')
        self.assertNotIn('private-script',result);self.assertNotIn('<script>',result);self.assertNotIn('\x1b',result)
        self.assertLessEqual(len(school_message('错'*1000)),360)
        self.assertEqual(school_message('x'*8193),'学校错误信息过长，已省略')
    def test_schema_allows_only_safe_fields_and_preserves_zero_code(self):
        value=submission_details({'apiCode':0,'httpStatus':200,'outcome':'rejected','password':'secret','headers':{'Cookie':'secret'},'body':'private'})
        self.assertEqual(value,{'outcome':'rejected','httpStatus':200,'apiCode':0})
        self.assertIsNone(submission_details({'outcome':[],'httpStatus':True,'apiCode':False}))
        self.assertIsNone(verification_details({'status':{},'body':'private'}))


class DashboardDiagnostics(WebCase):
    def setup_runner(self,transport):
        instant=transport.instant
        self.worker.runner=lambda payload,mode,state,directory,**kwargs:run_account(payload,mode,state,directory,clock=lambda:instant,sleep=lambda _:None,emit=kwargs['emit'],run_id=kwargs['run_id'],transport_factory=lambda *args:transport)
    def setup_account(self):
        return self.add_account(location={'mode':'fixed','name':'Synthetic','latitude':0.0,'longitude':0.0,'coordinate_system':'gcj02','reverse_geocode':'Synthetic address'})
    def queued(self,account):return self.store.enqueue(self.u1,account['id'],'checkin')
    def test_job_api_persists_original_error_redacts_and_enforces_owner_access(self):
        account=self.setup_account();transport=DiagnosticTransport(now().replace(hour=22,minute=0,second=0,microsecond=0));transport.failure=(200,4709,'拒绝 '+f.ACCOUNT['password']+' '+f.ACCOUNT['browser_fingerprint']+' '+f.ACCOUNT['student_id'],False);self.setup_runner(transport)
        jid=self.queued(account);self.worker.run_one();job=self.store.jobs(self.u1,jid)
        self.assertEqual(job['diagnostics']['action'],'first_submit');self.assertEqual(job['diagnostics']['submission']['apiCode'],4709);self.assertEqual(len(job['diagnostics']['verification']),1)
        raw=self.req(self.c1,self.t1,'/api/jobs/'+jid).get_data(as_text=True)
        for secret in (f.ACCOUNT['password'],f.ACCOUNT['browser_fingerprint']):self.assertNotIn(secret,raw)
        self.assertEqual(self.req(self.c2,self.t2,'/api/jobs/'+jid).status_code,404);self.assertEqual(self.req(self.c2,self.t2,'/api/jobs').get_json()['jobs'],[])
        self.assertEqual(self.req(self.ac,self.at,'/api/jobs/'+jid).status_code,200)
        with self.store.db() as db:
            saved=db.execute('SELECT payload FROM web_job_diagnostics WHERE job_id=?',(jid,)).fetchone()[0]
            self.assertNotIn(f.ACCOUNT['password'],saved)
    def test_recheck_job_keeps_original_submission_id(self):
        account=self.setup_account();transport=DiagnosticTransport(now().replace(hour=22,minute=0,second=0,microsecond=0));transport.failure=(200,4709,'学校拒绝',False);self.setup_runner(transport)
        first=self.queued(account);self.worker.run_one()
        with self.store.db(True) as db:db.execute('UPDATE web_jobs SET created_at=0 WHERE id=?',(first,))
        second=self.queued(account);self.worker.run_one();a=self.store.jobs(self.u1,first);b=self.store.jobs(self.u1,second)
        self.assertEqual(b['diagnostics']['action'],'recheck');self.assertEqual(a['diagnostics']['submission'],b['diagnostics']['submission']);self.assertEqual(transport.post_count,1)
    def test_interrupted_job_has_diagnostics_even_without_finished_result(self):
        account=self.setup_account();transport=DiagnosticTransport(now().replace(hour=22,minute=0,second=0,microsecond=0));transport.failure=(200,4709,'学校拒绝',False)
        def interrupted(payload,mode,state,directory,**kwargs):
            def emit(event,**values):
                kwargs['emit'](event,**values)
                if event=='submission_result':raise KeyboardInterrupt()
            return run_account(payload,mode,state,directory,clock=lambda:transport.instant,sleep=lambda _:None,emit=emit,transport_factory=lambda *args:transport,run_id=kwargs['run_id'])
        self.worker.runner=interrupted;jid=self.queued(account)
        with self.assertRaises(KeyboardInterrupt):self.worker.run_one()
        job=self.store.jobs(self.u1,jid);self.assertEqual(job['state'],'running');self.assertEqual(job['diagnostics']['submission']['apiCode'],4709)
        self.store.recover_jobs();job=self.store.jobs(self.u1,jid);self.assertEqual(job['result']['reason'],'worker_interrupted');self.assertEqual(job['diagnostics']['action'],'first_submit')
    def test_pre_submit_error_is_marked_not_submitted(self):
        account=self.setup_account();jid=self.queued(account)
        def failure(*a,**kw):raise ToolError('session_rejected','today',5000,http_status=403,school_message='请重新登录 '+f.ACCOUNT['password'])
        self.worker.runner=failure;self.worker.run_one();job=self.store.jobs(self.u1,jid)
        self.assertEqual(job['diagnostics']['action'],'not_submitted');self.assertEqual(job['diagnostics']['error']['apiCode'],5000);self.assertNotIn(f.ACCOUNT['password'],json.dumps(job))
    def test_legacy_job_results_remain_unchanged_and_unclassified(self):
        account=self.setup_account();jid=self.queued(account);legacy={'result':'submission_unknown','reason':'record_not_confirmed'}
        with self.store.db(True) as db:db.execute("UPDATE web_jobs SET state='failed',result=? WHERE id=?",(json.dumps(legacy),jid))
        job=self.store.jobs(self.u1,jid);self.assertEqual(job['result'],legacy);self.assertIsNone(job['diagnostics'])
    def test_extra_fields_are_dropped_and_verification_history_is_bounded(self):
        account=self.setup_account();jid=self.queued(account);job={'id':jid}
        self.store.record_job_event(job,'submission_result',{'submission':{'httpStatus':200,'apiCode':4709,'schoolMessage':'错误','headers':{'cookie':'private'},'body':'private'}})
        for i in range(20):self.store.record_job_event(job,'verification',{'observation':{'attempt':1,'status':'PENDING','body':'private'}})
        saved=self.store.jobs(self.u1,jid)['diagnostics'];self.assertEqual(len(saved['verification']),4);self.assertNotIn('private',json.dumps(saved))

    def test_container_diagnostic_logging_never_contains_raw_secrets(self):
        account=self.setup_account();jid=self.queued(account);payload=self.store.job_payload({'account_id':account['id']})
        with self.assertLogs('moonuestc.diagnostics',level='WARNING') as captured:
            self.store.record_job_event({'id':jid},'submission_result',{'submission':{'outcome':'rejected','httpStatus':200,'apiCode':4709,'schoolMessage':'学校拒绝 '+payload['password']+' '+payload['browser_fingerprint']}},payload)
        raw=' '.join(captured.output);self.assertIn('4709',raw)
        self.assertNotIn(payload['password'],raw);self.assertNotIn(payload['browser_fingerprint'],raw)

    def test_response_error_is_persistent_if_cookie_cache_save_fails(self):
        account=self.setup_account();transport=DiagnosticTransport(now().replace(hour=22,minute=0,second=0,microsecond=0));transport.failure=(200,4709,'学校拒绝',False);transport.save_failure=True;self.setup_runner(transport)
        jid=self.queued(account);self.worker.run_one();job=self.store.jobs(self.u1,jid)
        self.assertEqual(job['result']['reason'],'encrypted_cookie_invalid')
        self.assertEqual(job['diagnostics']['submission']['apiCode'],4709)
        self.assertEqual(job['diagnostics']['action'],'first_submit')


class LoginErrorMetadata(unittest.TestCase):
    def test_http_200_login_rejection_is_not_misreported_as_school_business_code(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('MOON_TEST_TMP')) as directory:
            state=State(directory);transport=DiagnosticTransport();transport.login_rejected=True
            try:
                with self.assertRaises(ToolError) as caught:
                    run_account(copy.deepcopy(f.ACCOUNT),'checkin',state,directory,clock=lambda:f.INSTANT,sleep=lambda _:None,transport_factory=lambda *a:transport)
                self.assertEqual(caught.exception.reason,'login_rejected')
                self.assertEqual(caught.exception.http_status,200)
                self.assertIsNone(caught.exception.api_code)
                self.assertEqual(transport.post_count,0)
            finally:state.close()

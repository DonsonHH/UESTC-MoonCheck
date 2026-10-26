"""One operator recipient gets final errors and the selected owner's success."""
import datetime as dt
import json
import time
from unittest.mock import patch

import dashboard_helpers as fixtures
import test_class_bot as fake
from moonuestc.policy import SHANGHAI
from moonuestc.qq_bot import group_message
from moonuestc.support_service import SupportManager


class OperatorAlerts(fixtures.WebCase):
    def setUp(self):
        super().setUp();self.a=self.add_account();self.other=self.add_account(2,'202300000002')
        self.support=self.app.extensions['moon_support'];self.support.pool.shutdown();self.support.pool=None
        self.qq=fake.FakeQQ();self.support.qq_factory=lambda config:self.qq
        self.instant=dt.datetime(2026,10,26,23,0,tzinfo=SHANGHAI);self.support.clock=lambda:self.instant
        self.support.configure_bot({'app_id':'1000000001','app_secret':'synthetic-operator-secret-for-testing','enabled':True})
        self.stamp=time.time()
        self.config={'enabled':True,'openid':'synthetic-operator-recipient','owner_student_digest':self.store.vault.digest('student','202300000001'),'not_before':0}
        self.support.data.put('qq_operator',self.config)
    def job(self,account=None,result=None,mode='checkin'):
        account=account or self.a;user=self.u1 if account['id']==self.a['id'] else self.u2
        self.stamp+=30
        with patch('moonuestc.web_store.time.time',return_value=self.stamp),patch('moonuestc.web_store.now',return_value=self.instant):
            ident=self.store.enqueue(user,account['id'],mode,'manual',self.instant.date().isoformat())
        row=self.store.claim_job();self.assertEqual(row['id'],ident)
        value=result or {'result':'error','reason':'need_manual_mfa'}
        with patch('moonuestc.web_store.time.time',return_value=self.stamp):self.store.finish_job(row,value)
        return row,value
    def notify(self,*args,**values):
        row,result=self.job(*args,**values);self.support.after_job(row,result);return row
    def test_other_account_error_goes_to_only_operator_without_school_traffic(self):
        self.notify(self.other,{'result':'error','reason':'need_manual_mfa','schoolMessage':'private body must not be forwarded'})
        self.assertEqual(len(self.qq.messages),1)
        kind,target,text,_=self.qq.messages[0]
        self.assertEqual((kind,target),('user','synthetic-operator-recipient'))
        self.assertIn('需要处理',text);self.assertIn('202300000002',text);self.assertNotIn('private body',text)
    def test_owner_confirmed_success_only_once_per_day_and_not_other_students(self):
        result={'result':'confirmed','status':'CHECKED_IN'}
        self.notify(result=result);self.notify(result=result);self.notify(self.other,result)
        self.assertEqual(len(self.qq.messages),1);self.assertIn('签到已完成',self.qq.messages[0][2])
    def test_success_does_not_include_exemption_or_situation_report(self):
        self.notify(result={'result':'already_recorded','status':'EXEMPT'})
        self.notify(result={'result':'already_recorded','status':'STUDENT_REPORTED'})
        self.notify(result={'result':'auth_ready','status':'CHECKED_IN'},mode='diagnose')
        self.assertEqual(self.qq.messages,[])
    def test_tick_recovers_missed_final_hook_and_does_not_resend_after_restart(self):
        row,_=self.job(self.other);self.support.next_poll=0;self.support.tick()
        self.assertEqual(len(self.qq.messages),1)
        restarted=SupportManager(self.store,background=False,clock=lambda:self.instant,qq_factory=lambda config:self.qq)
        try:restarted.tick();restarted.after_job(row,{'result':'error'})
        finally:restarted.close()
        self.assertEqual(len(self.qq.messages),1)
    def test_disabled_operator_and_pre_activation_history_do_not_send(self):
        self.support.data.put('qq_operator',{**self.config,'enabled':False});self.notify()
        self.support.data.put('qq_operator',{**self.config,'not_before':10**12});self.notify()
        self.assertEqual(self.qq.messages,[])
    def test_unknown_delivery_is_not_retried_by_hook_or_tick(self):
        self.qq.fail=True;row=self.notify()
        for _ in range(2):self.support.next_poll=0;self.support.tick();self.support.after_job(row,{'result':'error'})
        self.assertEqual(len(self.qq.messages),1)
    def test_real_worker_completion_drives_operator_notification(self):
        self.worker.support_manager=self.support
        self.worker.runner=lambda *args,**values:{'result':'error','reason':'need_manual_captcha'}
        with patch('moonuestc.web_store.now',return_value=self.instant):
            ident=self.store.enqueue(self.u1,self.a['id'],'checkin','manual',self.instant.date().isoformat())
        with patch('moonuestc.web_service.now',return_value=self.instant):self.assertTrue(self.worker.run_one())
        self.assertEqual(len(self.qq.messages),1);self.assertIn('验证码',self.qq.messages[0][2])
        self.assertEqual(self.store.jobs(self.u1,ident)['state'],'failed')
    def test_queued_or_retry_pending_results_do_not_notify_until_final(self):
        row,_=self.job(result={'result':'retry_pending','reason':'timeout'})
        self.support.after_job(row,{'result':'retry_pending'});self.assertEqual(self.qq.messages,[])
        self.store.finish_job(row,{'result':'error','reason':'timeout','retryExhausted':True})
        self.support.after_job(row,{'result':'error'});self.assertEqual(len(self.qq.messages),1)
    def test_private_summary_never_exposes_recipient_and_old_student_routes_are_removed(self):
        summary=self.req(self.ac,self.at,'/api/qq/operator')
        self.assertEqual(summary.status_code,200,summary.json);self.assertTrue(summary.json['configured'])
        self.assertNotIn('synthetic-operator-recipient',summary.get_data(as_text=True))
        self.assertEqual(self.req(self.c1,self.t1,'/api/qq/operator').status_code,403)
        for url,method in (('/api/qq/reminder','GET'),('/api/qq/reminder','PATCH'),('/api/qq/binding','POST')):
            self.assertEqual(self.req(self.c1,self.t1,url,method,{} if method!='GET' else None).status_code,404)
        self.assertEqual(self.c1.get('/app/reminders',base_url=fixtures.ORIGIN).status_code,404)
    def test_zero_pending_message_celebrates_without_claiming_everyone_checked_in(self):
        text=group_message('2026-10-26',[])
        self.assertIn('🎉',text);self.assertIn('待处理名单已清零',text);self.assertNotIn('全部已签到',text)
    def test_slow_operator_transport_does_not_block_class_work(self):
        import threading
        started=threading.Event();release=threading.Event();class_done=threading.Event()
        manager=SupportManager(self.store,background=True)
        def blocked():started.set();release.wait(3)
        try:
            manager.submit('operator-slow',blocked);self.assertTrue(started.wait(1))
            manager.submit('class-timed',class_done.set);self.assertTrue(class_done.wait(1))
        finally:release.set();manager.close()

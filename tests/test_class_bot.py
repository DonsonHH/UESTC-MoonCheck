"""Class and QQ workflows use synthetic identities and no external services."""
import contextlib
import copy
import datetime as dt
import json
import time
import unittest
import urllib.parse
from unittest.mock import patch

import dashboard_helpers as fixtures
from moonuestc.class_cadre import CadreSchool,daily_remark,school_session
from moonuestc.errors import ToolError
from moonuestc.policy import SHANGHAI
from moonuestc.qq_bot import QQClient,QQError,signing_key,verified_callback,group_message
from moonuestc.support_store import SupportStore
from moonuestc.web_errors import WebError

DAY='2026-10-26'
TARGET='202300000099'


class FakeSchool:
    def __init__(self):
        self.rows=[{'studentSn':TARGET,'studentName':'合成同学乙','id':'synthetic-record-99','recordStatusCode':'PENDING','studentPhone':'synthetic-private-phone','dormitoryLocation':'synthetic-private-room'},
            {'studentSn':'202300000098','studentName':'合成同学丙','id':'synthetic-record-98','recordStatusCode':'NOT_CHECKIN'},
            {'studentSn':'202300000097','studentName':'合成同学丁','id':'synthetic-record-97','recordStatusCode':'CHECKED_IN'}]
        self.posts=[];self.failure=None;self.queries=0;self.permissions=True;self.today_status='CHECKED_IN'
    def api(self,path,*,stage,payload=None):
        self.queries+=1
        if path=='/class-cadre/my-classes':return [{'classKey':'synthetic-class','manageClass':'合成班级'}] if self.permissions else []
        if path.startswith('/class-cadre/checkin-list?'):
            q=urllib.parse.parse_qs(urllib.parse.urlsplit(path).query);index=int(q['pageIndex'][0]);return copy.deepcopy(self.rows[(index-1)*100:index*100])
        if path.startswith('/case-keyword/active?'):return [{'id':'synthetic-study-option','keyword':'学习','remarkRequired':True,'situationTypeCode':'CAMPUS'}]
        if path=='/class-cadre/situation/report':
            self.posts.append(copy.deepcopy(payload))
            if self.failure=='timeout':raise ToolError('timeout','class_report_post')
            for r in self.rows:
                if r['id']==payload[0]['recordId']:r['recordStatusCode']='STUDENT_REPORTED'
            if self.failure=='delivered_timeout':raise ToolError('timeout','class_report_post')
            return None
        raise AssertionError('Unexpected school endpoint '+path)
    def schedule(self):return {'effective':True,'studentReportStartOffsetMinute':1260,'studentReportEndOffsetMinute':1410}
    def today(self):return {'businessDate':DAY,'recordStatusCode':self.today_status,'abnormalFlag':False,'checkinTime':'22:00:00'}


class FakeQQ:
    def __init__(self):self.messages=[];self.fail=False
    def identity(self):return {'verified':True}
    def send(self,kind,target,text,**values):
        self.messages.append((kind,target,text,values))
        if self.fail:raise QQError('synthetic-rejection')
        return {'sent':True}
    def close(self):pass


class ClassBot(fixtures.WebCase):
    def setUp(self):
        super().setUp();self.account=self.add_account();self.aid=self.account['id'];self.school=FakeSchool();self.qq=FakeQQ()
        self.instant=dt.datetime(2026,10,26,22,0,tzinfo=SHANGHAI)
        self.support=self.app.extensions['moon_support'];self.support.pool.shutdown();self.support.pool=None
        self.support.clock=lambda:self.instant;self.support.qq_factory=lambda config:self.qq
        self.sessions=0
        @contextlib.contextmanager
        def session(store,aid,**values):
            self.sessions+=1;yield CadreSchool(self.school,lambda:self.instant)
        self.support.session_factory=session
        self.config={'class_key':'synthetic-class','class_name':'合成班级','targets':[TARGET],'members':{TARGET:'synthetic-member-99'},'report_enabled':True,'group_reminders':True,'group_openid':'synthetic-group'}
        self.support.data.put('cadre:'+self.aid,self.config,account_id=self.aid)
        self.support.configure_bot({'app_id':'1000000001','app_secret':'synthetic-bot-secret-for-testing','enabled':True})
        self.store.execution_window=('21:06','23:24')
    def parent_job(self):
        with patch('moonuestc.web_store.now',return_value=self.instant):
            jid=self.store.enqueue(self.u1,self.aid,'checkin','schedule',DAY)
        job=self.store.claim_job();self.store.finish_job(job,{'result':'confirmed','businessDate':DAY})
        with self.store.db(True) as db:db.execute('UPDATE web_accounts SET automatic=1 WHERE id=?',(self.aid,))
        return job
    def callback(self,event,*,tamper=False,old=False):
        config=self.support.data.get('qq_bot');raw=json.dumps(event,separators=(',',':')).encode();stamp=str(int(time.time())-(900 if old else 0))
        sig=signing_key(config['app_secret']).sign(stamp.encode()+raw).hex()
        if tamper:raw+=b' '
        return self.app.test_client().post('/api/qq/callback/'+config['callback_key'],base_url=fixtures.ORIGIN,data=raw,
            headers={'Content-Type':'application/json','X-Bot-Appid':config['app_id'],'X-Signature-Timestamp':stamp,'X-Signature-Ed25519':sig})
    def event(self,content,*,group=False,ident='synthetic-message-1'):
        return {'op':0,'id':ident,'t':'GROUP_AT_MESSAGE_CREATE' if group else 'C2C_MESSAGE_CREATE','d':{'id':ident,'content':content,
            'group_openid':'synthetic-group','author':{'user_openid':'synthetic-person','member_openid':'synthetic-member'}}}
    def test_class_page_is_owner_scoped_and_regular_users_cannot_enumerate(self):
        self.assertEqual(self.req(self.c2,self.t2,'/api/class/'+self.aid).status_code,404)
        self.support.data.put('cadre:'+self.aid,{},account_id=self.aid)
        self.assertEqual(self.req(self.c1,self.t1,'/api/class/'+self.aid).status_code,403)
        self.assertEqual(self.sessions,0)
    def test_snapshot_excludes_school_phone_dormitory_and_record_identifiers(self):
        response=self.req(self.c1,self.t1,'/api/class/'+self.aid);self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(response.json['pending_count'],2)
        raw=response.get_data(as_text=True)
        for text in ('synthetic-private-phone','synthetic-private-room','synthetic-record-99'):self.assertNotIn(text,raw)
    def test_admin_configuration_checks_real_class_members_and_revision(self):
        before=copy.deepcopy(self.support.data.cadre(self.aid))
        with self.assertRaises(WebError):self.support.configure_class(self.admin,self.aid,{'targets':['202300000096']})
        self.assertEqual(self.support.data.cadre(self.aid),before)
        with self.assertRaises(WebError) as raised:self.support.configure_class(self.admin,self.aid,{'if_match':'old-revision','targets':[]})
        self.assertEqual(raised.exception.code,'class_configuration_changed')
    def test_regular_owner_cannot_enable_class_report_or_change_mapping(self):
        response=self.req(self.c1,self.t1,'/api/class/'+self.aid,'PATCH',{'targets':[]})
        self.assertEqual(response.status_code,403);self.assertEqual(self.sessions,0)
    def test_report_requires_confirmed_scheduled_self_job(self):
        self.support.report_class(self.aid,DAY);self.assertEqual(self.school.posts,[]);self.assertEqual(self.sessions,0)
    def test_report_waits_for_time_then_records_only_selected_student_once(self):
        self.parent_job();self.instant=self.instant.replace(hour=20)
        self.support.report_class(self.aid,DAY);self.assertEqual(self.school.posts,[])
        self.instant=self.instant.replace(hour=22)
        self.support.report_class(self.aid,DAY);self.support.report_class(self.aid,DAY)
        self.assertEqual(len(self.school.posts),1)
        body=self.school.posts[0];self.assertEqual(len(body),1);self.assertEqual(body[0]['recordId'],'synthetic-record-99')
        self.assertEqual(body[0]['locationTypeCode'],'CAMPUS');self.assertGreaterEqual(len(body[0]['caseRemark']),10)
        self.assertEqual(self.school.rows[0]['recordStatusCode'],'STUDENT_REPORTED')
    def test_report_skips_existing_school_record(self):
        self.parent_job();self.school.rows[0]['recordStatusCode']='CHECKED_IN';self.support.report_class(self.aid,DAY)
        self.assertEqual(self.school.posts,[])
    def test_ambiguous_delivery_is_never_reposted_even_with_new_store(self):
        self.school.failure='timeout';api=CadreSchool(self.school,lambda:self.instant)
        first=api.report('synthetic-class',TARGET,DAY,self.support.data,self.aid,self.store.execution_window)
        self.assertEqual(first['result'],'submission_unknown')
        api.report('synthetic-class',TARGET,DAY,SupportStore(self.store),self.aid,self.store.execution_window)
        self.assertEqual(len(self.school.posts),1)
    def test_delivered_timeout_is_read_back_without_duplicate_write(self):
        self.school.failure='delivered_timeout';api=CadreSchool(self.school,lambda:self.instant)
        api.report('synthetic-class',TARGET,DAY,self.support.data,self.aid,self.store.execution_window)
        result=api.report('synthetic-class',TARGET,DAY,self.support.data,self.aid,self.store.execution_window)
        self.assertEqual(result['result'],'already_recorded');self.assertEqual(len(self.school.posts),1)
    def test_unknown_school_status_never_counts_as_success(self):
        self.school.rows[0]['recordStatusCode']='NEW_UNKNOWN'
        with self.assertRaises(ToolError):CadreSchool(self.school,lambda:self.instant).report('synthetic-class',TARGET,DAY,self.support.data,self.aid,self.store.execution_window)
        self.assertEqual(self.school.posts,[])
    def test_permission_loss_never_attempts_report(self):
        self.parent_job();self.school.permissions=False;self.support.report_class(self.aid,DAY)
        self.assertEqual(self.school.posts,[])
    def test_group_check_at_2310_mentions_everyone_and_lists_only_pending_students(self):
        self.instant=self.instant.replace(hour=23,minute=9);self.support.tick();self.assertEqual(self.qq.messages,[])
        self.instant=self.instant.replace(minute=10);self.support.next_poll=0;self.support.tick()
        self.support.next_poll=0;self.support.tick()
        self.assertEqual(len(self.qq.messages),1)
        kind,target,text,_=self.qq.messages[0];self.assertEqual((kind,target),('group','synthetic-group'))
        self.assertIn('2 位',text);self.assertIn('<qqbot-at-everyone />',text)
        self.assertNotIn('合成同学丁',text);self.assertIn(TARGET,text);self.assertIn('合成同学乙',text)
        self.assertIn('synthetic-private-room',text);self.assertNotIn('synthetic-private-phone',text)
        self.assertEqual(self.sessions,1)
    def test_failed_qq_delivery_cannot_spam_or_revert_school_results(self):
        self.qq.fail=True;self.instant=self.instant.replace(hour=23,minute=10)
        for _ in range(3):self.support.next_poll=0;self.support.tick()
        self.assertEqual(len(self.qq.messages),1);self.assertEqual(self.school.posts,[])
        self.assertTrue(any(r['state']=='failed' for r in self.support.data.runs(self.aid)))
    def test_no_qq_binding_means_no_personal_messages_and_disabled_by_default(self):
        response=self.req(self.c1,self.t1,'/api/qq/reminder');self.assertFalse(response.json['enabled']);self.assertFalse(response.json['linked'])
        self.assertEqual(self.req(self.c1,self.t1,'/api/qq/reminder','PATCH',{'enabled':True,'consent_version':'2026-10-26-qq-v1'}).status_code,409)
    def test_personal_binding_never_automatically_enables_reminders(self):
        code=self.support.data.new_code('personal',user_id=self.u1['id'])
        self.assertEqual(self.callback(self.event('绑定 '+code)).status_code,200)
        value=self.support.data.reminder(self.u1['id']);self.assertTrue(value['openid']);self.assertFalse(value['enabled'])
        self.assertFalse(self.support.data.reminder(self.u2['id'])['enabled'])
        self.assertEqual(self.req(self.c1,self.t1,'/api/qq/reminder','PATCH',{'enabled':True}).status_code,428)
        response=self.req(self.c1,self.t1,'/api/qq/reminder','PATCH',{'enabled':True,'consent_version':'2026-10-26-qq-v1'})
        self.assertEqual(response.status_code,200,response.json);self.assertTrue(response.json['enabled']);self.assertNotIn('synthetic-person',response.get_data(as_text=True))
    def test_group_event_cannot_consume_personal_code(self):
        code=self.support.data.new_code('personal',user_id=self.u1['id'])
        self.callback(self.event('绑定 '+code,group=True))
        self.assertFalse(self.support.data.reminder(self.u1['id']).get('openid'))
        self.callback(self.event('绑定 '+code,ident='synthetic-message-2'))
        self.assertTrue(self.support.data.reminder(self.u1['id']).get('openid'))
    def test_group_binding_code_is_single_use_and_only_updates_its_class(self):
        code=self.support.data.new_code('group',account_id=self.aid)
        self.assertEqual(self.callback(self.event('绑定班级 '+code,group=True)).status_code,200)
        self.assertEqual(self.support.data.cadre(self.aid)['group_openid'],'synthetic-group')
        self.assertFalse(self.support.data.bind_code(code,{'kind':'group','target':'another-group','sender':'another-member'}))
    def test_signature_tampering_stale_signature_and_duplicates(self):
        event=self.event('身份',group=True)
        self.assertEqual(self.callback(event,tamper=True).status_code,403)
        self.assertEqual(self.callback(event,old=True).status_code,403)
        self.assertEqual(self.qq.messages,[])
        self.assertEqual(self.callback(event).status_code,200);self.assertEqual(self.callback(event).status_code,200)
        self.assertEqual(len(self.qq.messages),1)
    def test_callback_challenge_is_restricted_and_does_not_dispatch_events(self):
        config=self.support.data.get('qq_bot');event={'op':13,'d':{'plain_token':'SyntheticChallenge123','event_ts':str(int(time.time()))}}
        raw=json.dumps(event).encode();response=self.app.test_client().post('/api/qq/callback/'+config['callback_key'],base_url=fixtures.ORIGIN,data=raw,headers={'X-Bot-Appid':config['app_id']})
        self.assertEqual(response.status_code,200,response.json);self.assertIn('signature',response.json)
        event['d']['plain_token']='{"op":0}'
        with self.assertRaises(WebError):verified_callback(config,{'X-Bot-Appid':config['app_id']},json.dumps(event).encode())
        self.assertEqual(self.qq.messages,[])
    def test_bot_secrets_are_encrypted_and_never_returned(self):
        response=self.req(self.ac,self.at,'/api/qq/settings');self.assertEqual(response.status_code,200,response.json)
        self.assertNotIn('synthetic-bot-secret-for-testing',response.get_data(as_text=True))
        with self.store.db() as db:
            raw=db.execute("SELECT payload FROM web_support_settings WHERE name='qq_bot'").fetchone()[0]
        self.assertNotIn(b'synthetic-bot-secret-for-testing',raw)
        self.assertEqual(self.req(self.c1,self.t1,'/api/qq/settings').status_code,403)
    def test_private_mapping_and_tokens_follow_account_deletion(self):
        self.support.data.new_code('group',account_id=self.aid)
        self.store.delete_account(self.u1,self.aid)
        self.assertEqual(self.support.data.cadre(self.aid),{})
        with self.store.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM web_support_tokens').fetchone()[0],0)
    def test_personal_2310_is_opt_in_and_truthful(self):
        self.support.data.put('cadre:'+self.aid,{**self.config,'group_reminders':False},account_id=self.aid)
        self.support.data.put('reminder:'+str(self.u1['id']),{'enabled':True,'openid':'synthetic-person','consent_version':'2026-10-26-qq-v1'},user_id=self.u1['id'])
        self.instant=self.instant.replace(hour=23,minute=10);self.school.today_status='PENDING'
        for _ in range(2):self.support.next_poll=0;self.support.tick()
        self.assertEqual(len(self.qq.messages),1);self.assertEqual(self.qq.messages[0][0],'user');self.assertIn('尚未记录',self.qq.messages[0][2]);self.assertEqual(self.school.posts,[])
    def test_stop_command_only_disables_the_matching_person(self):
        for user,openid in ((self.u1,'synthetic-person'),(self.u2,'synthetic-other-person')):
            self.support.data.put('reminder:'+str(user['id']),{'enabled':True,'openid':openid},user_id=user['id'])
        self.callback(self.event('取消提醒'))
        self.assertFalse(self.support.data.reminder(self.u1['id'])['enabled']);self.assertTrue(self.support.data.reminder(self.u2['id'])['enabled'])
    def test_remark_is_truthful_dated_and_unique_each_day(self):
        values=[daily_remark((dt.date(2026,10,26)+dt.timedelta(days=i)).isoformat()) for i in range(60)]
        self.assertEqual(len(set(values)),60)
        self.assertTrue(all(len(v)>=10 and '校内' in v and '学习' in v for v in values))
    def test_pause_while_school_is_read_cancels_class_write(self):
        self.parent_job();original=self.school.api
        def changed(path,**values):
            result=original(path,**values)
            if path.startswith('/case-keyword/'):
                with self.store.db(True) as db:db.execute('UPDATE web_accounts SET automatic=0 WHERE id=?',(self.aid,))
            return result
        self.school.api=changed;self.support.report_class(self.aid,DAY)
        self.assertEqual(self.school.posts,[])
    def test_disabling_group_reminders_during_read_prevents_delivery(self):
        self.instant=self.instant.replace(hour=23,minute=10);original=self.school.api
        def changed(path,**values):
            result=original(path,**values)
            if path.startswith('/class-cadre/checkin-list'):
                self.support.data.put('cadre:'+self.aid,{**self.config,'group_reminders':False},account_id=self.aid)
            return result
        self.school.api=changed;self.support.remind_class(self.aid,DAY);self.assertEqual(self.qq.messages,[])
    def test_disabling_personal_reminder_during_read_prevents_delivery(self):
        self.instant=self.instant.replace(hour=23,minute=10)
        self.support.data.put('reminder:'+str(self.u1['id']),{'enabled':True,'openid':'synthetic-person','consent_version':'2026-10-26-qq-v1'},user_id=self.u1['id'])
        original=self.school.today
        def changed():
            value=self.support.data.reminder(self.u1['id']);value['enabled']=False
            self.support.data.put('reminder:'+str(self.u1['id']),value,user_id=self.u1['id']);return original()
        self.school.today=changed;self.support.remind_person(self.u1['id'],DAY);self.assertEqual(self.qq.messages,[])
    def test_delayed_or_old_day_reminders_do_not_send(self):
        self.support.remind_class(self.aid,DAY)
        self.instant=self.instant.replace(hour=23,minute=17);self.support.remind_class(self.aid,DAY)
        self.instant=self.instant.replace(minute=10);self.support.remind_class(self.aid,'2026-10-25')
        self.assertEqual(self.qq.messages,[]);self.assertEqual(self.sessions,0)
    def test_school_session_always_saves_cookie_changes_even_on_failure(self):
        from unittest.mock import Mock
        transport=Mock();school=Mock();school.connect.side_effect=ToolError('timeout','portal_warmup')
        with patch('moonuestc.class_cadre.EncryptedTransport',return_value=transport),patch('moonuestc.class_cadre.School',return_value=school):
            with self.assertRaises(ToolError):
                with school_session(self.store,self.aid,clock=lambda:self.instant):self.fail('Failed login cannot yield a school session')
        transport.save.assert_called_once()
    def test_test_group_binding_never_activates_or_replaces_formal_group(self):
        before=copy.deepcopy(self.support.data.cadre(self.aid));code=self.support.data.new_code('group_test',account_id=self.aid)
        event=self.event('绑定测试群 '+code,group=True);event['d']['group_openid']='synthetic-test-group'
        self.assertEqual(self.callback(event).status_code,200)
        self.assertEqual(self.support.data.cadre(self.aid),before)
        self.assertEqual(self.support.data.get('qq_test_destination')['group_openid'],'synthetic-test-group')
    def test_changing_formal_group_clears_old_group_member_mappings(self):
        code=self.support.data.new_code('group',account_id=self.aid);event=self.event('绑定班级 '+code,group=True)
        event['d']['group_openid']='synthetic-new-formal-group';self.callback(event)
        self.assertEqual(self.support.data.cadre(self.aid)['members'],{})
    def test_cancelled_member_mapping_flow_no_longer_collects_target_identity(self):
        event=self.event('成员身份',group=True);event['d']['mentions']=[{'member_openid':'synthetic-classmate','bot':False}]
        self.callback(event)
        self.assertEqual(self.qq.messages,[]);self.assertEqual(self.support.data.contacts(),[])
    def test_unbound_formal_group_still_retains_daily_count_without_sending_to_test(self):
        self.support.data.put('cadre:'+self.aid,{**self.config,'group_openid':'','group_reminders':False},account_id=self.aid)
        self.support.data.put('qq_test_destination',{'group_openid':'synthetic-test-group','openid':'synthetic-operator'})
        self.instant=self.instant.replace(hour=23,minute=10);self.support.next_poll=0;self.support.tick()
        self.assertEqual(self.qq.messages,[])
        runs=self.support.data.runs(self.aid);self.assertEqual(runs[0]['result']['pending'],2);self.assertEqual(runs[0]['result']['delivery'],'disabled')
    def test_expired_identity_metadata_is_pruned_without_new_messages(self):
        self.support.data.contact({'kind':'group','target':'synthetic-group','sender':'synthetic-member'})
        self.support.data.once_event('synthetic-expired-event')
        self.support.data.new_code('group',account_id=self.aid)
        with self.store.db(True) as db:
            db.execute('UPDATE web_qq_contacts SET updated_at=?',(time.time()-8*86400,))
            db.execute('UPDATE web_qq_events SET created_at=?',(time.time()-8*86400,))
            db.execute('UPDATE web_support_tokens SET expires_at=0')
        self.assertEqual(self.support.data.contacts(),[])
        self.support.next_poll=0;self.support.tick()
        with self.store.db() as db:
            for table in ('web_qq_contacts','web_qq_events','web_support_tokens'):
                self.assertEqual(db.execute('SELECT count(*) FROM '+table).fetchone()[0],0)
    def test_marked_test_group_cannot_be_activated_as_formal(self):
        self.support.data.put('qq_test_destination',{'group_openid':'synthetic-group','openid':'synthetic-operator'})
        self.support.data.put('cadre:'+self.aid,{**self.config,'group_openid':'','group_reminders':False},account_id=self.aid)
        code=self.support.data.new_code('group',account_id=self.aid);self.callback(self.event('绑定班级 '+code,group=True))
        self.assertFalse(self.support.data.cadre(self.aid).get('group_openid'))
    def test_misconfigured_test_destination_never_receives_class_details(self):
        self.support.data.put('qq_test_destination',{'group_openid':'synthetic-group','openid':'synthetic-operator'})
        self.instant=self.instant.replace(hour=23,minute=10);self.support.remind_class(self.aid,DAY)
        self.assertEqual(self.qq.messages,[])
        self.assertEqual(self.support.data.runs(self.aid)[0]['result']['pending'],2)

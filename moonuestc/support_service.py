"""Class reports and opt-in QQ delivery, separate from personal check-in jobs."""
import copy
import json
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .class_cadre import school_session,daily_remark,PENDING
from .errors import ToolError
from .policy import now,valid_today,TERMINAL
from .qq_bot import QQClient,QQError,event_context,group_message,identifier,verified_callback
from .support_store import SupportStore
from .web_errors import WebError


class SupportManager:
    def __init__(self,store,*,session_factory=school_session,qq_factory=QQClient,clock=now,background=True):
        self.store=store;self.data=SupportStore(store);self.session_factory=session_factory;self.qq_factory=qq_factory;self.clock=clock
        self.background=background;self.pool=ThreadPoolExecutor(max_workers=1,thread_name_prefix='moon-support') if background else None
        self.lock=threading.RLock();self.pending=set();self.client=None;self.client_key=None;self.next_poll=0;self.next_prune=0;self.closed=False
    def session(self,account_id):return self.session_factory(self.store,account_id,clock=self.clock)
    def client_for_bot(self):
        config=self.data.get('qq_bot')
        if not config.get('enabled') or not config.get('app_id') or not config.get('app_secret'):raise QQError('qq_not_configured')
        key=self.store.vault.digest('qq_client',config['app_id']+config['app_secret'])
        with self.lock:
            if key!=self.client_key:
                if self.client:self.client.close()
                self.client=self.qq_factory(config);self.client_key=key
            return self.client
    def bot_summary(self,origin):
        value=self.data.get('qq_bot')
        return {'configured':bool(value.get('app_id') and value.get('app_secret')),'enabled':bool(value.get('enabled')),
            'callback_url':origin+'/api/qq/callback/'+value['callback_key'] if value.get('callback_key') else '',
            'last_verified_at':value.get('verified_at'),'last_callback':value.get('last_callback')}
    def configure_bot(self,data):
        if not isinstance(data,dict) or set(data)-{'app_id','app_secret','enabled'}:raise WebError(400,'invalid_fields','机器人参数不正确。')
        value=self.data.get('qq_bot');value.update(data)
        if not isinstance(value.get('app_id'),str) or not re.fullmatch('[0-9]{6,20}',value['app_id']) or not isinstance(value.get('app_secret'),str) or not 16<=len(value['app_secret'])<=128 or type(value.get('enabled',False)) is not bool:
            raise WebError(400,'invalid_bot_credentials','请检查机器人凭据。')
        value.setdefault('callback_key',secrets.token_hex(32));self.data.put('qq_bot',value)
    def probe_bot(self):
        self.client_for_bot().identity();value=self.data.get('qq_bot');value['verified_at']=time.time();self.data.put('qq_bot',value)
        return {'verified':True}
    def feature_summary(self,actor):
        with self.store.db() as db:
            row=db.execute('SELECT id FROM web_accounts WHERE owner_id=?',(actor['id'],)).fetchone()
        cadre=bool(row and self.data.cadre(row['id']))
        return {'class_management':cadre,'qq_available':bool(self.data.get('qq_bot').get('enabled'))}
    def class_snapshot(self,actor,account_id):
        self.data.owner(actor,account_id,require_cadre=actor['role']!='admin')
        with self.session(account_id) as school:
            classes=school.classes();config=self.data.cadre(account_id)
            key=config.get('class_key') or (classes[0]['class_key'] if len(classes)==1 else '')
            roster=school.roster(key,self.clock().date().isoformat()) if key else []
        return {'classes':classes,'students':[{k:r[k] for k in ('student_id','name','status')} for r in roster],
            'business_date':self.clock().date().isoformat(),'pending_count':sum(r['status'] in PENDING for r in roster),
            'settings':config,'configuration_revision':self.class_revision(config),'test_group_bound':bool(self.data.get('qq_test_destination').get('group_openid')),
            'runs':self.data.runs(account_id),'remark_preview':daily_remark(self.clock().date().isoformat())}
    def class_revision(self,value):return self.store.vault.digest('class_settings',json.dumps(value,sort_keys=True,separators=(',',':')))
    def configure_class(self,actor,account_id,data):
        if actor['role']!='admin':raise WebError(403,'admin_required','班级自动填报由管理员配置。')
        self.data.owner(actor,account_id,require_cadre=False)
        allowed={'class_key','targets','report_enabled','group_reminders','nightly_check','members','group_openid','if_match'}
        if not isinstance(data,dict) or set(data)-allowed:raise WebError(400,'invalid_fields','班级参数不正确。')
        current=self.data.cadre(account_id)
        expected=data.get('if_match',self.class_revision(current))
        if expected!=self.class_revision(current):raise WebError(409,'class_configuration_changed','班级设置已更新，请刷新后再保存。')
        data={k:v for k,v in data.items() if k!='if_match'}
        value={**{'targets':[],'report_enabled':False,'group_reminders':False,'nightly_check':True,'members':{},'group_openid':''},**current,**copy.deepcopy(data)}
        if any(type(value.get(k)) is not bool for k in ('report_enabled','group_reminders','nightly_check')):raise WebError(400,'invalid_fields','开关参数不正确。')
        if not isinstance(value.get('class_key'),str) or not isinstance(value['targets'],list) or len(value['targets'])>100 or not all(isinstance(s,str) and re.fullmatch('[0-9]{8,20}',s) for s in value['targets']):raise WebError(400,'invalid_class_targets','请选择班级中的学生。')
        if not isinstance(value['members'],dict) or len(value['members'])>300:raise WebError(400,'invalid_members','QQ 映射不正确。')
        try:
            for member in value['members'].values():identifier(member)
            if value['group_openid']:identifier(value['group_openid'])
        except QQError:raise WebError(400,'invalid_qq_identifier','请使用机器人返回的 QQ OpenID。') from None
        if len(set(value['members'].values()))!=len(value['members']):raise WebError(400,'duplicate_member','同一班级成员不能绑定到多位学生。')
        with self.session(account_id) as school:
            classes=school.classes();rows=school.roster(value['class_key'],self.clock().date().isoformat())
            roster={r['student_id']:r for r in rows}
            if not set(value['targets'])<=set(roster) or not set(value['members'])<=set(roster):raise WebError(400,'class_target_not_found','学生不在此账号有权管理的班级。')
            if value['report_enabled']:school.study_option()
        value['class_name']=next(r['name'] for r in classes if r['class_key']==value['class_key'])
        with self.store.db(True) as db:
            if self.class_revision(self.data.get('cadre:'+account_id,db=db))!=expected:raise WebError(409,'class_configuration_changed','班级设置已更新，请刷新后再保存。')
            self.data.put('cadre:'+account_id,value,account_id=account_id,db=db)
            self.store._audit(db,actor,'class_settings_updated',account_id)
        return value
    def reminder_summary(self,actor):
        value=self.data.reminder(actor['id'])
        return {'enabled':bool(value.get('enabled')),'linked':bool(value.get('openid')),'last_status':value.get('last_status'),
            'available':bool(self.data.get('qq_bot').get('enabled')),'at':'23:10','consent_version':'2026-10-26-qq-v1'}
    def configure_reminder(self,actor,data):
        if not isinstance(data,dict) or set(data)-{'enabled','consent_version','unbind'} or type(data.get('enabled',False)) is not bool:raise WebError(400,'invalid_fields','提醒参数不正确。')
        value=self.data.reminder(actor['id'])
        if data.get('unbind'):
            self.data.put('reminder:'+str(actor['id']),{'enabled':False},user_id=actor['id']);return self.reminder_summary(actor)
        if data.get('enabled'):
            if data.get('consent_version')!='2026-10-26-qq-v1':raise WebError(428,'qq_consent_required','请先确认 QQ 提醒说明。')
            if not value.get('openid'):raise WebError(409,'qq_binding_required','请先添加并绑定机器人。')
            if not self.data.get('qq_bot').get('enabled'):raise WebError(409,'qq_not_available','机器人暂未启用。')
            value.update(consent_version=data['consent_version'],accepted_at=time.time())
        value['enabled']=data.get('enabled',False);self.data.put('reminder:'+str(actor['id']),value,user_id=actor['id'])
        return self.reminder_summary(actor)
    def submit(self,key,function):
        with self.lock:
            if self.closed or key in self.pending or len(self.pending)>=32:return
            self.pending.add(key)
        def run():
            try:function()
            except Exception:pass  # No raw network errors, school records or credentials in logs.
            finally:
                with self.lock:self.pending.discard(key)
        if self.pool:self.pool.submit(run)
        else:run()
    def callback(self,key,headers,raw):
        config=self.data.get('qq_bot')
        if not config.get('enabled') or not secrets.compare_digest(key,config.get('callback_key','')):raise WebError(404,'not_found','请求地址不存在。')
        response,event=verified_callback(config,headers,raw)
        context=event_context(event) if event else None
        kind=(event or {}).get('t','VALIDATION')
        if not isinstance(kind,str) or not re.fullmatch('[A-Z_]{1,80}',kind):kind='UNKNOWN_EVENT'
        # Retain only delivery metadata, never raw events or chat content.
        with self.store.db(True) as db:
            current=self.data.get('qq_bot',db=db)
            if current.get('callback_key')==key:
                current['last_callback']={'at':time.time(),'event_type':kind,'message_parsed':bool(context),'mention_count':len((context or {}).get('mentioned_members',[]))}
                self.data.put('qq_bot',current,db=db)
        if event:
            event_id=event.get('id') or (context or {}).get('msg_id')
            if context and isinstance(event_id,str) and len(event_id)<=1200 and self.data.once_event(event_id):
                content=context['content'];reply=None
                if content in ('身份','我的身份'):
                    self.data.contact(context)
                    reply=('本群标识：'+context['target']+'\n你的群成员标识：'+context['sender']) if context['kind']=='group' else '你的私聊标识：'+context['sender']
                elif re.fullmatch(r'(?:绑定|绑定班级|绑定测试群)\s+[A-Fa-f0-9]{16}',content):
                    success=self.data.bind_code(content.split()[-1],context)
                    if success:self.data.contact(context)
                    reply=('测试群已连接，不会接收正式班级状态。' if success=='group_test' else '正式班级群已绑定；每日提醒使用 @全体与未签到名单，请确保机器人有管理员权限。' if context['kind']=='group' else 'QQ 已绑定；请返回网页，自行开启每日提醒。') if success else '绑定码无效、过期或场景不匹配，请重新生成。'
                elif content in ('取消提醒','停止提醒') and context['kind']=='user':
                    for uid,value in self.data.reminders():
                        if value.get('openid')==context['sender']:
                            value['enabled']=False;self.data.put('reminder:'+str(uid),value,user_id=uid)
                    reply='个人提醒已关闭。'
                if reply:self.submit('reply:'+self.store.vault.digest('event_reply',event_id),lambda:self.client_for_bot().send(context['kind'],context['target'],reply,msg_id=context['msg_id']))
        return response
    def after_job(self,job,result):
        if job['mode']=='checkin' and job['source']=='schedule' and result.get('result') in ('confirmed','already_recorded'):
            config=self.data.cadre(job['account_id'])
            if config.get('report_enabled') and config.get('targets'):
                self.submit('class:'+job['account_id'],lambda:self.report_class(job['account_id'],job['business_date']))
    def report_allowed(self,account_id,class_key,student=None):
        config=self.data.cadre(account_id)
        with self.store.db() as db:
            row=db.execute('SELECT a.enabled,a.automatic,a.owner_id,u.active,u.role FROM web_accounts a JOIN web_users u ON u.id=a.owner_id WHERE a.id=?',(account_id,)).fetchone()
        if not row or not row['enabled'] or not row['automatic'] or not row['active'] or not config.get('report_enabled') or config.get('class_key')!=class_key or student is not None and student not in config.get('targets',[]):
            raise ToolError('class_configuration_changed','class_report')
        if self.store.require_notice and not self.store.notice_accepted({'id':row['owner_id'],'role':row['role']}):raise ToolError('privacy_consent_required','class_report')
    def report_class(self,account_id,day):
        if self.clock().date().isoformat()!=day:return
        bounds=self.store.execution_window or ('21:06','23:24')
        if not bounds[0]<=self.clock().strftime('%H:%M')<=bounds[1]:return
        config=self.data.cadre(account_id)
        if not config.get('report_enabled') or not config.get('targets'):return
        # The bundle is only driven by a school-confirmed scheduled self-job.
        with self.store.db() as db:
            job=db.execute("SELECT result FROM web_jobs WHERE account_id=? AND business_date=? AND source='schedule' AND mode='checkin' AND state='done'",(account_id,day)).fetchone()
        if not job or (json.loads(job['result']) if job['result'] else {}).get('result') not in ('confirmed','already_recorded'):return
        ident,fresh,_=self.data.begin(account_id,'class_bundle',day,account_id=account_id)
        if not fresh:return
        try:
            with self.session(account_id) as school:
                school.check_window(day,self.store.execution_window)
                results=[]
                for student in config['targets']:
                    # Recheck settings before every side effect; pause/removal takes effect.
                    latest=self.data.cadre(account_id)
                    if not latest.get('report_enabled') or latest.get('class_key')!=config['class_key'] or student not in latest.get('targets',[]):break
                    results.append(school.report(config['class_key'],student,day,self.data,account_id,self.store.execution_window,
                        before_submit=lambda student=student:self.report_allowed(account_id,config['class_key'],student)))
            self.data.finish(ident,{'result':'class_processed','targets':len(results),'reported':sum(r['result']=='class_reported' for r in results),
                'already_recorded':sum(r['result']=='already_recorded' for r in results),'unconfirmed':sum(r['result']=='submission_unknown' for r in results)})
            return results
        except ToolError as error:self.data.finish(ident,{'result':'class_failed','reason':error.reason},'failed')
    def send_once(self,scope,kind,day,target,text,account_id=None):
        ident,fresh,_=self.data.begin(scope,kind,day,account_id=account_id,initial={'result':'delivery_unknown'})
        if not fresh:return
        try:self.client_for_bot().send('group' if kind=='group_reminder' else 'user',target,text)
        except QQError as error:
            self.data.finish(ident,{'result':'notification_failed','code':error.code,'httpStatus':error.http},'failed');return 'failed'
        self.data.finish(ident,{'result':'notification_sent'});return 'sent'
    def remind_class(self,account_id,day):
        if not self.reminder_window(day):return
        config=self.data.cadre(account_id)
        if not config.get('class_key') or not config.get('nightly_check',True):return
        ident,fresh,_=self.data.begin(account_id,'group_check',day,account_id=account_id)
        if not fresh:return
        try:
            with self.session(account_id) as school:rows=school.roster(config['class_key'],day)
            unknown=sum(r['status'] not in TERMINAL|PENDING for r in rows)
            if unknown:raise ToolError('unknown_record_status','class_roster')
            pending=[r for r in rows if r['status'] in PENDING]
            if not self.reminder_window(day):
                self.data.finish(ident,{'result':'class_read_failed','reason':'reminder_window_expired'},'failed');return
            latest=self.data.cadre(account_id)
            state='disabled'
            test_group=self.data.get('qq_test_destination').get('group_openid')
            if self.data.get('qq_bot').get('enabled') and latest.get('group_reminders') and latest.get('group_openid') and latest.get('group_openid')!=test_group and latest.get('group_openid')==config.get('group_openid') and latest.get('class_key')==config['class_key']:
                state=self.send_once(account_id,'group_reminder',day,config['group_openid'],group_message(day,pending),account_id)
            self.data.finish(ident,{'result':'class_checked','total':len(rows),'pending':len(pending),'delivery':state})
        except ToolError as error:
            self.data.finish(ident,{'result':'class_read_failed','reason':error.reason},'failed')
    def remind_person(self,user_id,day):
        if not self.reminder_window(day):return
        config=self.data.reminder(user_id)
        if not config.get('enabled') or not config.get('openid') or config.get('consent_version')!='2026-10-26-qq-v1':return
        with self.store.db() as db:
            row=db.execute('SELECT a.id,u.role FROM web_accounts a JOIN web_users u ON u.id=a.owner_id WHERE a.owner_id=? AND a.enabled=1 AND u.active=1',(user_id,)).fetchone()
        if not row or self.store.require_notice and not self.store.notice_accepted({'id':user_id,'role':row['role']}):return
        ident,fresh,_=self.data.begin(str(user_id),'personal_check',day,account_id=row['id'])
        if not fresh:return
        try:
            with self.session(row['id']) as school:status=valid_today(school.school.today(),self.clock())
            labels={'CHECKED_IN':'学校已确认今日签到','STUDENT_REPORTED':'学校已登记本人情况说明','INSTRUCTOR_REPORTED':'学校已登记情况说明','EXEMPT':'学校记录为免签到','PENDING':'学校尚未记录今日签到，请在截止前处理'}
            text=f'晚安成电 · {day} 23:10\n'+labels.get(status,'学校已有今日记录')
        except ToolError:text=f'晚安成电 · {day} 23:10\n暂时无法核实学校记录，请自行打开学校小程序确认。'
        latest=self.data.reminder(user_id)
        if not self.reminder_window(day) or not latest.get('enabled') or latest.get('openid')!=config['openid']:
            self.data.finish(ident,{'result':'reminder_cancelled'});return
        state=self.send_once(str(user_id),'personal_reminder',day,config['openid'],text,row['id'])
        self.data.finish(ident,{'result':'personal_checked','delivery':state})
        if state:
            latest=self.data.reminder(user_id);latest['last_status']=state;self.data.put('reminder:'+str(user_id),latest,user_id=user_id)
    def reminder_window(self,day):
        instant=self.clock();return instant.date().isoformat()==day and '23:10'<=instant.strftime('%H:%M')<'23:16'
    def tick(self):
        if self.closed or time.monotonic()<self.next_poll:return
        self.next_poll=time.monotonic()+20;instant=self.clock();day=instant.date().isoformat();clock=instant.strftime('%H:%M')
        if time.monotonic()>=self.next_prune:
            self.data.prune();self.next_prune=time.monotonic()+60
        for row,config in self.data.cadres():
            if not row['enabled'] or not row['active']:continue
            if self.store.require_notice and not self.store.notice_accepted({'id':row['owner_id'],'role':row['role']}):continue
            if config.get('report_enabled') and '21:06'<=clock<='23:24':
                # Recheck-only calls are bounded to once per minute after restart.
                with self.store.db() as db:
                    own=db.execute("SELECT result FROM web_jobs WHERE account_id=? AND business_date=? AND source='schedule' AND mode='checkin' AND state='done'",(row['id'],day)).fetchone()
                if own and json.loads(own['result'] or '{}').get('result') in ('confirmed','already_recorded'):
                    self.submit('class:'+row['id'],lambda aid=row['id']:self.report_class(aid,day))
            if '23:10'<=clock<'23:16' and config.get('nightly_check',True):
                self.submit('group:'+row['id'],lambda aid=row['id']:self.remind_class(aid,day))
        if '23:10'<=clock<'23:16' and self.data.get('qq_bot').get('enabled'):
            for uid,config in self.data.reminders():
                if config.get('enabled'):self.submit('personal:'+str(uid),lambda uid=uid:self.remind_person(uid,day))
    def close(self):
        self.closed=True
        if self.pool:self.pool.shutdown(wait=True,cancel_futures=True)
        if self.client:self.client.close()

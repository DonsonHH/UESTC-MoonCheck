"""One school-request worker for dashboard jobs and daily scheduling."""
import threading
import json
import time

from .errors import ToolError
from .diagnostics import error_details
from .policy import clock_minutes,now
from .runner import account_key,run_account
from .state import State,execution_lock
from .vault import EncryptedTransport
from .web_errors import WebError
from .daily_plan import planned_time
from .scheduling import slot_target

RETRY_REASONS={'session_rejected','portal_session_rejected','micro_app_unauthorized','timeout','network_error','connection_error','http_error','invalid_json','record_not_confirmed','worker_internal_error','dns_error','reserved_slot_expired','reverse_geocode_unavailable'}
RETRY_REASONS.update({'wechat_code_transport_failed','wechat_network_unavailable','wechat_poll_timeout',
    'wechat_refresh_failed','wechat_protocol_login_failed','wechat_http_failure','wechat_login_buffer_failed'})


class WebWorker:
    def __init__(self,store,runner=None,gap_seconds=20):
        self.store=store
        self.runner=runner or run_account
        self.gap_seconds=max(20,gap_seconds)
        self.stop_event=threading.Event()
        self.thread=None
        self.next_job_at=0
        self.wechat_manager=None
        self.support_manager=None

    def schedule_once(self):
        state=State(self.store.directory)
        try:
            if state.school_client_requirement() and self.wechat_manager is None:return
        finally:state.close()
        instant=now()
        minute=instant.hour*60+instant.minute
        day=instant.date().isoformat()
        self.store.ensure_slots(day=day)
        for row in self.store.automatic_accounts(day):
            try:
                payload=self.store.vault.open(row['payload'],'account:'+row['id'])
                if self.wechat_manager:
                    from .wechat_authorization import authorization_eligible
                    if not authorization_eligible(payload):continue
                if not self.store.location_open(payload):continue
                school_window=(json.loads(row['last_result']) if row.get('last_result') else {}).get('checkinWindow')
                target=planned_time(payload,row['run_at'],day,self.store.execution_window,school_window)
                if self.store.execution_window:
                    if row['slot_minute'] is None:continue
                    if instant.strftime('%H:%M:%S')<slot_target(payload,day,row['slot_minute']):continue
                elif minute<clock_minutes(target):continue
                if self.store.execution_window and minute>clock_minutes(self.store.execution_window[1]):continue
                state=State(self.store.directory)
                try: ready=state.ready(account_key(payload)) and not state.auth_requirement(account_key(payload))
                finally: state.close()
                if not ready: continue
                start=end=0
                if self.store.execution_window:
                    base=instant.replace(hour=0,minute=0,second=0,microsecond=0)
                    start=base.timestamp()+row['slot_minute']*60+int(slot_target(payload,day,row['slot_minute'])[-2:])
                    end=base.timestamp()+row['slot_minute']*60+30
                self.store.enqueue({'id':row['owner_id'],'role':'admin'},row['id'],'checkin','schedule',day,available_at=start,execute_before=end)
            except (WebError,ToolError):
                continue

    def run_one(self):
        job=self.store.claim_job()
        if not job: return False
        payload=None
        try:
            self.store.record_job_event(job,'run_started',{})
            if job['business_date']!=now().date().isoformat():
                raise ToolError('job_expired','worker')
            if job['source']=='schedule' and self.store.execution_window and now().strftime('%H:%M')>self.store.execution_window[1]:
                raise ToolError('schedule_deadline_missed','worker')
            if job.get('execute_before') and now().timestamp()>=job['execute_before']:raise ToolError('reserved_slot_expired','worker')
            payload=self.store.job_payload(job)
            with execution_lock(self.store.directory):
                state=State(self.store.directory)
                try:
                    extra={}
                    if self.wechat_manager:extra={'authorization':self.wechat_manager.for_account(payload),'require_authorization':True}
                    result=self.runner(payload,job['mode'],state,self.store.directory,
                        emit=lambda event,**values:self.store.record_job_event(job,event,values,payload),
                        run_id=job['id'],
                        transport_factory=lambda ua,path:EncryptedTransport(ua,path,self.store),**extra)
                finally: state.close()
        except ToolError as error:
            result={'result':'error',**error_details(error,payload)}
            self.store.record_job_event(job,'run_error',{'error':error},payload)
        except WebError as error:
            result={'result':'error','reason':error.code,'stage':'worker'}
        except Exception:
            result={'result':'error','reason':'worker_internal_error','stage':'worker'}
        retryable=result.get('result')=='submission_unknown' or result.get('result')=='error' and result.get('reason') in RETRY_REASONS
        if job['source']=='schedule' and retryable:
            if not job.get('attempt',0) and self.store.defer_scheduled_retry(job,result,now().timestamp()):return True
            if job.get('attempt',0):result['retryExhausted']=True
            else:result['retryUnavailable']=True
        self.store.finish_job(job,result)
        if self.support_manager:self.support_manager.after_job(job,result)
        return True

    def start(self):
        if self.thread: return
        self.store.recover_jobs()
        def loop():
            while not self.stop_event.is_set():
                try:
                    self.tick()
                except Exception:
                    # School secrets and raw exception messages never enter web logs.
                    pass
                self.stop_event.wait(1)
        self.thread=threading.Thread(target=loop,name='moon-checkin-worker',daemon=True)
        self.thread.start()

    def tick(self):
        if self.wechat_manager:self.wechat_manager.prune()
        self.schedule_once()
        if time.monotonic()>=self.next_job_at and self.run_one():
            self.next_job_at=time.monotonic()+self.gap_seconds
        if self.support_manager:self.support_manager.tick()

    def stop(self):
        self.stop_event.set()
        if self.thread: self.thread.join(timeout=3)
        if self.wechat_manager:self.wechat_manager.close()
        if self.support_manager:self.support_manager.close()

import logging
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from portal import Portal, PortalError
from storage import now, stamp, DEFAULT_SETTINGS
from planning import daily_plan, randomized_location
from notifications import NotificationDispatcher
from wechat import WechatPortal, prepare_credentials
from wx_auth import AuthClient

log = logging.getLogger(__name__)

def minutes(value):
    return int(value[:2]) * 60 + int(value[3:])

def due(account, settings, current, plan=None):
    if not settings['enabled'] or not account.get('enabled'):
        return False
    day = current.date().isoformat()
    state = account.get('state', {})
    if state.get('success_date') == day:
        return False
    t = current.hour * 3600 + current.minute * 60 + current.second
    target = plan['target_second'] if plan else minutes(settings['time'])*60
    if not target <= t < minutes(settings['window_end'])*60:
        return False
    if state.get('attempt_date') == day:
        if state.get('attempt_count', 0) >= settings['max_attempts']:
            return False
        last = datetime.fromisoformat(state['last_attempt'])
        if (current - last).total_seconds() < settings['retry_minutes'] * 60 + (plan.get('retry_delay_seconds',0) if plan else 0):
            return False
    return True

def preparation_day(account, settings, current, plan_factory=None):
    if not settings['enabled'] or not account.get('enabled'):
        return None
    state = account.get('state', {})
    midnight = current.replace(hour=0,minute=0,second=0,microsecond=0)
    for offset in (0,1):
        base = midnight + timedelta(days=offset)
        day = base.date().isoformat()
        target = base + timedelta(seconds=plan_factory(day)['target_second'] if plan_factory else minutes(settings['time'])*60)
        if not target-timedelta(minutes=30) <= current < target or state.get('success_date') == day:
            continue
        if state.get('preparation_date') == day:
            if state.get('preparation_done') or state.get('preparation_attempts', 0) >= 3:
                continue
            last = state.get('preparation_last_at')
            if last and (current-datetime.fromisoformat(last)).total_seconds() < 120:
                continue
        return day
    return None

class Service:
    def __init__(self, store, portal_factory=Portal):
        self.store = store
        self.portal_factory = portal_factory
        self.gate = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='mooncheck-job')
        self.stop = threading.Event()
        self.busy = None
        self.scheduler_thread = None
        self.scheduler_error = False
        self.notifier = NotificationDispatcher(store)
        self.auth = AuthClient()
        from wechat_scans import ScanManager
        self.scans = ScanManager(self)

    def portal(self, account, original=None):
        if self.portal_factory is Portal:
            def persist(updated):
                if original is not None:
                    original['wx_credentials'] = updated['wx_credentials']
                    self.store.save_account(original)
                else:
                    self.store.save_account(updated)
            return WechatPortal(account, self.auth, persist)
        return self.portal_factory(account)

    def enqueue(self, aid, action, preparation_for=None, scheduled=False):
        if action not in ('probe', 'checkin'):
            raise ValueError('未知操作')
        if not self.gate.acquire(blocking=False):
            raise ValueError('已有任务执行中，请稍后再试')
        try:
            a = self.store.account(aid)
            self.busy = {'account_id': aid, 'name': a['name'], 'action': action, 'started': stamp()}
            return self.executor.submit(self._worker, aid, action, preparation_for, scheduled)
        except Exception:
            self.busy = None
            self.gate.release()
            raise

    def _worker(self, aid, action, preparation_for=None, scheduled=False):
        try:
            self.execute(aid, action, preparation_for, scheduled)
        except Exception:
            log.exception('Background job failed (no response body or credentials logged)')
        finally:
            self.busy = None
            self.gate.release()

    def execute(self, aid, action, preparation_for=None, scheduled=False):
        a = self.store.account(aid)
        state = a.setdefault('state', {})
        day = now().date().isoformat()
        owner = self.store.user(uid=a.get('owner_id'))
        settings = owner['settings'] if owner else DEFAULT_SETTINGS
        state['daily_plan'] = daily_plan(self.store.random_key,a,settings,preparation_for or day)
        portal = None
        stage = '读取位置配置'
        outcome, message = 'failed', '任务未完成'
        if preparation_for:
            count = state.get('preparation_attempts', 0) if state.get('preparation_date') == preparation_for else 0
            state.update(preparation_date=preparation_for, preparation_attempts=count + 1,
                         preparation_last_at=stamp(), preparation_done=False)
            self.store.save_account(a)
        # Persist attempt before any network activity; restarts retain retry limits.
        if action == 'checkin':
            if state.get('success_date') == day:
                self.store.event(a, action, 'already_done', '今日已打卡')
                return
            count = state.get('attempt_count', 0) if state.get('attempt_date') == day else 0
            state.update(attempt_date=day, attempt_count=count + 1, last_attempt=stamp())
            state['daily_plan'] = daily_plan(self.store.random_key,a,settings,day)
            self.store.save_account(a)
        try:
            try:
                effective = self.store.resolve_location(a)
            except ValueError as e:
                raise PortalError(str(e), 'need_location') from None
            portal = self.portal(effective, a)
            stage = '验证登录身份'
            portal.ensure()
            stage = '查询今日记录'
            today = portal.today()
            state['today'] = today
            if today.get('businessDate') != day:
                raise PortalError('暂时无法确认今日状态，请稍后再试。', 'pending')
            if today.get('abnormalFlag'):
                raise PortalError('打卡记录异常。', 'abnormal')
            if today['recordStatusCode'] == 'CHECKED_IN':
                state['success_date'] = day
                outcome, message = 'already_done', '统一身份认证正常，微信授权正常；今日已打卡' if action == 'probe' else '今日已打卡'
            else:
                stage = '读取打卡时段'
                schedule = portal.schedule()
                state['platform_schedule'] = schedule
                # Locations are diagnostic only; never substitute a location center.
                try:
                    state['locations'] = portal.locations()
                except PortalError:
                    state['locations'] = []
                if action == 'probe':
                    outcome, message = 'connected', '统一身份认证正常，微信授权正常'
                else:
                    t = now().hour * 60 + now().minute
                    if not schedule['start'] <= t < schedule['end']:
                        raise PortalError('当前不在学校允许的打卡时间内。', 'out_of_window')
                    if a.get('latitude') is None or a.get('longitude') is None:
                        raise PortalError('请先设置打卡位置。', 'need_location')
                    submitted = randomized_location(self.store.random_key,effective,settings,day,state['locations'])
                    portal.a.update(submitted)
                    state['submitted_location'] = {k:submitted[k] for k in ('latitude','longitude','coordinate_system') if k in submitted}
                    # A failed POST can still have reached the platform. Any retry
                    # starts by checking today's record rather than repeating POST.
                    stage = '准备打卡数据'
                    payload = portal.payload()
                    stage = '检查提交时间'
                    latest = now()
                    if latest.date().isoformat()!=day or not schedule['start']<=latest.hour*60+latest.minute<schedule['end']:
                        raise PortalError('已超过学校允许的打卡时间。','out_of_window')
                    if scheduled and latest.hour*3600+latest.minute*60+latest.second >= minutes(settings['window_end'])*60:
                        raise PortalError('已到最晚重试时间，停止重试。','out_of_window')
                    stage = '提交打卡'
                    portal.api('student-checkin-record/checkin', 'POST', payload)
                    stage = '确认打卡结果'
                    try:confirmed = portal.today()
                    except PortalError as exc:
                        raise PortalError('提交请求已返回成功，但查询结果失败。'+str(exc),'pending',stage=stage) from None
                    state['today'] = confirmed
                    if confirmed.get('abnormalFlag'):
                        raise PortalError('打卡记录异常。', 'abnormal')
                    if confirmed.get('businessDate') != day or confirmed.get('recordStatusCode') != 'CHECKED_IN':
                        raise PortalError('已提交，结果待确认，请稍后检查。', 'pending')
                    state['success_date'] = day
                    outcome, message = 'success', '打卡成功'
        except PortalError as e:
            outcome, message = e.kind, str(e.contextualize(stage))
        except Exception as exc:
            outcome, message = 'failed', stage+'失败：内部处理异常（'+type(exc).__name__+'）。'
            log.error('School operation failed stage=%s error_type=%s',stage,type(exc).__name__)
        finally:
            if portal:
                wx_status=getattr(portal,'wx_status',None)
                if wx_status:
                    state['wx_health']={'status':wx_status,'at':stamp()}
                if not isinstance(portal,WechatPortal) or portal.business_source=='school':
                    a['cookies'] = portal.cookies()
                a.pop('session_cookie', None)
                portal.close()
            state.update(last_outcome=outcome, last_message=message, updated_at=stamp())
            preparation_notice = None
            if preparation_for:
                ready = outcome in ('connected', 'already_done')
                finished = ready or state['preparation_attempts'] >= 3
                state.update(preparation_done=finished, preparation_last_at=stamp())
                if finished:
                    preparation_notice = 'preparation_success' if ready else 'preparation_failed'
            self.store.save_account(a)
            self.store.event(a, action, outcome, message)
            if action == 'checkin' or preparation_notice:
                try:
                    notice_message = message
                    if preparation_notice:
                        notice_message = f"提前检查第 {state['preparation_attempts']} 次：{message}"
                    self.notifier.enqueue(a, preparation_notice or outcome, notice_message, stamp())
                except Exception:
                    log.warning('Could not queue Feishu notification; school result unchanged')

    def tick(self):
        current = now()
        for a in self.store.accounts():
            owner = self.store.user(uid=a.get('owner_id'))
            if not owner or not owner['active']:
                continue
            settings = owner['settings']
            plan = daily_plan(self.store.random_key,a,settings,current.date().isoformat())
            if due(a, settings, current, plan):
                try:
                    self.enqueue(a['id'], 'checkin', scheduled=True)
                except ValueError:
                    pass
                break
            day = preparation_day(a, settings, current, lambda day:daily_plan(self.store.random_key,a,settings,day))
            if day:
                try:
                    self.enqueue(a['id'], 'probe', preparation_for=day)
                except ValueError:
                    pass
                break
        else:
            # Keep refresh credentials usable even when scheduled check-in is disabled.
            for a in self.store.accounts():
                creds = a.get('wx_credentials') or {}
                owner = self.store.user(uid=a.get('owner_id'))
                state = a.setdefault('state', {})
                if owner and owner['active'] and creds and creds.get('expires_at',0)<=current.timestamp()+60 and state.get('wx_refresh_after',0)<=current.timestamp():
                    if self.gate.acquire(blocking=False):
                        try:
                            self.executor.submit(self._refresh_wechat, a['id'])
                        except Exception:
                            self.gate.release()
                            raise
                    break

    def _refresh_wechat(self, aid):
        try:
            a = self.store.account(aid)
            state=a.setdefault('state',{})
            current=now().timestamp()
            previous=state.get('wx_health',{})
            notice=None
            try:
                prepare_credentials(self.auth, a, self.store.save_account)
                state.pop('wx_refresh_after',None)
                state['wx_health']={'status':'ready','at':stamp(),'failures':0}
                if previous.get('status') in ('expired','retrying'):
                    notice=('connected','微信授权刷新已恢复。','wechat_recovered')
            except PortalError as exc:
                status='expired' if exc.kind=='need_auth' else 'retrying'
                count=previous.get('failures',0)+1
                delay=min(60*2**min(count-1,3),300)
                state['wx_refresh_after']=current+delay
                message=str(exc.contextualize('刷新微信授权'))
                if status=='retrying':message+=f' {delay//60} 分钟后重试。'
                state['wx_health']={'status':status,'at':stamp(),'failures':count,'message':message}
                # First failure, changed failure type, or six-hour reminder only.
                if status!=previous.get('status') or current-state.get('wx_notice_at',0)>=21600:
                    notice=(exc.kind,message,'wechat_expired' if status=='expired' else 'wechat_refresh_failed')
            if notice:
                outcome,message,notification=notice
                state['wx_notice_at']=current
                self.store.event(a,'wechat_refresh',outcome,message)
            self.store.save_account(a)
            if notice:
                try:self.notifier.enqueue(a,notification,message,stamp())
                except Exception:log.warning('Could not queue WeChat health notification')
        finally:
            self.gate.release()

    def start(self):
        def loop():
            while not self.stop.wait(10):
                try:
                    self.tick()
                    self.scheduler_error = False
                except Exception:
                    self.scheduler_error = True
                    log.exception('Scheduler iteration failed')
        self.scheduler_thread = threading.Thread(target=loop, daemon=True, name='mooncheck-scheduler')
        self.scheduler_thread.start()

    def close(self):
        self.stop.set()
        if self.scheduler_thread and self.scheduler_thread is not threading.current_thread():
            self.scheduler_thread.join(timeout=2)
        self.scans.close()
        self.executor.shutdown(wait=True)
        self.notifier.close()
        self.auth.close()

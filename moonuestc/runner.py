"""Single-account flow; an uncertain check-in POST is never resent."""
import hashlib
import time
import uuid
from pathlib import Path

from .client import School
from .locations import location_details
from .errors import AuthRequired, ToolError
from .diagnostics import error_details,submission_details,verification_details
from .policy import TERMINAL, build_payload, check_fence, location_configured, location_source, now, valid_today, verified, window
from .transport import Transport
from .daily_plan import normalize_variation,verify_circle
from .geocoding import resolve_address
from .school_policy import SCHOOL_CLIENT_REASON, SCHOOL_CLIENT_MESSAGE, submission_rejection


def account_key(account):
    return hashlib.sha256(account["student_id"].encode()).hexdigest()[:32]


def cookie_path(directory, account):
    binding = "\0".join(account[k] for k in ("student_id", "browser_fingerprint", "password"))
    name = hashlib.sha256(binding.encode()).hexdigest()[:32]
    return Path(directory) / "cookies" / (name + ".lwp")


def reconcile(school, state, key, day, clock, sleep, *, emit=lambda *args,**kwargs:None, observations=None):
    last_reason = "record_not_confirmed"
    for attempt in range(3):
        if attempt:
            sleep(2)
        try:
            instant = clock()
            if instant.date().isoformat() != day:
                raise ToolError("business_date_changed", "verification")
            data = school.today()
            status = valid_today(data,instant)
            observation=verification_details({'attempt':attempt+1,'at':instant.timestamp(),'status':data.get('recordStatusCode') if isinstance(data,dict) else None})
            if observation:
                if observations is not None:observations.append(observation)
                emit('verification',observation=observation)
            if verified(data, instant):
                state.outcome(key, day, "confirmed")
                return {"result": "confirmed", "businessDate": day, "status": "CHECKED_IN", "abnormalFlag": False}
            if status in TERMINAL:
                return {"result": "record_changed", "businessDate": day, "status": status}
            rejected=submission_rejection(state.submission(key,day))
            if rejected:
                state.outcome(key,day,'rejected')
                return {**rejected,'businessDate':day}
        except ToolError as error:
            observation=verification_details({'attempt':attempt+1,'at':clock().timestamp(),**error_details(error,school.account)},school.account)
            if observations is not None:observations.append(observation)
            emit('verification',observation=observation)
            last_reason = error.reason
            if error.reason in ("abnormal_record", "business_date_mismatch", "business_date_changed"):
                break
    rejected=submission_rejection(state.submission(key,day))
    if rejected:
        state.outcome(key,day,'rejected')
        return {**rejected,'businessDate':day,'verificationReason':last_reason}
    state.outcome(key, day, "unknown")
    return {"result": "submission_unknown", "businessDate": day, "reason": last_reason}


def run_account(account, mode, state, directory, *, clock=now, sleep=time.sleep,
                emit=lambda *args, **kwargs: None, transport_factory=Transport, run_id=None,
                authorization=None,require_authorization=False):
    key = account_key(account)
    transport = transport_factory(account["user_agent"], cookie_path(directory, account))
    school = School(transport, account,
                    budget=lambda: state.login_budget(key, clock().date().isoformat()), emit=emit,
                    before_login=lambda:state.check_unattended_login(key,clock().date().isoformat()))
    school.operation_required=bool(authorization or require_authorization)
    action='not_submitted'
    observations=[]
    original=None
    prior_attempt=False
    checked_window=None
    run_id=run_id or uuid.uuid4().hex
    def mark(value,day):
        nonlocal action,original,prior_attempt
        action=value
        original=state.submission(key,day)
        prior_attempt=(value=='recheck' and state.claimed(key,day))
        emit('submission_action',action=action,submission=original,priorAttempt=prior_attempt)
    def observed(data,instant):
        observation=verification_details({'attempt':0,'at':instant.timestamp(),'status':data.get('recordStatusCode')})
        observations.append(observation);emit('verification',observation=observation)
    def finished(value):
        if checked_window:value['checkinWindow']=checked_window
        if mode=='checkin':
            value['submissionAction']=action
            value['priorAttempt']=prior_attempt
            value['submission']=original
            value['verification']=observations
        return value
    def recheck(day):
        mark('recheck',day)
        return finished(reconcile(school,state,key,day,clock,sleep,emit=emit,observations=observations))
    def school_client_result(*,sync_login_required=False):
        day=clock().date().isoformat()
        if action=='not_submitted' and state.claimed(key,day):mark('recheck',day)
        return finished({'result':'error','reason':'school_sync_login_required' if sync_login_required else SCHOOL_CLIENT_REASON,
                         'stage':'checkin_authorization','businessDate':day,
                         'schoolMessage':'请重新验证学校登录后再同步记录；签到仍须在微信「成电智慧学工」小程序内完成。' if sync_login_required else SCHOOL_CLIENT_MESSAGE})
    try:
        prior_authorized_claim=bool((authorization or require_authorization) and mode=='checkin' and state.claimed(key,clock().date().isoformat()))
        restricted=mode=='checkin' and ((state.school_client_requirement() or require_authorization) and authorization is None or prior_authorized_claim)
        authorization_prepared=False
        if authorization and not restricted:
            authorization.prepare();authorization_prepared=True
        if restricted:
            # This action now synchronizes official records only. Never refresh
            # passwords, manufacture an entry ticket, or submit a check-in.
            if not transport.has_session():return school_client_result(sync_login_required=True)
            try:data=school.enter()
            except AuthRequired:return school_client_result(sync_login_required=True)
        else:data = school.connect()
        if authorization_prepared:authorization.check_business(school)
        instant = clock()
        day = instant.date().isoformat()
        status = valid_today(data, instant)
        if not restricted:state.background_session_verified(key,day)
        emit("record_read", businessDate=day, status=status, abnormalFlag=data.get("abnormalFlag"))
        if mode == "diagnose":
            win = window(school.schedule(), clock())
            locs = school.locations()
            if not isinstance(locs, list) or not locs:
                raise ToolError("locations_unavailable", "locations")
            return {"result": "auth_ready", "businessDate": day, "status": status,
                    "checkinWindow": win, "locationCount": len(locs),
                    "payloadConfigured": location_configured(account),
                    "locationConfigured": location_configured(account), "locationSource": location_source(account),
                    **location_details(account)}
        if status in TERMINAL and mode != "prepare":
            mark('recheck',day);observed(data,instant)
            if status == "CHECKED_IN" and state.claimed(key, day) and verified(data, instant):
                state.outcome(key, day, "confirmed")
                return finished({"result": "confirmed", "businessDate": day, "status": status, "abnormalFlag": False})
            return finished({"result": "already_recorded", "businessDate": day, "status": status})
        if state.claimed(key, day) and mode != "prepare":
            return recheck(day)
        if restricted:return school_client_result()
        if account.get('_allowed_presets') and (account.get('location') or {}).get('preset') not in account['_allowed_presets']:raise ToolError('location_not_open','location')
        payload = build_payload(account, instant)
        fences=school.locations()
        check_fence(payload, fences)
        variation=normalize_variation(account.get('variation'))
        if variation['meters']:
            base=build_payload({**account,'variation':{'minutes':0,'meters':0}},instant)
            verify_circle(base['latitude'],base['longitude'],variation['meters'],fences)
        address = payload["reverseGeocode"]
        if not address:
            address = resolve_address(school,account,payload,directory,clock=clock,sleep=sleep,emit=emit)
        payload["reverseGeocode"] = address
        win = window(school.schedule(), clock())
        checked_window=win
        if mode == "prepare":
            return {"result": "dry_run_ready", "businessDate": day, "checkinWindow": win,
                    "submitted": False, "alreadyRecorded": status in TERMINAL, "locationSource": location_source(account), **location_details(account)}
        if mode != "checkin":
            raise ToolError("invalid_mode", "local")
        if not win["open"]:
            raise ToolError("outside_checkin_window", "schedule")
        bounds=account.get('_execution_window')
        if bounds and not bounds[0]<=instant.strftime('%H:%M')<=bounds[1]:raise ToolError('outside_execution_window','schedule')
        # Refresh status and schedule just before the durable claim.
        fresh = school.today()
        instant = clock()
        if instant.date().isoformat() != day:
            raise ToolError("business_date_changed", "today")
        status = valid_today(fresh, instant)
        if status in TERMINAL:
            mark('recheck',day);observed(fresh,instant)
            return finished({"result": "already_recorded", "businessDate": day, "status": status})
        if not window(school.schedule(), clock())["open"]:
            raise ToolError("outside_checkin_window", "schedule")
        instant = clock()
        if instant.date().isoformat() != day:
            raise ToolError("business_date_changed", "checkin_post")
        if account.get('_job_deadline') and instant.timestamp()>=account['_job_deadline']:raise ToolError('reserved_slot_expired','schedule')
        if bounds and not bounds[0]<=instant.strftime('%H:%M')<=bounds[1]:raise ToolError('outside_execution_window','schedule')
        payload = build_payload(account, instant)
        check_fence(payload, school.locations())
        payload["reverseGeocode"] = address
        if authorization_prepared:
            value,expiry=authorization.ticket()
            school.authorize_operation(value,expiry)
            instant=clock()
            if instant.date().isoformat()!=day:raise ToolError('business_date_changed','wechat_ticket')
            if account.get('_job_deadline') and instant.timestamp()>=account['_job_deadline']:raise ToolError('reserved_slot_expired','schedule')
            if bounds and not bounds[0]<=instant.strftime('%H:%M')<=bounds[1]:raise ToolError('outside_execution_window','schedule')
            if not window(school.schedule(),clock())['open']:raise ToolError('outside_checkin_window','schedule')
            instant=clock()
            if instant.date().isoformat()!=day:raise ToolError('business_date_changed','wechat_ticket')
            if account.get('_job_deadline') and instant.timestamp()>=account['_job_deadline']:raise ToolError('reserved_slot_expired','schedule')
            if bounds and not bounds[0]<=instant.strftime('%H:%M')<=bounds[1]:raise ToolError('outside_execution_window','schedule')
        elif state.school_client_requirement() or require_authorization:return school_client_result()
        initial={'attemptId':uuid.uuid4().hex,'originRun':run_id,'startedAt':clock().timestamp(),'outcome':'attempting'}
        if not state.claim(key, day, initial):
            return recheck(day)
        mark('first_submit',day)
        emit("post_claim_saved", businessDate=day)
        try:
            school.submit(payload)
        except ToolError as error:
            # Preserve the original error before any reconciliation can replace it.
            outcome='rejected' if error.reason in ('business_error','session_rejected',SCHOOL_CLIENT_REASON) else 'error' if error.reason in ('http_error','invalid_json','api_contract_changed') else 'unknown'
            details={**initial,**(school.submission_response or {}),**error_details(error,account),'outcome':outcome,'finishedAt':clock().timestamp()}
        else:
            details={**initial,**(school.submission_response or {}),'outcome':'accepted','finishedAt':clock().timestamp()}
        original=submission_details(details,account)
        state.record_submission(key,day,original)
        if authorization_prepared and original.get('outcome')=='rejected' and original.get('apiCode') in (46001,46002,46003):
            authorization.reject()
        emit('submission_result',submission=original)
        return finished(reconcile(school,state,key,day,clock,sleep,emit=emit,observations=observations))

    except ToolError as error:
        state.require_interactive_auth(key,error.reason)
        raise
    finally:
        if authorization:authorization.close()
        transport.save()

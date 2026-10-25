"""School's class-cadre workflow, distinct from a student's location check-in."""
import contextlib
import datetime as dt
import urllib.parse

from .client import School
from .errors import ToolError
from .policy import now,TERMINAL
from .runner import account_key,cookie_path
from .state import State,execution_lock
from .vault import EncryptedTransport

PENDING={'PENDING','NOT_CHECKIN'}


def daily_remark(day):
    date=dt.date.fromisoformat(day)
    phrases=('今日在校内学习，按实际情况登记。','该同学今日在校内学习，现登记情况。','今日校内学习，现由班委记录情况。')
    return date.strftime('%Y年%m月%d日：')+phrases[date.toordinal()%len(phrases)]


class CadreSchool:
    def __init__(self,school,clock=now):self.school=school;self.clock=clock
    def classes(self):
        value=self.school.api('/class-cadre/my-classes',stage='class_permissions')
        if not isinstance(value,list) or any(not isinstance(r,dict) or not isinstance(r.get('classKey'),str) for r in value):
            raise ToolError('class_contract_changed','class_permissions')
        return [{'class_key':r['classKey'],'name':str(r.get('manageClass') or '')} for r in value]
    def roster(self,class_key,day):
        if self.clock().date().isoformat()!=day:raise ToolError('business_date_changed','class_roster')
        if class_key not in {r['class_key'] for r in self.classes()}:raise ToolError('class_access_denied','class_permissions')
        rows=[];seen=set()
        for page in range(1,31):
            query=urllib.parse.urlencode({'classKey':class_key,'businessDate':day,'pageIndex':page,'pageSize':100,'keyword':''})
            data=self.school.api('/class-cadre/checkin-list?'+query,stage='class_roster')
            if not isinstance(data,list):raise ToolError('class_contract_changed','class_roster')
            for r in data:
                if not isinstance(r,dict) or not all(isinstance(r.get(k),str) and r[k] for k in ('studentSn','studentName','id','recordStatusCode')):
                    raise ToolError('class_contract_changed','class_roster')
                if r['studentSn'] in seen:raise ToolError('class_pagination_changed','class_roster')
                seen.add(r['studentSn'])
                rows.append({'student_id':r['studentSn'],'name':r['studentName'],'record_id':r['id'],'status':r['recordStatusCode']})
            if len(data)<100:return rows
        raise ToolError('class_roster_limit','class_roster')
    def study_option(self):
        data=self.school.api('/case-keyword/active?locationTypeCode=CAMPUS',stage='class_options')
        found=[r for r in data if isinstance(r,dict) and r.get('keyword')=='学习' and r.get('situationTypeCode') in (None,'CAMPUS')] if isinstance(data,list) else []
        if len(found)!=1 or not isinstance(found[0].get('id'),str):raise ToolError('class_study_option_unavailable','class_options')
        return found[0]['id']
    def check_window(self,day,bounds):
        instant=self.clock()
        if instant.date().isoformat()!=day:raise ToolError('business_date_changed','class_report')
        data=self.school.schedule();start=data.get('studentReportStartOffsetMinute');end=data.get('studentReportEndOffsetMinute')
        minute=instant.hour*60+instant.minute+instant.second/60
        if data.get('effective') is not True or type(start) not in (int,float) or type(end) not in (int,float) or not 0<=start<end<=1440:
            raise ToolError('invalid_schedule','class_report')
        if not start<=minute<end-2 or bounds and not bounds[0]<=instant.strftime('%H:%M')<=bounds[1]:
            raise ToolError('outside_class_report_window','class_report')
    def report(self,class_key,student_id,day,ledger,account_id,bounds,*,before_submit=lambda:None):
        self.check_window(day,bounds)
        target=[r for r in self.roster(class_key,day) if r['student_id']==student_id]
        if len(target)!=1:raise ToolError('class_target_not_found','class_report')
        target=target[0]
        if target['status'] in TERMINAL:return {'result':'already_recorded','status':target['status']}
        if target['status'] not in PENDING:raise ToolError('unknown_record_status','class_report')
        keyword=self.study_option();self.check_window(day,bounds)
        before_submit()
        remark=daily_remark(day)
        ident,fresh,_=ledger.begin(class_key+'\0'+student_id,'class_report',day,account_id=account_id,initial={'result':'submission_unknown'})
        if not fresh:
            current=[r for r in self.roster(class_key,day) if r['student_id']==student_id]
            result={'result':'class_reported' if len(current)==1 and current[0]['status'] in TERMINAL else 'submission_unknown','rechecked':True}
            ledger.finish(ident,result,'done' if result['result']=='class_reported' else 'unknown');return result
        try:
            self.school.api('/class-cadre/situation/report',stage='class_report_post',payload=[{'classKey':class_key,
                'recordId':target['record_id'],'locationTypeCode':'CAMPUS','caseKeywordId':keyword,'caseRemark':remark}])
        except ToolError as error:
            # The durable claim survives ambiguous delivery and process restarts.
            result={'result':'submission_unknown','reason':error.reason,'apiCode':error.api_code,'httpStatus':error.http_status}
            ledger.finish(ident,result,'unknown');return result
        current=[r for r in self.roster(class_key,day) if r['student_id']==student_id]
        status=current[0]['status'] if len(current)==1 else 'UNKNOWN'
        result={'result':'class_reported' if status in TERMINAL else 'submission_unknown','status':status}
        ledger.finish(ident,result,'done' if result['result']=='class_reported' else 'unknown');return result


@contextlib.contextmanager
def school_session(store,account_id,*,clock=now):
    with store.db() as db:
        row=db.execute('SELECT a.*,u.active FROM web_accounts a JOIN web_users u ON u.id=a.owner_id WHERE a.id=?',(account_id,)).fetchone()
    if not row or not row['active'] or not row['enabled']:raise ToolError('account_disabled','class_permissions')
    account=store._payload(row);key=account_key(account)
    with execution_lock(store.directory):
        state=State(store.directory);transport=EncryptedTransport(account['user_agent'],cookie_path(store.directory,account),store)
        school=School(transport,account,budget=lambda:state.login_budget(key,clock().date().isoformat()),emit=lambda *a,**k:None,
            before_login=lambda:state.check_unattended_login(key,clock().date().isoformat()))
        try:
            school.connect()
            yield CadreSchool(school,clock)
        except ToolError as error:
            state.require_interactive_auth(key,error.reason);raise
        finally:
            transport.save()
            state.close()

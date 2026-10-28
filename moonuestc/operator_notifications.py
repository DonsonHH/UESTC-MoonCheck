"""Final job events to one encrypted operator destination, without school calls."""
import json
import time

from .qq_bot import QQError,identifier
from .web_errors import WebError


def field(value,limit=60):
    return ''.join(c for c in str(value or '')[:limit] if c.isalnum() or c in ' ·.-/()').strip() or '未提供'


REASONS={'need_manual_mfa':'需要本人完成学校二次验证','need_manual_captcha':'需要本人完成学校验证码',
    'login_rejected':'学校账号或密码未通过','daily_login_limit':'后台连续重登尚未确认，请更新学校验证',
    'privacy_consent_required':'用户尚未同意当前托管说明','timeout':'学校请求超时','network_error':'学校网络连接失败',
    'school_client_required':'学校要求小程序授权','wechat_authorization_required':'需要本人连接微信授权',
    'wechat_authorization_expired':'微信授权已失效，需要本人重新连接','wechat_access_token_invalid':'微信访问凭据刷新失败',
    'wechat_identity_mismatch':'微信与学校账号身份不一致','reserved_slot_expired':'错过本次执行时段',
    'schedule_deadline_missed':'排队已超过学校时段','outside_allowed_location':'所选地点不在校方允许范围',
    'variation_outside_allowed_location':'位置浮动范围不在校方允许区域','record_not_confirmed':'学校记录尚未确认',
    'reverse_geocode_unavailable':'学校地址解析暂不可用，尚未提交签到'}


class OperatorNotifications:
    def __init__(self,store,data,client):self.store=store;self.data=data;self.client=client
    def summary(self):
        c=self.data.get('qq_operator')
        return {'configured':bool(c.get('openid')),'enabled':bool(c.get('enabled')),
            'owner_success_configured':bool(c.get('owner_student_digest'))}
    def configure(self,value):
        if not isinstance(value,dict) or set(value)!={'enabled'} or type(value.get('enabled')) is not bool:
            raise WebError(400,'invalid_fields','通知开关参数不正确。')
        c=self.data.get('qq_operator')
        if not c.get('openid'):raise WebError(409,'operator_not_connected','尚未配置接收通知的 QQ。')
        if value['enabled'] and not c.get('enabled'):c['not_before']=time.time()
        c['enabled']=value['enabled'];self.data.put('qq_operator',c)
        return self.summary()
    def notify(self,job_id):
        c=self.data.get('qq_operator')
        if not c.get('enabled') or not c.get('openid'):return
        with self.store.db() as db:
            row=db.execute("SELECT j.*,a.student_digest,a.owner_id,u.display_name FROM web_jobs j JOIN web_accounts a ON a.id=j.account_id JOIN web_users u ON u.id=a.owner_id WHERE j.id=? AND j.state IN ('done','failed')",(job_id,)).fetchone()
        if not row or row['finished_at'] is None or row['finished_at']<c.get('not_before',0):return
        result=json.loads(row['result'] or '{}');outcome=result.get('result')
        if outcome=='retry_pending':return
        attention=outcome in ('error','submission_unknown','submission_rejected','record_changed') or bool(result.get('retryExhausted') or result.get('retryUnavailable'))
        success=row['mode']=='checkin' and row['student_digest']==c.get('owner_student_digest') and (outcome=='confirmed' or outcome=='already_recorded' and result.get('status')=='CHECKED_IN')
        if not attention and not success:return
        kind='operator_alert' if attention else 'operator_success'
        scope=row['id'] if attention else row['student_digest']
        ident,fresh,_=self.data.begin(scope,kind,row['business_date'],account_id=row['account_id'],initial={'result':'delivery_unknown'},retry_cancelled=True)
        if not fresh:return
        with self.store.db() as db:
            account=db.execute('SELECT payload FROM web_accounts WHERE id=?',(row['account_id'],)).fetchone()
        if not account:
            self.data.finish(ident,{'result':'reminder_cancelled'});return
        payload=self.store.vault.open(account['payload'],'account:'+row['account_id'])
        title='需要处理' if attention else '签到已完成'
        mode={'checkin':'签到','prepare':'位置检查','diagnose':'只读诊断'}.get(row['mode'],'任务')
        lines=[f'晚安成电 · {title}',f"账号：{field(row['display_name'])}｜学号：{field(payload.get('student_id'),24)}",f"业务日期：{row['business_date']}"]
        if attention:
            detail=REASONS.get(result.get('reason'),'学校未确认执行结果，请在管理端查看')
            lines.extend([f'操作：{mode}',f'结果：{detail}','请在管理端查看最近结果并处理。'])
        else:lines.append('学校已确认本人今日签到，可以安心休息了。')
        current=self.data.get('qq_operator')
        if not current.get('enabled') or current.get('openid')!=c['openid'] or row['finished_at']<current.get('not_before',0) or not self.data.get('qq_bot').get('enabled'):
            self.data.finish(ident,{'result':'reminder_cancelled'});return
        try:self.client().send('user',identifier(c['openid']),'\n'.join(lines))
        except QQError as error:
            self.data.finish(ident,{'result':'notification_failed','code':error.code,'httpStatus':error.http},'failed');return
        self.data.finish(ident,{'result':'notification_sent'})
    def tick(self):
        c=self.data.get('qq_operator')
        if not c.get('enabled') or not c.get('openid'):return
        cursor=self.data.get('qq_operator_cursor');stamp=cursor.get('finished_at',c.get('not_before',0));last=cursor.get('id','')
        with self.store.db() as db:
            rows=db.execute("SELECT id,finished_at FROM web_jobs WHERE state IN ('done','failed') AND finished_at>=? AND (finished_at>? OR (finished_at=? AND id>?)) ORDER BY finished_at,id LIMIT 50",(c.get('not_before',0),stamp,stamp,last)).fetchall()
        for row in rows:
            self.notify(row['id'])
            self.data.put('qq_operator_cursor',{'finished_at':row['finished_at'],'id':row['id']})

import {requiresOfficialEntry,type PresentedResult} from './result-presentation.ts';
type TodayJob={state:string;source:string;result:PresentedResult|null};
export type HomeAccount={wechat_auth_enabled?:boolean;wechat_authorization?:{linked:boolean;status:string;eligible:boolean};school_checkin_required?:boolean;enabled:boolean;automatic:boolean;location:unknown;location_open?:boolean;ready_for_automation:boolean;recorded_today?:boolean;confirmed_today:boolean;school_auth_required?:boolean;school_auth_reason?:string|null;planned_run_at?:string|null;schedule_slot?:unknown;today_job?:TodayJob|null};
type Action='authorize'|'settings'|'submit'|'history'|'reauthenticate'|'none';
export type HomeState={key:string;title:string;message:string;action:Action;label:string;tone:'calm'|'success'|'warning'|'busy'};
export function submissionIntent(a:Pick<HomeAccount,'school_checkin_required'|'wechat_auth_enabled'|'recorded_today'|'confirmed_today'|'today_job'>&{last_result?:PresentedResult|null}){
 if(a.school_checkin_required||!a.wechat_auth_enabled&&requiresOfficialEntry(a.last_result))return 'sync';
 if(a.recorded_today||a.confirmed_today||['submission_unknown','submission_rejected'].includes(a.today_job?.result?.result||''))return 'recheck';
 return 'submit';
}
export function studentState(a:HomeAccount,time:string,busy=false,taskState?:string):HomeState{
 const state=(key:string,title:string,message:string,action:Action,label:string,tone:HomeState['tone']='calm'):HomeState=>({key,title,message,action,label,tone});
 const minute=time.slice(0,5),early=minute<'21:06',late=minute>'23:24';
 if(busy)return state('running',a.today_job?.result?.result==='retry_pending'?'稍后自动重试':taskState==='queued'?'签到任务已排队':'正在处理今日任务','完成后会自动更新结果，稍候即可。','history','查看进度','busy');
 if((a.recorded_today||a.confirmed_today)&&a.enabled&&a.wechat_auth_enabled&&a.school_checkin_required)return state('done-authorization','今日已完成','学校已有记录。连接微信后可继续后续每日计划。','authorize','连接微信','success');
 if(a.recorded_today&&!a.ready_for_automation)return state('first-recorded','今日已有学校记录','今天无需重复签到。明晚在本站完成首次签到，学校确认后再开启每日计划。','history','查看今日记录','success');
 if(a.recorded_today||a.confirmed_today)return state('done','今日已完成','学校已有今日记录。'+(a.school_checkin_required?'学校当前要求在微信小程序完成后续签到。':a.automatic?'明天继续按每日计划执行。':'可以开启每日计划，让之后的签到自动完成。'),a.automatic||a.school_checkin_required?'history':'settings',a.automatic||a.school_checkin_required?'查看今日记录':'开启每日计划','success');
 if(!a.enabled)return state('paused','托管已暂停','计划已保留。关闭“暂停账号托管”并保存，即可恢复。','settings','恢复托管');
 if(a.wechat_auth_enabled&&a.school_auth_required)return state('authentication','更新学校验证','学校需要你完成验证码或二次验证。','reauthenticate','验证学校账号','warning');
 if(a.wechat_auth_enabled&&a.school_checkin_required)return state('wechat-authorization','连接微信，完成设置','用已绑定本人学校账号的微信扫码。连接后再设置每日计划。','authorize','连接微信','warning');
 if(a.school_checkin_required&&a.school_auth_required)return state('sync-authentication','同步前请更新学校登录','学校会话已失效。重新验证后可以同步记录；签到仍须在微信「成电智慧学工」小程序内完成。','reauthenticate','重新验证学校登录','warning');
 if(a.school_checkin_required||!a.wechat_auth_enabled&&requiresOfficialEntry(a.today_job?.result))return state('school-client','请在微信小程序完成签到','在微信中搜索「成电智慧学工」，进入打卡应用签到，完成后点击下方按钮同步学校记录。本站自动提交已暂停，重新验证密码不能解除此要求。','submit','同步今日学校记录','warning');
 if(a.school_auth_required)return state('authentication','请更新学校认证','在学校原页面完成验证码或二次验证，成功后继续执行计划。','reauthenticate','重新验证学校登录','warning');
 if(!a.location||a.location_open===false)return state('setup','设置你的每日计划','选择实际所在组团和偏好时间。','settings','设置地点与时间');
 if(a.today_job?.result?.result==='submission_unknown')return state('uncertain','今日结果待确认','请复查学校记录，已有提交不会重复发送。','submit','复查今日结果','warning');
 if(a.today_job?.state==='failed')return state('failed','今日任务需要处理','查看失败原因，处理后可在签到时段手动补签。','history','查看原因','warning');
 if(a.automatic){
  if(!a.schedule_slot)return state('capacity','请调整偏好时间','偏好时间前后五分钟内的发起时段已满，调整后可继续安排。','settings','调整时间','warning');
  if(late)return state('closed','今日签到时段已结束','可在运行记录查看今天的执行情况，明天继续按计划安排。','history','查看今日记录');
  if(a.planned_run_at&&time>=a.planned_run_at)return state('due','正在等待计划执行','系统会按今日安排发起签到，结果自动更新到本页。','history','查看运行进度');
  return state('scheduled','今晚已安排自动签到',`${a.planned_run_at?'预计 '+a.planned_run_at+' 发起。':'到时自动执行。'}无需每天回来检查或手动操作。`,'settings','查看我的计划');
 }
 if(a.ready_for_automation)return state('enable','开启每日计划','首次签到已获学校确认，现在可以开启自动执行。','settings','开启每日计划');
 if(early)return state('first-wait','今晚 21:06 开始首签','计划已保存。在 21:06–23:24 完成首次签到，确认后即可开启自动执行。','settings','查看我的计划');
 if(late)return state('first-closed','今天的签到时段已结束','明晚 21:06–23:24 完成首次签到，之后即可开启每日计划。','settings','查看我的计划');
 return state('first-sign','完成首次签到','确认本人位于所选区域后提交一次；系统会同步验证地点与学校时段。学校确认后即可开启每日计划。','submit','完成首次签到');
}

import React,{useEffect,useRef,useState} from 'react';
import {Check,LoaderCircle,RefreshCw,ShieldCheck,School,ArrowRight,ChevronDown} from 'lucide-react';
import {toast} from 'sonner';
import {SetupProgress,type StudentAccount} from './student-flow';

type Request=(path:string,method?:string,body?:unknown)=>Promise<any>;
type Scan={id:string;status:string;image:string;error?:string|null};
const errors:Record<string,string>={wechat_identity_mismatch:'扫码微信与当前学号不一致，未保存连接。',wechat_school_not_bound:'先在「成电智慧学工」中绑定本人学校账号，再回来扫码。',wechat_ticket_rejected:'学校未接受本次授权，请稍后重试。',wechat_scan_expired:'二维码已过期，请重新获取。',wechat_authorization_expired:'微信授权已失效，请重新扫码。',wechat_code_transport_failed:'连接未成功，请稍后重试。',wechat_protocol_login_failed:'连接未完成，请稍后重试。',wechat_binding_rejected:'学校未接受绑定校验，请确认原小程序能正常使用。',wechat_refresh_unavailable:'未取得可续期授权，请重新扫码。',wechat_authorization_changed:'授权已更新，请重新获取二维码。'};

export function WechatAuthorization({account:a,request,onChanged,onContinue,onToday,onReauthenticate,reauthenticating=false}:{account:StudentAccount;request:Request;onChanged:()=>Promise<void>;onContinue:()=>void;onToday:()=>void;onReauthenticate:()=>void;reauthenticating?:boolean}){
 const[notice,setNotice]=useState<{version:string;title:string;text:string}|null>(null),[consent,setConsent]=useState(false),[scan,setScan]=useState<Scan|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[editing,setEditing]=useState(false),[remove,setRemove]=useState(false),[noticeAttempt,setNoticeAttempt]=useState(0),[noticeError,setNoticeError]=useState('');
 const mounted=useRef(true),authorization=a.wechat_authorization;
 const connected=!!authorization?.eligible||scan?.status==='completed',formOpen=!connected||editing;
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false}},[]);
 useEffect(()=>{if(!formOpen)return;let live=true;setNoticeError('');request('/api/wechat/notice').then(value=>{if(live)setNotice(value.notice)}).catch(e=>{if(live)setNoticeError(e.message)});return()=>{live=false}},[formOpen,noticeAttempt]);
 useEffect(()=>{
  if(!scan?.id)return;
  let live=true,finished=false,timer:ReturnType<typeof setTimeout>;const id=scan.id;
  async function poll(){try{const value=await request('/api/wechat/scans/'+id);if(!live)return;setError('');setScan(value.scan);if(value.scan.status==='completed'){finished=true;setEditing(false);setConsent(false);toast.success('微信已连接');await onChanged();return}if(['failed','cancelled','expired'].includes(value.scan.status)){finished=true;return}timer=setTimeout(poll,1500)}catch(e){if(live){const failure=e as Error&{code?:string};setError(failure.message);if(['not_found','login_required'].includes(failure.code||'')){finished=true;setScan(previous=>previous?{...previous,status:'expired',image:''}:previous);setConsent(false)}else timer=setTimeout(poll,4000)}}}
  timer=setTimeout(poll,900);return()=>{live=false;clearTimeout(timer);if(!finished)request('/api/wechat/scans/'+id,'DELETE').catch(()=>{})};
 },[scan?.id]);
 async function start(){if(!notice||!consent||busy)return;setBusy(true);setError('');try{const value=await request('/api/accounts/'+a.id+'/wechat/scans','POST',{consent_version:notice.version});if(mounted.current)setScan(value.scan);else await request('/api/wechat/scans/'+value.scan.id,'DELETE')}catch(e){if(mounted.current)setError((e as Error).message)}finally{if(mounted.current)setBusy(false)}}
 async function cancel(){if(!scan)return;setBusy(true);try{await request('/api/wechat/scans/'+scan.id,'DELETE');setScan(null);setConsent(false);setError('')}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function revoke(){setBusy(true);setError('');try{await request('/api/accounts/'+a.id+'/wechat','DELETE');setScan(null);setRemove(false);setConsent(false);setEditing(false);toast.success('微信连接已移除');await onChanged()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 const waiting=!!scan&&['pending','scanned'].includes(scan.status),processing=scan?.status==='processing';
 const issue=error||(scan?.status==='failed'?(errors[scan.error||'']||'连接未完成，请重新尝试。'):scan?.status==='expired'?'二维码已过期，请重新获取。':'');
 return <div className="connection-workspace"><SetupProgress account={a} current="account" onAccount={()=>{}} onPlan={onContinue} onToday={onToday}/>
  <section className="panel connection-card"><div className="connection-identity"><span className="connection-avatar">{a.owner_name.slice(0,1)}</span><div><h2>{a.owner_name}</h2><p className="tabular">{a.student_id}</p></div></div>
   <div className="connection-row"><span className="connection-icon"><School size={21}/></span><div><h3>学校账号</h3><p>{a.school_auth_required?'请按学校提示完成验证':'已验证本人身份'}</p></div><span className={'status-label '+(!a.school_auth_required?'good':'')}>{!a.school_auth_required?<><Check size={15}/>正常</>:'待验证'}</span>{(!a.school_auth_required||!connected)&&<button className={'button '+(a.school_auth_required?'primary':'')} onClick={onReauthenticate} disabled={reauthenticating}>{reauthenticating?<LoaderCircle size={16} className="spin"/>:<RefreshCw size={16}/>} {a.school_auth_required?'完成学校验证':'更新验证'}</button>}</div>
   <div className="connection-row"><span className="connection-icon"><ShieldCheck size={21}/></span><div><h3>微信连接</h3><p>{connected?'自动续期，用于每日签到':authorization?.linked?'连接已失效，请重新扫码':'扫码一次，连接学校小程序'}</p></div><span className={'status-label '+(connected?'good':'')}>{connected?<><Check size={15}/>已连接</>:'待连接'}</span></div>
   {issue&&<div role="alert" className="inline-error connection-error">{issue}</div>}
   {formOpen&&<div className="connection-setup"><p className="connection-prerequisite">首次扫码前，先在微信「成电智慧学工」绑定同一学号。</p>
    {waiting&&scan?.image?<div className="wechat-qr"><img src={'data:image/png;base64,'+scan.image} alt="微信授权二维码"/><h3>{scan.status==='scanned'?'请在微信中确认':'使用本人微信扫码'}</h3><p>授权页面显示「应用宝」，请确认授权。</p><details className="phone-scan-help"><summary>正在用同一台手机？</summary><p>保存二维码，在微信“扫一扫”中从相册选择。二维码过期后需重新获取。</p><a className="button" href={'data:image/png;base64,'+scan.image} download="moon-wechat-authorization.png">保存二维码</a></details><button className="button" disabled={busy} onClick={cancel}>取消扫码</button></div>:processing?<div className="wechat-progress" role="status"><LoaderCircle className="spin" size={28}/><h3>正在核对学校身份</h3><p>稍候，完成后即可继续设置。</p><button className="text-link" disabled={busy} onClick={cancel}>取消连接</button></div>:<>
     {notice?<div className="connection-consent"><h3>授权托管说明</h3><p>{notice.text}</p><label className="student-check"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)}/><span>我同意托管上述授权，用于本人账号的每日签到。</span></label></div>:noticeError?<div role="alert" className="inline-error">{noticeError}<button className="text-link" onClick={()=>setNoticeAttempt(n=>n+1)}>重新加载说明</button></div>:<div className="connection-loading" role="status"><LoaderCircle className="spin" size={18}/>正在读取授权说明</div>}
     <div className="connection-actions"><button className="button primary" disabled={!consent||!notice||busy} onClick={start}>{busy?<LoaderCircle className="spin" size={17}/>:<ShieldCheck size={17}/>}获取授权二维码</button>{editing&&<button className="button" disabled={busy} onClick={()=>{setEditing(false);setConsent(false);setError('')}}>取消更改</button>}</div>
    </>}
   </div>}
   {connected&&!editing&&<div className="connection-next"><span>{!a.school_auth_required?<><Check size={18}/>连接已就绪</>:'学校验证待完成'}</span><button className="button primary" onClick={a.school_auth_required?onReauthenticate:onContinue} disabled={reauthenticating}>{a.school_auth_required?'完成学校验证':a.ready_for_automation?'返回今日':'下一步：设置计划'}<ArrowRight size={17}/></button></div>}
  </section>
  {authorization?.linked&&!waiting&&!processing&&<details className="connection-manage"><summary>管理微信连接<ChevronDown size={16}/></summary><div><button className="text-link" onClick={()=>{setEditing(true);setRemove(false);setConsent(false);setScan(null);setError('')}}>重新扫码连接</button><button className="text-link danger-text" onClick={()=>setRemove(true)}>移除连接</button></div>{remove&&<div className="remove-confirm"><p>移除后，每日计划将等待重新连接。账号与历史记录保留。</p><button className="button danger-button" disabled={busy} onClick={revoke}>确认移除</button><button className="button" onClick={()=>setRemove(false)}>保留连接</button></div>}</details>}
 </div>;
}

import React,{useEffect,useState} from 'react';
import {Check,LoaderCircle,RefreshCw,ShieldCheck,Trash2} from 'lucide-react';
import {toast} from 'sonner';
import type {StudentAccount} from './student-workspace';

type Request=(path:string,method?:string,body?:unknown)=>Promise<any>;
type Scan={id:string;status:string;image:string;error?:string|null};
const errors:Record<string,string>={wechat_identity_mismatch:'扫码微信绑定的学号与当前账号不一致，未保存授权。',wechat_school_not_bound:'请先在学校「成电智慧学工」小程序绑定本人学校账号。',wechat_ticket_rejected:'学校未接受本次授权，请稍后再试。',wechat_scan_expired:'二维码已过期，请重新获取。',wechat_authorization_expired:'微信授权已失效，请重新扫码。',wechat_code_transport_failed:'小程序取码连接未成功，请稍后重试。',wechat_protocol_login_failed:'取码通道未完成连接，请稍后重试。',wechat_binding_rejected:'学校未接受微信绑定校验，请确认原小程序能够正常使用。'};
errors.wechat_refresh_unavailable='授权服务没有返回可续期的令牌，未保存授权，请重新扫码。';
errors.wechat_authorization_changed='授权已被移除或更新，请重新获取二维码。';
export function WechatAuthorization({account,request,onChanged}:{account:StudentAccount;request:Request;onChanged:()=>Promise<void>}){
 const[notice,setNotice]=useState<{version:string;title:string;text:string}|null>(null),[consent,setConsent]=useState(false),[scan,setScan]=useState<Scan|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[remove,setRemove]=useState(false);
 const authorization=account.wechat_authorization;
 useEffect(()=>{let live=true;request('/api/wechat/notice').then(value=>{if(live)setNotice(value.notice)}).catch(e=>{if(live)setError(e.message)});return()=>{live=false}},[]);
 useEffect(()=>{
  if(!scan?.id)return;
  let live=true,finished=false,timer:ReturnType<typeof setTimeout>;
  const id=scan.id;
  async function poll(){try{const value=await request('/api/wechat/scans/'+id);if(!live)return;setScan(value.scan);if(value.scan.status==='completed'){finished=true;toast.success('微信授权已验证，未提交签到');await onChanged();return}if(['failed','cancelled','expired'].includes(value.scan.status)){finished=true;return}timer=setTimeout(poll,1500)}catch(e){if(live){finished=true;setError((e as Error).message)}}}
  timer=setTimeout(poll,900);
  return()=>{live=false;clearTimeout(timer);if(!finished)request('/api/wechat/scans/'+id,'DELETE').catch(()=>{})};
 },[scan?.id]);
 async function start(){if(!notice)return;setBusy(true);setError('');try{const value=await request('/api/accounts/'+account.id+'/wechat/scans','POST',{consent_version:notice.version});setScan(value.scan)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function revoke(){setBusy(true);try{await request('/api/accounts/'+account.id+'/wechat','DELETE');setScan(null);setRemove(false);setConsent(false);toast.success('微信授权已移除，账号与计划保留');await onChanged()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 const processing=scan?.status==='processing',waiting=scan&&['pending','scanned'].includes(scan.status),done=scan?.status==='completed'||authorization?.eligible;
 return <div className="wechat-authorization"><section className="panel wechat-auth-main"><div className="panel-title"><h2><ShieldCheck size={21}/>微信授权</h2><span className="muted">{account.owner_name} · {account.student_id}</span></div><div className="wechat-auth-body">
 <p className="lead">首次扫码后，服务器会在每日执行时获取新的学校操作票据，无需电脑或微信客户端常驻。</p>
 {done&&<div className="notice"><Check size={21}/><p>授权已绑定当前学校账号。访问令牌到期时会尝试自动续期；如授权撤销或续期被拒，本站会提示重新扫码。</p></div>}
 {error&&<p role="alert" className="inline-error">{error}</p>}
 {scan?.status==='failed'&&<p role="alert" className="inline-error">{errors[scan.error||'']||'本次授权未完成，请稍后重试。'}{scan.error&&<small>错误类型：{scan.error}</small>}</p>}
 {scan?.status==='expired'&&<p role="alert" className="inline-error">本次扫码已过期，请重新获取二维码。</p>}
 {waiting&&scan.image?<div className="wechat-qr"><img src={'data:image/png;base64,'+scan.image} alt="微信授权二维码"/><strong>{scan.status==='scanned'?'已扫码，请在微信确认':'请用已绑定本人学校账号的微信扫码'}</strong><p>授权页显示「应用宝」，用于学校小程序取码。</p><button className="text-link" type="button" onClick={async()=>{await request('/api/wechat/scans/'+scan.id,'DELETE');setScan(null)}}>取消本次扫码</button></div>:processing?<div className="wechat-progress" role="status"><LoaderCircle className="spin" size={28}/><h3>正在核对学校身份和票据获取能力</h3><p>微信已确认，请稍候。这个过程不会提交签到。</p></div>:<>
 <div className="wechat-auth-explanation"><h3>{notice?.title||'授权信息托管说明'}</h3><p>{notice?.text||'正在读取授权说明…'}</p></div>
 <label className="student-check"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)}/><span>我理解并同意加密托管上述授权令牌，用于本人学校账号的自动签到。</span></label>
 <button className="button primary" type="button" disabled={!consent||!notice||busy} onClick={start}>{busy?<LoaderCircle className="spin" size={18}/>:<RefreshCw size={18}/>} {authorization?.linked?'重新扫码授权':'获取微信授权二维码'}</button>
 </>}
 {authorization?.linked&&<div className="wechat-revoke">{remove?<><p>移除后，每日计划将等待你重新授权。学校账号、位置和历史记录保留。</p><button className="button danger-button" type="button" disabled={busy} onClick={revoke}>确认移除授权</button><button className="text-link" type="button" onClick={()=>setRemove(false)}>保留授权</button></>:<button className="text-link" type="button" onClick={()=>setRemove(true)}><Trash2 size={16}/>移除微信授权</button>}</div>}
 </div></section><aside className="panel wechat-auth-guide"><div className="panel-title"><h2>授权后的每日流程</h2></div><ol><li><strong>校验身份</strong><p>学校登录与微信绑定必须对应同一学号。</p></li><li><strong>取得本次票据</strong><p>临近提交时获取新的操作票据，每次只使用一次。</p></li><li><strong>执行并复查</strong><p>按已保存地点和学校时段提交，再读取学校记录确认结果。</p></li></ol><p className="field-help">扫码授权不等于签到成功。每日计划仍遵守你选择的地点、时段和防重复提交规则。</p></aside></div>;
}

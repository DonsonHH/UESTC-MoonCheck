import React,{useEffect,useState} from 'react';
import {HostingNoticeDialog,type HostingNotice} from './hosting-notice';
export function SessionNotice({request,onAccepted,onLogout}:{request:(path:string,method?:string,body?:unknown)=>Promise<any>;onAccepted:(session:any)=>void;onLogout:()=>void}){
 const[notice,setNotice]=useState<HostingNotice|null>(null),[error,setError]=useState('');
 useEffect(()=>{request('/api/notice').then(v=>setNotice(v.notice)).catch(e=>setError(e.message))},[]);
 async function accept(version:string){
  try{await request('/api/notice/accept','POST',{version});onAccepted(await request('/api/session'))}
  catch(e){setError((e as Error).message)}
 }
 return <main className="fatal"><h1>请确认本次托管说明</h1><p>继续使用自动签到前，请了解学校登录信息和个人资料的保存方式。</p>{error&&<p role="alert">{error}</p>}<button className="button" onClick={onLogout}>暂不继续并退出</button>{notice&&<HostingNoticeDialog notice={notice} error={error} open loginPending={false} onClose={onLogout} onAccept={accept}/>}</main>;
}

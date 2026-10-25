import React,{useEffect,useState} from 'react';
import {toast} from 'sonner';
import {LoaderCircle,Plus,ShieldCheck,Trash2} from 'lucide-react';

type Grant={id:string;student_id:string;created_at:number};
type Props={request:(path:string,method?:string,body?:unknown)=>Promise<any>;onConfirm:(student:string,action:()=>Promise<void>)=>void};
export function StudentAccessPanel({request,onConfirm}:Props){
 const[grants,setGrants]=useState<Grant[]>([]),[prefix,setPrefix]=useState(''),[student,setStudent]=useState(''),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState('');
 async function load(){setError('');try{const result=await request('/api/portal/authorizations');setGrants(result.authorizations);setPrefix(result.student_prefix)}catch(e){setError((e as Error).message)}finally{setLoading(false)}}
 useEffect(()=>{void load()},[]);
 async function add(event:React.FormEvent){event.preventDefault();setBusy(true);try{await request('/api/portal/authorizations','POST',{student_id:student.trim()});setStudent('');await load();toast.success('已授权该学号，首次登录仍需完成学校验证')}catch(e){toast.error((e as Error).message)}finally{setBusy(false)}}
 async function revoke(grant:Grant){await request('/api/portal/authorizations/'+grant.id,'DELETE');await load();toast.success('额外授权已撤销')}
 return <section className="panel" aria-labelledby="student-access-title"><div className="panel-title"><h2 id="student-access-title"><ShieldCheck size={19}/>学号登录授权</h2></div><div className="student-access-body">
 {loading?<p role="status"><LoaderCircle className="spin" size={17}/>正在读取授权…</p>:error?<div><p role="alert" className="inline-error">{error}</p><button className="button" onClick={()=>void load()}>重新读取</button></div>:<>
 <p className="field-help">默认开放{prefix?<strong className="tabular"> {prefix}** </strong>:'全部学号'}。范围外的同学可在这里单独授权，首次登录仍需完成学校验证。</p>
 <form onSubmit={add} className="student-access-form"><label>额外授权学号<input value={student} onChange={e=>setStudent(e.target.value)} required inputMode="numeric" pattern="[0-9]{8,20}" maxLength={20} autoComplete="off" placeholder="输入需要开放的完整学号" disabled={busy}/></label><button type="submit" className="button primary" disabled={busy}>{busy?<LoaderCircle size={17} className="spin"/>:<Plus size={17}/>}添加授权</button></form>
 {grants.length?<ul className="student-access-list" aria-label="额外授权学号列表">{grants.map(grant=><li key={grant.id}><span className="tabular">{grant.student_id}</span><button type="button" className="button danger-outline" disabled={busy} onClick={()=>onConfirm(grant.student_id,()=>revoke(grant))}><Trash2 size={16}/>撤销授权</button></li>)}</ul>:<p className="field-help">暂未添加额外授权。</p>}
 </>}</div></section>;
}

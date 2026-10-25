import React,{useEffect,useRef,useState} from 'react';
import {ChevronDown,LoaderCircle,RefreshCw} from 'lucide-react';

type RecordRow={id:string;created_at:number;state:string;result:unknown};
type Page<T>={jobs:T[];next_cursor:string|null;recent_since:number};
const merge=<T extends RecordRow>(first:T[],rest:T[])=>[...new Map([...rest,...first].map(row=>[row.id,row])).values()].sort((a,b)=>b.created_at-a.created_at||b.id.localeCompare(a.id));

export function JobHistory<T extends RecordRow>({request,renderJobs,revision}:{request:(path:string)=>Promise<Page<T>>;renderJobs:(jobs:T[])=>React.ReactNode;revision:string}){
 const[rows,setRows]=useState<T[]>([]),[cursor,setCursor]=useState<string|null>(null),[loaded,setLoaded]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[expanded,setExpanded]=useState(false),[refresh,setRefresh]=useState(0);
 const expandedRef=useRef(false),pending=useRef(false),mounted=useRef(true);
 const failedPage=useRef<'recent'|'older'>('recent');
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false}},[]);
 useEffect(()=>{
  let alive=true;
  request('/api/jobs/history').then(page=>{if(!alive)return;setRows(previous=>expandedRef.current?merge(page.jobs,previous):page.jobs);if(!expandedRef.current)setCursor(page.next_cursor);setLoaded(true);setError('')}).catch(e=>{if(alive){failedPage.current='recent';setError(e.message)}});
  return()=>{alive=false};
 },[revision,refresh]);
 async function more(){
  if(!cursor||pending.current)return;
  pending.current=true;setBusy(true);setError('');
  try{const page=await request('/api/jobs/history?cursor='+encodeURIComponent(cursor));if(!mounted.current)return;expandedRef.current=true;setExpanded(true);setRows(previous=>merge(page.jobs,previous));setCursor(page.next_cursor)}
  catch(e){if(mounted.current){failedPage.current='older';setError((e as Error).message)}}
  finally{pending.current=false;if(mounted.current)setBusy(false)}
 }
 return <section className="panel history-panel"><div className="panel-title"><h2>{expanded?'全部已加载记录':'最近三天'}</h2>{expanded&&<button className="text-link" disabled={busy} onClick={()=>{expandedRef.current=false;setExpanded(false);setLoaded(false);setRows([]);setCursor(null);setError('');setRefresh(n=>n+1)}}>只看最近三天</button>}</div>
 {error&&<div role="alert" className="inline-error history-error">{error}<button className="text-link" disabled={busy} onClick={()=>failedPage.current==='older'?void more():setRefresh(n=>n+1)}><RefreshCw size={15}/>重试</button></div>}
 {!loaded&&!error?<div className="loading" role="status"><LoaderCircle className="spin" size={19}/>正在读取记录…</div>:rows.length?renderJobs(rows):loaded?<div className="empty history-empty"><h3>近三天没有运行记录</h3><p>{cursor?'可以继续查看更早的记录。':'执行检查或签到后，结果会出现在这里。'}</p></div>:null}
 {loaded&&(cursor||expanded)&&<div className="history-more">{cursor?<button className="button" onClick={more} disabled={busy}>{busy?<LoaderCircle className="spin" size={17}/>:<ChevronDown size={17}/>} {busy?'正在加载…':'加载更多记录'}</button>:<p role="status">已显示全部记录</p>}</div>}
 </section>;
}

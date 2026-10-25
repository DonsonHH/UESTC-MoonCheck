import React,{useEffect,useRef,useState} from 'react';
import {Dialog} from 'radix-ui';
import {LoaderCircle,RefreshCw,ShieldCheck,X} from 'lucide-react';
import {passiveShell,renderPassivePage} from './passive-page';

type Page={ready:boolean;loading?:boolean;mode:'page';html?:string;revision:string;document:string;host:string;expires_in:number;width:number;height:number};
type EventData={kind:string;key?:string;document:string;value?:string;checked?:boolean;index?:number;x?:number;y?:number;width?:number;height?:number;points?:number[][]};
export class OnboardingError extends Error{constructor(message:string,public code:string,public status:number,public retryAfter?:number){super(message)}}
export async function onboardingRequest(path:string,token:string,body?:unknown){
 const response=await fetch('/api/onboarding/'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Onboarding-CSRF':token},...(body===undefined?{}:{body:JSON.stringify(body)})});
 const value=await response.json();if(!response.ok||value.ok===false)throw new OnboardingError(value.error?.message||'学校验证暂时不可用。',value.error?.code||'browser_unavailable',response.status,Number(value.error?.retry_after)||undefined);return value;
}
export async function awaitSchoolCredentials(start:{onboarding_csrf:string;phase?:string}){
 if(start.phase!=='pending')return;
 for(let attempt=0;attempt<15;attempt++){
  await new Promise(resolve=>setTimeout(resolve,600));
  const progress=await onboardingRequest('progress',start.onboarding_csrf);
  if(progress.phase!=='pending')return;
 }
 try{await onboardingRequest('cancel',start.onboarding_csrf,{})}catch{}
 throw new OnboardingError('学校尚未返回密码校验结果，请稍后重试。','school_unavailable',502);
}
export function AssistedDialog({token,onComplete,onClose,onRejected}:{token:string;onComplete:(value:any)=>void;onClose:()=>void;onRejected:(message:string)=>void}){
 const[page,setPage]=useState<Page|null>(null),[error,setError]=useState(''),[notice,setNotice]=useState(''),[finishing,setFinishing]=useState(false),[retry,setRetry]=useState(0);
 const iframe=useRef<HTMLIFrameElement>(null),title=useRef<HTMLHeadingElement>(null),alive=useRef(true),complete=useRef(false),current=useRef<Page|null>(null),appliedDocument=useRef(''),revision=useRef(''),serial=useRef(Promise.resolve()),dirty=useRef<Record<string,EventData>>({}),wake=useRef(()=>{}),unbind=useRef(()=>{}),boundDocument=useRef<Document|null>(null);
 function queue(event:EventData|null){
  serial.current=serial.current.then(async()=>{const fields=Object.values(dirty.current);dirty.current={};for(const field of fields)await onboardingRequest('event',token,field);if(event)await onboardingRequest('event',token,event);wake.current()}).catch(e=>{if(alive.current){if((e as OnboardingError).status===410)setError(e.message);else{setNotice('校方页面正在变化，正在更新当前页面…');wake.current()}}});return serial.current;
 }
 function apply(){const doc=iframe.current?.contentDocument,value=current.current;if(!doc||!value?.html)return;if(boundDocument.current!==doc){attach();return;}renderPassivePage(doc,value.html,appliedDocument.current!==value.document);appliedDocument.current=value.document;}
 function attach(){
  unbind.current();const doc=iframe.current?.contentDocument,win=iframe.current?.contentWindow;if(!doc||!win)return;boundDocument.current=doc;
  let inputTimer:ReturnType<typeof setTimeout>,scrollTimer:ReturnType<typeof setTimeout>,resizeTimer:ReturnType<typeof setTimeout>;
  let drag:{key:string;rect:DOMRect;points:number[][]}|null=null,suppressClick=false;
  const key=(target:EventTarget|null)=>target&&'closest'in target?(target as Element).closest('[data-moon-node]')?.getAttribute('data-moon-node')||'':'';
  const send=(kind:string,target:EventTarget|null,extra:Partial<EventData>={})=>{if(current.current)queue({kind,key:key(target),document:current.current.document,...extra})};
  const input=(event:Event)=>{const element=event.target as HTMLInputElement;if(!key(element)||element.readOnly||['checkbox','radio','file'].includes(element.type))return;dirty.current[key(element)]={kind:'input',key:key(element),document:current.current?.document||'',value:element.value.slice(0,1024)};clearTimeout(inputTimer);inputTimer=setTimeout(()=>queue(null),180)};
  const change=(event:Event)=>{const element=event.target as HTMLSelectElement;if(element.tagName==='SELECT')send('select',element,{index:element.selectedIndex});else if(['checkbox','radio'].includes((element as unknown as HTMLInputElement).type))send('check',element,{checked:(element as unknown as HTMLInputElement).checked})};
  const click=(event:MouseEvent)=>{const element=event.target as HTMLElement;if(!key(element))return;const choice=element.closest('label')?.querySelector('input[type=checkbox],input[type=radio]');if(choice||element.matches('input[type=checkbox],input[type=radio]'))return;if(element.closest('input:not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"]),textarea,select'))return;event.preventDefault();event.stopPropagation();if(suppressClick){suppressClick=false;return;}send('click',element)};
  const focus=(event:FocusEvent)=>{const element=event.target as HTMLElement;if(element.matches('input,textarea,select'))send('focus',element)};
  const enter=(event:KeyboardEvent)=>{if(event.key==='Enter'){event.preventDefault();send('enter',event.target)}};
  const submit=(event:Event)=>event.preventDefault();
  const scroll=()=>{clearTimeout(scrollTimer);scrollTimer=setTimeout(()=>{if(current.current)queue({kind:'scroll',document:current.current.document,x:Math.max(0,win.scrollX),y:Math.max(0,win.scrollY)})},180)};
  const down=(event:PointerEvent)=>{const target=event.target as Element;const element=target.closest('[class*="sliderContainer"],[class*="slidercaptcha"],[class*="geetest_panel"]')||target.closest('canvas,img,[class*="captcha"],[class*="slider"],[class*="geetest"],[class*="yidun"]');if(!element||!key(element))return;const rect=element.getBoundingClientRect();if(!rect.width||!rect.height)return;event.preventDefault();drag={key:key(element),rect,points:[[Math.max(0,Math.min(1,(event.clientX-rect.left)/rect.width)),Math.max(0,Math.min(1,(event.clientY-rect.top)/rect.height))]]}};
  const move=(event:PointerEvent)=>{if(drag&&drag.points.length<39)drag.points.push([Math.max(0,Math.min(1,(event.clientX-drag.rect.left)/drag.rect.width)),Math.max(0,Math.min(1,(event.clientY-drag.rect.top)/drag.rect.height))])};
  const cancelDrag=()=>{drag=null};
  const up=(event:PointerEvent)=>{move(event);if(drag&&drag.points.length>2&&current.current){const end=[Math.max(0,Math.min(1,(event.clientX-drag.rect.left)/drag.rect.width)),Math.max(0,Math.min(1,(event.clientY-drag.rect.top)/drag.rect.height))];suppressClick=true;queue({kind:'gesture',key:drag.key,document:current.current.document,points:[...drag.points,end]})}cancelDrag()};
  doc.addEventListener('input',input,true);doc.addEventListener('change',change,true);doc.addEventListener('click',click,true);doc.addEventListener('focusin',focus,true);doc.addEventListener('keydown',enter,true);doc.addEventListener('submit',submit,true);win.addEventListener('scroll',scroll);doc.addEventListener('pointerdown',down,true);doc.addEventListener('pointermove',move,true);doc.addEventListener('pointerup',up,true);doc.addEventListener('pointercancel',cancelDrag,true);
  const observer=new ResizeObserver(()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>{const value=current.current,frame=iframe.current;if(value&&frame){const width=Math.max(300,Math.min(1920,Math.round(frame.clientWidth))),height=Math.max(240,Math.min(1400,Math.round(frame.clientHeight)));if(width!==value.width||height!==value.height)queue({kind:'resize',document:value.document,width,height})}},200)});if(iframe.current)observer.observe(iframe.current);
  unbind.current=()=>{cancelDrag();clearTimeout(inputTimer);clearTimeout(scrollTimer);clearTimeout(resizeTimer);observer.disconnect();doc.removeEventListener('input',input,true);doc.removeEventListener('change',change,true);doc.removeEventListener('click',click,true);doc.removeEventListener('focusin',focus,true);doc.removeEventListener('keydown',enter,true);doc.removeEventListener('submit',submit,true);win.removeEventListener('scroll',scroll);doc.removeEventListener('pointerdown',down,true);doc.removeEventListener('pointermove',move,true);doc.removeEventListener('pointerup',up,true);doc.removeEventListener('pointercancel',cancelDrag,true)};
  apply();
 }
 useEffect(()=>{current.current=page;apply()},[page]);
 useEffect(()=>{const value=current.current,frame=iframe.current;if(!value||!frame)return;const width=Math.max(300,Math.min(1920,Math.round(frame.clientWidth))),height=Math.max(240,Math.min(1400,Math.round(frame.clientHeight)));if(width!==value.width||height!==value.height)queue({kind:'resize',document:value.document,width,height})},[page?.document]);
 useEffect(()=>{
  alive.current=true;let cancelled=false,busy=false,pending=false,failures=0;let timer:ReturnType<typeof setTimeout>;setError('');
  async function poll(){if(cancelled||complete.current)return;if(busy){pending=true;return;}busy=true;try{
   const next=await onboardingRequest('state?revision='+encodeURIComponent(revision.current),token);if(cancelled)return;
   failures=0;setNotice('');if(current.current?.document!==next.document)dirty.current={};revision.current=next.revision||revision.current;setPage(previous=>({...previous,...next}));
   if(next.ready&&!complete.current){complete.current=true;setFinishing(true);await serial.current;try{const value=await onboardingRequest('finish',token,{});if(!cancelled)onComplete(value)}catch(e){if(!cancelled)setError((e as Error).message)}return;}
  }catch(e){if(cancelled)return;if((e as OnboardingError).code==='school_login_rejected'){void onboardingRequest('cancel',token,{}).catch(()=>{});onRejected((e as Error).message);return;}if((e as OnboardingError).status===410||++failures>=4){setError((e as Error).message);return;}setNotice('连接短暂中断，正在恢复当前学校页面…')}
  finally{busy=false;}
  if(!cancelled&&!complete.current){timer=setTimeout(poll,pending?0:1200);pending=false;}
  }
  wake.current=()=>{clearTimeout(timer);void poll()};void poll();return()=>{cancelled=true;alive.current=false;clearTimeout(timer)};
 },[token,retry]);
 useEffect(()=>()=>unbind.current(),[]);
 async function cancel(){alive.current=false;try{await onboardingRequest('cancel',token,{})}catch{}onClose()}
 return <Dialog.Root open onOpenChange={open=>!open&&!finishing&&cancel()}><Dialog.Portal><Dialog.Overlay className="overlay"/><Dialog.Content className="modal original-modal" aria-describedby="original-description" onOpenAutoFocus={e=>{e.preventDefault();title.current?.focus()}}>
 <header className="original-heading"><div><Dialog.Title ref={title} tabIndex={-1}>{finishing?'正在绑定学校账号':'学校统一身份认证'}</Dialog.Title><Dialog.Description id="original-description">按学校原页面完成验证；若询问信任设备，请选择信任此浏览器。</Dialog.Description></div><button className="icon-button" aria-label="取消学校验证" onClick={cancel} disabled={finishing}><X size={20}/></button></header>
 <div className="original-bar"><span><ShieldCheck size={15}/>{page?.host||'正在连接学校认证'} · 通过本站认证环境加载</span><button className="text-link" onClick={()=>setRetry(v=>v+1)} disabled={finishing}><RefreshCw size={14}/>重新连接</button></div>
 {notice&&<p className="original-notice" role="status">{notice}</p>}
 {error?<div className="original-error"><p role="alert" className="inline-error">{error}</p><button className="button" onClick={cancel}>返回登录</button></div>:<div className="original-frame-wrap">{(!page?.html||finishing)&&<div className="original-loading"><LoaderCircle className="spin"/>{finishing?'学校验证完成，正在绑定…':'正在加载学校原页面…'}</div>}<iframe ref={iframe} title="学校统一身份认证原页面" sandbox="allow-same-origin" srcDoc={passiveShell} onLoad={attach} className="original-frame" style={{pointerEvents:finishing?'none':'auto'}}/></div>}
 </Dialog.Content></Dialog.Portal></Dialog.Root>;
}

import {useEffect,useState} from 'react';
type HistoryGuard=(path:string,proceed:()=>void)=>void;
type Entry={path:string;index:number};
let historyGuard:HistoryGuard|null=null,currentIndex=0,currentPath='';
let restoringTo:Entry|null=null,approved:Entry|null=null;
function initializeEntry(){
 if(currentPath)return;
 currentPath=location.pathname+location.search;
 currentIndex=Number.isInteger(history.state?.moonRouteIndex)?history.state.moonRouteIndex:0;
 history.replaceState({...history.state,moonRouteIndex:currentIndex},'',location.href);
}
export const adminRoutes:Record<string,string>={overview:'/admin',accounts:'/admin/accounts',users:'/admin/users',history:'/admin/history',support:'/admin/class-bot'};
export const studentRoutes:Record<string,string>={overview:'/app',history:'/app/history',settings:'/app/settings',authorization:'/app/authorization'};
export function navigate(path:string,replace=false){
 initializeEntry();
 if(location.pathname+location.search===path)return;
 currentIndex+=replace?0:1;currentPath=path;
 history[replace?'replaceState':'pushState']({moonRouteIndex:currentIndex},'',path);
 window.dispatchEvent(new PopStateEvent('popstate',{state:history.state}));
 window.scrollTo(0,0);
}
export function useHistoryGuard(enabled:boolean,request:HistoryGuard){
 useEffect(()=>{
  if(!enabled)return;
  historyGuard=request;
  return()=>{if(historyGuard===request)historyGuard=null};
 },[enabled,request]);
}
export function useRoute(){
 const[path,setPath]=useState(()=>{initializeEntry();return location.pathname+location.search});
 useEffect(()=>{
  const update=()=>{
   const next=location.pathname+location.search,index=history.state?.moonRouteIndex;
   // Restore the current entry before asking; cancellation keeps its draft and
   // approval resumes the real traversal without inventing a new history entry.
   if(restoringTo&&next===currentPath){
    const target=restoringTo;restoringTo=null;
    const proceed=()=>{approved=target;history.go(target.index-currentIndex)};
    if(historyGuard)historyGuard(target.path,proceed);else proceed();
    return;
   }
   const accepted=approved?.path===next&&approved.index===index;
   if(accepted)approved=null;
   if(!accepted&&historyGuard&&next!==currentPath&&Number.isInteger(index)&&index!==currentIndex){
    restoringTo={path:next,index};history.go(currentIndex-index);return;
   }
   currentPath=next;
   if(Number.isInteger(index))currentIndex=index;
   setPath(next);
  };
  window.addEventListener('popstate',update);
  return()=>window.removeEventListener('popstate',update);
 },[]);
 return path.split('?')[0];
}
export function resolveTab(path:string,admin:boolean){return Object.entries(admin?adminRoutes:studentRoutes).find(([,url])=>url===path)?.[0]||'overview'}
export function loginDestination(admin:boolean){const candidate=new URLSearchParams(location.search).get('next')||'';return Object.values(admin?adminRoutes:studentRoutes).includes(candidate)?candidate:admin?'/admin':'/app'}

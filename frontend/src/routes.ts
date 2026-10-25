import {useEffect,useState} from 'react';
export const adminRoutes:Record<string,string>={overview:'/admin',accounts:'/admin/accounts',users:'/admin/users',history:'/admin/history'};
export const studentRoutes:Record<string,string>={overview:'/app',history:'/app/history',settings:'/app/settings',authorization:'/app/authorization'};
export function navigate(path:string,replace=false){if(location.pathname+location.search===path)return;history[replace?'replaceState':'pushState']({},'',path);window.dispatchEvent(new PopStateEvent('popstate'));window.scrollTo(0,0)}
export function useRoute(){const[path,setPath]=useState(location.pathname+location.search);useEffect(()=>{const update=()=>setPath(location.pathname+location.search);window.addEventListener('popstate',update);return()=>window.removeEventListener('popstate',update)},[]);return path.split('?')[0]}
export function resolveTab(path:string,admin:boolean){return Object.entries(admin?adminRoutes:studentRoutes).find(([,url])=>url===path)?.[0]||'overview'}
export function loginDestination(admin:boolean){const candidate=new URLSearchParams(location.search).get('next')||'';return Object.values(admin?adminRoutes:studentRoutes).includes(candidate)?candidate:admin?'/admin':'/app'}

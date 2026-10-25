import React,{createContext,useContext,useEffect,useState} from 'react';
import {Monitor,Moon,Sun} from 'lucide-react';

type Mode='system'|'light'|'dark';
const valid=(value:unknown):value is Mode=>['system','light','dark'].includes(value as string);
const Theme=createContext<{mode:Mode;resolved:'light'|'dark';setMode:(mode:Mode)=>void}>({mode:'system',resolved:'light',setMode:()=>{}});

export function ThemeProvider({children}:{children:React.ReactNode}){
 const[mode,setMode]=useState<Mode>(()=>{const value=document.documentElement.dataset.theme;return valid(value)?value:'system'});
 const[systemDark,setSystemDark]=useState(()=>matchMedia('(prefers-color-scheme: dark)').matches);
 useEffect(()=>{const media=matchMedia('(prefers-color-scheme: dark)'),change=()=>setSystemDark(media.matches);media.addEventListener('change',change);change();return()=>media.removeEventListener('change',change)},[]);
 useEffect(()=>{document.documentElement.dataset.theme=mode;try{localStorage.setItem('moon-color-mode',mode)}catch{}},[mode]);
 useEffect(()=>{const change=(event:StorageEvent)=>{if(event.key==='moon-color-mode')setMode(valid(event.newValue)?event.newValue:'system')};addEventListener('storage',change);return()=>removeEventListener('storage',change)},[]);
 return <Theme.Provider value={{mode,resolved:mode==='system'?(systemDark?'dark':'light'):mode,setMode}}>{children}</Theme.Provider>;
}
export const useTheme=()=>useContext(Theme);
export function ThemeControl(){
 const{mode,setMode}=useTheme(),Icon=mode==='system'?Monitor:mode==='dark'?Moon:Sun;
 return <label className="theme-picker"><Icon size={17} aria-hidden="true"/><select aria-label="外观模式" value={mode} onChange={event=>setMode(event.target.value as Mode)}><option value="system">跟随系统</option><option value="light">浅色模式</option><option value="dark">深色模式</option></select></label>;
}

import morphdom from 'morphdom';

// The school page never executes scripts in this frame. This parent-owned
// patcher preserves its real DOM/CSS, focused fields and scroll positions.
export const passiveShell='<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'none\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\' data:; connect-src \'none\'; frame-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'"></head><body></body></html>';

export function renderPassivePage(document:Document,html:string,newDocument:boolean){
 const parsed=new DOMParser().parseFromString(html,'text/html');
 // Defense in depth, independent of the server sanitizer and iframe sandbox.
 parsed.querySelectorAll('script,iframe,frame,object,embed,base,meta[http-equiv],input[type="hidden"]').forEach(node=>node.remove());
 for(const element of parsed.querySelectorAll('*'))for(const attribute of [...element.attributes]){
  if(attribute.name.toLowerCase().startsWith('on')||['action','formaction','srcdoc','target','autofocus'].includes(attribute.name.toLowerCase()))element.removeAttribute(attribute.name);
 }
 // School drag handlers run remotely; reserve touch drags on the original
 // slider track so a phone does not turn them into page scrolling.
 for(const slider of parsed.querySelectorAll<HTMLElement>('.sliderContainer,.slidercaptcha,.geetest_panel'))slider.style.touchAction='none';
 if(newDocument){document.replaceChild(document.importNode(parsed.documentElement,true),document.documentElement);return;}
 morphdom(document.documentElement,parsed.documentElement,{
  getNodeKey:node=>node.nodeType===1?(node as Element).getAttribute('data-moon-node')||undefined:undefined,
  onBeforeElUpdated:(from,to)=>{
   // Editable values are deliberately never serialized by the school helper.
   // Retain the owner's local typing while applying classes, errors and modal
   // state from the actual school document.
   if(from.tagName==='INPUT'&&!['checkbox','radio','button','submit'].includes((from as HTMLInputElement).type)){
    (to as HTMLInputElement).value=(from as HTMLInputElement).value;
   }else if(from.tagName==='TEXTAREA'){
    (to as HTMLTextAreaElement).value=(from as HTMLTextAreaElement).value;to.textContent=(from as HTMLTextAreaElement).value;
   }else if(from.tagName==='SELECT'){
    (to as HTMLSelectElement).selectedIndex=(from as HTMLSelectElement).selectedIndex;
   }
   if(from.isEqualNode(to))return false;
   return true;
  }
 });
}

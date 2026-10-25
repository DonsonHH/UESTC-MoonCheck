() => {
  const memory = window.__moonPage || (window.__moonPage = {next:0,keys:new WeakMap()});
  for(const element of document.querySelectorAll('*')) {
    if(!memory.keys.has(element)) memory.keys.set(element,'n'+(++memory.next));
    element.setAttribute('data-moon-node',memory.keys.get(element));
  }
  const root=document.documentElement.cloneNode(true),resources=[],canvases={};
  const resource=(source,base=document.baseURI)=>{
    if(!source)return '';
    if(source.startsWith('#')||/^data:(image\/(png|jpeg|gif|webp|svg\+xml)|font\/|application\/font)/i.test(source))return source;
    try {const url=new URL(source,base);if(url.protocol!=='https:')return '';const token='__MOON_RESOURCE_'+resources.length+'__';resources.push(url.href);return token;}catch{return '';}
  };
  const css=(text,base)=>String(text).replace(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi,(_,a,b,c)=>'url("'+resource((a??b??c??'').trim(),base)+'")').replace(/@import\s+["']([^"']+)["']/gi,(_,url)=>'@import "'+resource(url,base)+'"');
  root.querySelectorAll('script,noscript,iframe,frame,object,embed,base,template,meta[http-equiv],input[type="hidden"],audio,video,source').forEach(e=>e.remove());
  const originals=new Map([...document.querySelectorAll('[data-moon-node]')].map(e=>[e.getAttribute('data-moon-node'),e]));
  for(const element of [root,...root.querySelectorAll('*')]) {
    const original=originals.get(element.getAttribute('data-moon-node'));
    for(const attribute of [...element.attributes]) {
      const name=attribute.name.toLowerCase();
      if(name.startsWith('on')||['srcdoc','action','formaction','target','download','autofocus','nonce','integrity','crossorigin','ping','srcset'].includes(name))element.removeAttribute(attribute.name);
    }
    if(element.tagName==='LINK') {
      if(!['stylesheet','icon','shortcut icon'].includes((element.getAttribute('rel')||'').toLowerCase())){element.remove();continue;}
      element.setAttribute('href',resource(original?.href||element.getAttribute('href')));
    } else if(element.tagName==='A')element.setAttribute('href','#');
    else if(element.hasAttribute('href')&&!element.getAttribute('href').startsWith('#'))element.setAttribute('href',resource(element.getAttribute('href')));
    if(element.tagName==='IMG')element.setAttribute('src',resource(original?.currentSrc||original?.src||element.getAttribute('src')));
    else if(element.hasAttribute('src'))element.removeAttribute('src');
    if(element.hasAttribute('style'))element.setAttribute('style',css(element.getAttribute('style'),original?.baseURI||document.baseURI));
    if(element.tagName==='STYLE')element.textContent=css(element.textContent,original?.baseURI||document.baseURI);
    if(element.tagName==='INPUT') {
      element.removeAttribute('value');
      if(original?.checked)element.setAttribute('checked','');else element.removeAttribute('checked');
      if(['username','password'].includes(element.id)){element.setAttribute('readonly','');element.setAttribute('placeholder',element.id==='password'?'学校密码已填写':'学号已填写');}
    }
    if(element.tagName==='TEXTAREA')element.textContent='';
    if(element.tagName==='OPTION'){element.setAttribute('value',String(original?.index||0));if(original?.selected)element.setAttribute('selected','');else element.removeAttribute('selected');}
    if(element.tagName==='CANVAS'&&original&&original.width<=800&&original.height<=800) {
      try {const data=original.toDataURL('image/png');if(data.length<=220000){const image=document.createElement('img');for(const a of element.attributes)image.setAttribute(a.name,a.value);image.setAttribute('width',String(original.width));image.setAttribute('height',String(original.height));const token='__MOON_CANVAS_'+Object.keys(canvases).length+'__';canvases[token]=data;image.setAttribute('src',token);element.replaceWith(image);}}catch{}
    }
  }
  const nodes=[...root.querySelectorAll('[data-moon-node]')].map(e=>({key:e.getAttribute('data-moon-node'),tag:originals.get(e.getAttribute('data-moon-node'))?.tagName.toLowerCase(),primary:['username','password'].includes(e.id)}));
  return {mode:'page',document:String(performance.timeOrigin),html:'<!doctype html>'+root.outerHTML,resources,canvases,nodes};
}

"""Extract visible CAS error text without retaining forms or response bodies."""
from html.parser import HTMLParser
from urllib.parse import urlsplit
import re
from diagnostics import safe_text


class LoginHints(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.stack=[];self.errors=[];self.title=[]
        self.feed(text[:1024*1024])

    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag in ('input','img','br','meta','link','hr','source','wbr'):return
        parent=self.stack[-1] if self.stack else (False,False,False)
        marker=' '.join(attrs.get(k,'') for k in ('id','class','role')).lower().strip()
        error=bool(re.search(r'error|alert-danger|alert-error|showerrortip|^alert$',marker))
        ignored=parent[2] or tag in ('script','style','noscript') or 'hidden' in attrs or attrs.get('aria-hidden')=='true'
        self.stack.append((parent[0] or error,parent[1] or tag=='title',ignored))

    def handle_endtag(self, tag):
        if self.stack:self.stack.pop()

    def handle_data(self, data):
        if not self.stack or self.stack[-1][2]:return
        if self.stack[-1][0]:self.errors.append(data)
        if self.stack[-1][1]:self.title.append(data)


def endpoint(url, account=None):
    try:
        parsed=urlsplit(url)
        hostname=parsed.hostname or ''
        host=hostname if hostname in ('idas.uestc.edu.cn','jzsz.uestc.edu.cn') else safe_text(hostname,account,limit=100)
        path='/'.join(safe_text(part,account,limit=80) for part in (parsed.path or '/').split('/'))
        return (host+path)[:240]
    except (ValueError,TypeError):return '地址无法解析'


def response_hints(response, account, cookies):
    secrets=(account,{'cookies':cookies})
    message='';code=None
    try:data=response.json()
    except (ValueError,TypeError):data=None
    if isinstance(data,dict):
        for source in (data,data.get('data')):
            if not isinstance(source,dict):continue
            message=next((safe_text(source[k],*secrets) for k in ('msg','message','error_description','error') if isinstance(source.get(k),str) and source[k].strip()),'')
            if message:break
        if type(data.get('code')) is int:code=data['code']
    title=''
    if not message:
        parser=LoginHints(response.text)
        message=safe_text(' '.join(dict.fromkeys(part.strip() for part in parser.errors if part.strip())),*secrets)
        title=safe_text(' '.join(parser.title),*secrets,limit=100)
    return message,title,code

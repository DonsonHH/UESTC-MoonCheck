"""Bounded CAS hints, adapted from Ryan-Orion/UESTC-MoonCheck 553b1dc.

Retain visible error messages and numeric codes, never forms, raw bodies,
redirect queries, login tickets or Cookie values.
"""
from html.parser import HTMLParser
import re

from .diagnostics import school_message
from .errors import ToolError


class LoginHints(HTMLParser):
    VOID={'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}

    def __init__(self,text):
        super().__init__(convert_charrefs=True)
        self.stack=[];self.errors=[]
        self.feed(text[:1024*1024])

    def handle_starttag(self,tag,attrs):
        if tag in self.VOID:return
        attrs=dict(attrs)
        parent=self.stack[-1] if self.stack else ('',False,False)
        marker=' '.join(attrs.get(key) or '' for key in ('id','class','role')).lower()
        error=parent[1] or bool(re.search(r'error|alert-danger|alert-error|showerrortip|(?:^|\s)alert(?:\s|$)',marker))
        style=attrs.get('style') or ''
        hidden=(parent[2] or tag in ('script','style','noscript','template') or 'hidden' in attrs
            or (attrs.get('aria-hidden') or '').lower()=='true'
            or bool(re.search(r'(?:display\s*:\s*none|visibility\s*:\s*hidden)',style,re.I))
            or bool(re.search(r'(?:^|\s)(?:hidden|hide|d-none|sr-only)(?:\s|$)',attrs.get('class') or '',re.I)))
        self.stack.append((tag,error,hidden))

    def handle_endtag(self,tag):
        for index in range(len(self.stack)-1,-1,-1):
            if self.stack[index][0]==tag:
                del self.stack[index:];break

    def handle_data(self,data):
        if self.stack and self.stack[-1][1] and not self.stack[-1][2] and len(self.errors)<16:
            self.errors.append(data[:512])


def response_hints(response,account,*,extra_secrets=()):
    try:value=response.json('cas_diagnostics')
    except ToolError:value=None
    message=None;code=None
    if isinstance(value,dict):
        if type(value.get('code')) is int:code=value['code']
        for item in (value,value.get('data')):
            if not isinstance(item,dict):continue
            message=next((item[key] for key in ('msg','message','error_description','error')
                if isinstance(item.get(key),str) and item[key].strip()),None)
            if message:break
    if not message:
        parser=LoginHints(response.text)
        message=' '.join(dict.fromkeys(part.strip() for part in parser.errors if part.strip()))
    return {'http_status':response.status,'api_code':code,
            'school_message':school_message(message,account,extra_secrets=extra_secrets)}

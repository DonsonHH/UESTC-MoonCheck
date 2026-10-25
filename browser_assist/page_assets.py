"""Owner-scoped passive page assets; this is not a general URL proxy."""
import base64,hashlib,re,secrets
from urllib.parse import urljoin,urlsplit,urlunsplit
from access_policy import allowed_resource

def allowed(url):
    return allowed_resource(url)

class PageAssets:
    def __init__(self):self.salt=secrets.token_hex(16);self.refs={};self.cached={};self.size=0
    def reference(self,url,base=''):
        absolute=urljoin(base,url)
        if not allowed(absolute):return ''
        value=urlsplit(absolute);fragment=value.fragment
        absolute=urlunsplit(value._replace(fragment=''))
        cached=self.cached.get(absolute)
        digest=hashlib.sha256(cached[1]).hexdigest() if cached else ''
        key=hashlib.sha256((self.salt+absolute+digest).encode()).hexdigest()[:32]
        self.refs[key]=absolute
        return '/api/onboarding/assets/'+key+('#'+fragment if fragment else '')
    def remember(self,url,content_type,body):
        mime=content_type.split(';')[0].strip().lower()
        if not allowed(url) or len(body)>4_000_000 or not (mime=='text/css' or mime.startswith('image/') or mime.startswith('font/') or mime in ('application/font-woff','application/vnd.ms-fontobject','application/octet-stream')):return
        old=self.cached.get(url)
        new_size=self.size-(len(old[1]) if old else 0)+len(body)
        if new_size>16_000_000:return
        self.cached[url]=(mime,body);self.size=new_size
    def stylesheet(self,text,base):
        pattern=r'''url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)'''
        def replace(match):
            url=next((x for x in match.groups() if x is not None),'').strip()
            if url.startswith(('data:','#')):return match[0]
            return 'url("'+self.reference(url,base)+'")'
        text=re.sub(pattern,replace,text,flags=re.I)
        return re.sub(r'''@import\s+["']([^"']+)["']''',lambda m:'@import "'+self.reference(m[1],base)+'"',text,flags=re.I)
    def document(self,snapshot):
        html=snapshot['html']
        for index,url in enumerate(snapshot['resources']):html=html.replace('__MOON_RESOURCE_'+str(index)+'__',self.reference(url))
        for token,data in snapshot['canvases'].items():
            body=base64.b64decode(data.split(',',1)[1],validate=True)
            url='https://idas.uestc.edu.cn/__moon_canvas/'+hashlib.sha256(body).hexdigest()
            self.remember(url,'image/png',body);html=html.replace(token,self.reference(url))
        return html
    def get(self,key,context):
        url=self.refs.get(key)
        if not url:raise ValueError('invalid_asset')
        cached=self.cached.get(url)
        if cached is None:
            # Only page-bound references can be fetched. A cached school image
            # is reused so loading a QR never generates a different challenge.
            static=re.search(r'\.(css|woff2?|ttf|otf|eot|png|jpe?g|gif|webp|svg|ico)$',urlsplit(url).path,re.I)
            challenge=re.search(r'captcha|qrcode|qr[-_]?code|verify|challenge',url,re.I)
            if not static or challenge:raise ValueError('invalid_asset')
            response=context.request.get(url,timeout=15000,max_redirects=0)
            if response.status!=200:raise ValueError('invalid_asset')
            self.remember(url,response.headers.get('content-type',''),response.body())
            cached=self.cached.get(url)
        if cached is None:raise ValueError('invalid_asset')
        mime,body=cached
        if mime=='text/css':body=self.stylesheet(body.decode('utf-8',errors='replace'),url).encode()
        return {'mime':mime,'body':base64.b64encode(body).decode()}

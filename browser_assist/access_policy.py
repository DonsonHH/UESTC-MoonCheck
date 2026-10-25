"""Exact authentication-provider scope, shared by navigation and asset routing."""
from urllib.parse import urlsplit,parse_qs,unquote

SCHOOL_HOSTS={'idas.uestc.edu.cn','jzsz.uestc.edu.cn'}
WECHAT_HOST='open.weixin.qq.com'
STATIC_HOSTS={'res.wx.qq.com','res2.wx.qq.com'}
POLL_HOSTS={'lp.open.weixin.qq.com','long.open.weixin.qq.com'}
RESOURCE_HOSTS=SCHOOL_HOSTS|STATIC_HOSTS|POLL_HOSTS|{WECHAT_HOST}

def allowed_resource(url):
    try:u=urlsplit(url);return u.scheme=='https' and u.hostname in RESOURCE_HOSTS and u.port in (None,443) and not u.username and not u.password
    except ValueError:return False

def school_callback(url):
    for _ in range(2):
        if url.startswith('https://'):break
        url=unquote(url)
    try:u=urlsplit(url);return u.scheme=='https' and u.hostname=='idas.uestc.edu.cn' and u.port in (None,443) and not u.username and not u.password
    except ValueError:return False

def allowed_request(url,resource_type,scope):
    if not allowed_resource(url):return False
    u=urlsplit(url)
    if resource_type=='document':
        if u.hostname in SCHOOL_HOSTS:return True
        if u.hostname!=WECHAT_HOST or not u.path.startswith('/connect/'):return False
        callback=parse_qs(u.query).get('redirect_uri')
        if callback:
            if len(callback)!=1 or not school_callback(callback[0]):return False
            scope['wechat_enabled']=True
        return bool(scope.get('wechat_enabled'))
    if u.hostname in STATIC_HOSTS:return resource_type in ('script','stylesheet','image','font')
    if u.hostname in POLL_HOSTS or u.hostname==WECHAT_HOST:return bool(scope.get('wechat_enabled'))
    return True

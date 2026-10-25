"""Opaque ordering cursor for owner-scoped history; never an authorization token."""
import base64
import datetime as dt
import json
import math
import re
from .web_errors import WebError

PAGE_SIZE=30

def recent_start(instant):
    return (instant-dt.timedelta(days=2)).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()

def encode_cursor(stamp,job_id):
    return base64.urlsafe_b64encode(json.dumps([stamp,job_id],separators=(',',':')).encode()).decode().rstrip('=')

def decode_cursor(value):
    try:
        if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9_-]{1,256}',value):raise ValueError()
        stamp,job_id=json.loads(base64.b64decode(value+'='*(-len(value)%4),altchars=b'-_',validate=True))
        if type(stamp) not in (int,float) or not math.isfinite(stamp) or not 0<=stamp<=253402300799:raise ValueError()
        if not isinstance(job_id,str) or not re.fullmatch('[a-f0-9]{32}|',job_id):raise ValueError()
        return stamp,job_id
    except (ValueError,TypeError,OverflowError):
        raise WebError(400,'invalid_cursor','记录分页已失效，请刷新后重试。') from None

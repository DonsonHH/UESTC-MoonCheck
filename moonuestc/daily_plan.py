"""Stable daily variation: one point and target time per account and date."""
import hashlib,hmac,math
from .errors import ToolError

def normalize_variation(value=None):
    value={} if value is None else value
    if not isinstance(value,dict) or set(value)-{'minutes','meters'}:raise ToolError('invalid_daily_variation','config')
    result={key:value.get(key,0) for key in ('minutes','meters')}
    if any(type(result[key]) is not int or not 0<=result[key]<=limit for key,limit in (('minutes',5),('meters',10))):raise ToolError('invalid_daily_variation','config')
    return result

def sample(account,day,purpose):
    seed=account.get('variation_seed') or str(account.get('id',''))+str(account.get('student_id',''))
    return int.from_bytes(hmac.new(seed.encode(),(day+'|'+purpose).encode(),hashlib.sha256).digest()[:8],'big')/2**64

def minute(value):
    hour,part=map(int,value.split(':'));return hour*60+part

def planned_time(account,base,day,bounds=None,school=None):
    spread=normalize_variation(account.get('variation'))['minutes']
    offset=min(spread*2,int(sample(account,day,'time')*(spread*2+1)))-spread if spread else 0
    low,high=(map(minute,bounds) if bounds else (0,1439))
    if school:
        low=max(low,minute(school['start']));high=min(high,minute(school['end'])-2)
    if low>high:raise ToolError('schedule_window_unavailable','schedule')
    return '%02d:%02d'%divmod(max(low,min(high,minute(base)+offset)),60)

def position_for(account,day,latitude,longitude):
    meters=normalize_variation(account.get('variation'))['meters']
    if not meters:return latitude,longitude
    radius=meters*math.sqrt(sample(account,day,'radius'));angle=sample(account,day,'angle')*math.tau
    if abs(latitude)>85:raise ToolError('variation_location_unsupported','location')
    return (latitude+math.degrees(radius*math.cos(angle)/6378137),
            longitude+math.degrees(radius*math.sin(angle)/(6378137*math.cos(math.radians(latitude)))))

def verify_circle(latitude,longitude,meters,fences):
    from .policy import check_fence
    check_fence({'latitude':latitude,'longitude':longitude},fences)
    for fence in fences:
        dlat=math.radians(fence['latitude']-latitude);dlng=math.radians(fence['longitude']-longitude)
        hav=math.sin(dlat/2)**2+math.cos(math.radians(latitude))*math.cos(math.radians(fence['latitude']))*math.sin(dlng/2)**2
        distance=6378137*2*math.asin(math.sqrt(min(1,max(0,hav))))
        if distance+meters<=fence['radiusMeter']:return
    raise ToolError('variation_outside_allowed_location','location')

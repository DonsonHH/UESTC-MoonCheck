"""Primary starts use the first half-minute; delayed retries reserve the second."""
import datetime as dt,math
from .daily_plan import minute,sample,normalize_variation
from .policy import SHANGHAI,now

def slot_bounds(bounds):
    low,high=map(minute,bounds or ('21:06','23:24'))
    return low,max(low,high-5)

def clock(value):return '%02d:%02d'%divmod(value,60)

def reserve_slot(db,account_id,preferred,bounds,*,replace=False,school=None,account=None,day=None):
    if not bounds:return None
    day=day or now().date().isoformat()
    account=account or {'id':account_id,'variation':{'minutes':5,'meters':0}}
    spread=normalize_variation(account.get('variation'))['minutes']
    low,high=slot_bounds(bounds)
    if school:
        low=max(low,minute(school['start']));high=min(high,minute(school['end'])-7)
    low=max(low,minute(preferred)-spread);high=min(high,minute(preferred)+spread)
    db.execute('DELETE FROM web_schedule_slots WHERE business_date!=?',(day,))
    existing=db.execute('SELECT minute FROM web_schedule_slots WHERE account_id=?',(account_id,)).fetchone()
    if existing and low<=existing[0]<=high and not replace:return existing[0]
    used={r[0] for r in db.execute('SELECT minute FROM web_schedule_slots WHERE account_id!=?',(account_id,))}
    candidates=[value for value in range(low,high+1) if value not in used]
    if not candidates:
        if existing and not low<=existing[0]<=high:db.execute('DELETE FROM web_schedule_slots WHERE account_id=?',(account_id,))
        return None
    offset=int(sample(account,day,'time')*(spread*2+1))-spread if spread else 0
    target=max(low,min(high,minute(preferred)+offset))
    chosen=min(candidates,key=lambda value:(abs(value-target),sample(account,day,'tie:'+str(value))))
    db.execute('INSERT INTO web_schedule_slots(account_id,minute,business_date) VALUES(?,?,?) ON CONFLICT(account_id) DO UPDATE SET minute=excluded.minute,business_date=excluded.business_date',(account_id,chosen,day))
    return chosen

def slot_target(account,day,reservation):
    seconds=int(sample(account,day,'reserved-second')*20) if normalize_variation(account.get('variation'))['minutes'] else 0
    return clock(reservation)+':%02d'%seconds

def slot_description(value):
    return {'start':clock(value),'end':clock(value)+':30','seconds':30} if value is not None else None

def retry_reservation(db,job,stamp,bounds):
    low,high=map(minute,bounds or ('00:00','23:59'))
    day=dt.date.fromisoformat(job['business_date']);start=dt.datetime.combine(day,dt.time(),SHANGHAI)
    first=max(low,math.ceil((stamp+120-start.timestamp()-30)/60));last=high-1
    used={r[0] for r in db.execute('SELECT minute FROM web_schedule_retries WHERE business_date=?',(job['business_date'],))}
    for value in range(first,last+1):
        if value in used:continue
        db.execute('INSERT INTO web_schedule_retries VALUES(?,?,?)',(job['id'],job['business_date'],value))
        return start.timestamp()+value*60+30
    return None

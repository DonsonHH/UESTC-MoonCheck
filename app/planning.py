"""Stable daily randomness, bounded by the configured deadline and location radius."""
import hashlib
import hmac
import math
import random
from datetime import timedelta

def minute(value):
    return int(value[:2]) * 60 + int(value[3:])

def rng_for(key, aid, day, purpose):
    message = f'mooncheck/v1/{aid}/{day}/{purpose}'.encode()
    seed = hmac.new(key, message, hashlib.sha256).digest()
    return random.Random(int.from_bytes(seed, 'big'))

def daily_plan(key, account, settings, day):
    aid = account['id']
    base = minute(settings['time']) * 60
    deadline = minute(settings['window_end']) * 60
    maximum = max(0, min(int(settings.get('time_jitter_seconds', 120)), deadline - base - 15))
    purpose = f"time/{settings['time']}/{settings['window_end']}/{maximum}"
    delay = rng_for(key, aid, day, purpose).randint(0, maximum)
    count = account.get('state', {}).get('attempt_count', 0)
    retry_delay = rng_for(key, aid, day, f'retry/{count}').randint(0, min(30, maximum))
    target = base + delay
    return {'date':day, 'delay_seconds':delay, 'target_second':target, 'target_time':f'{target//3600:02d}:{target//60%60:02d}:{target%60:02d}', 'retry_delay_seconds':retry_delay}

def plan_datetime(current, plan):
    return current.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(seconds=plan['target_second'])

def distance(lat1, lng1, lat2, lng2):
    a, b = math.radians(lat1), math.radians(lat2)
    x = math.sin((b-a)/2)**2 + math.cos(a)*math.cos(b)*math.sin(math.radians(lng2-lng1)/2)**2
    return 6371008.8 * 2 * math.asin(math.sqrt(min(1, max(0, x))))

def destination(lat, lng, meters, angle):
    a, b = math.radians(lat), math.radians(lng)
    arc = meters / 6371008.8
    result_lat = math.asin(math.sin(a)*math.cos(arc) + math.cos(a)*math.sin(arc)*math.cos(angle))
    result_lng = b + math.atan2(math.sin(angle)*math.sin(arc)*math.cos(a), math.cos(arc)-math.sin(a)*math.sin(result_lat))
    return math.degrees(result_lat), (math.degrees(result_lng)+180)%360-180

def randomized_location(key, account, settings, day, locations):
    result = dict(account)
    if account.get('coordinate_system', 'gcj02') != 'gcj02':
        return result
    radius = min(float(settings.get('location_jitter_meters',5)), max(0,float(account.get('accuracy',50))))
    if radius <= 0:
        return result
    lat, lng = account['latitude'], account['longitude']
    circles = []
    for location in locations:
        try:
            a,b,r = (float(location[k]) for k in ('latitude','longitude','radiusMeter'))
            if all(math.isfinite(v) for v in (a,b,r)) and -90<=a<=90 and -180<=b<=180 and r>0 and distance(lat,lng,a,b)<=r:
                circles.append((a,b,r))
        except (KeyError,ValueError,TypeError):
            continue
    # Never move an out-of-range point into a permitted location, or guess a boundary.
    if not circles:
        return result
    rng = rng_for(key,account['id'],day,'location')
    meters, angle = radius * math.sqrt(rng.random()), rng.random()*2*math.pi
    for _ in range(30):
        candidate = destination(lat,lng,meters,angle)
        if any(distance(*candidate,a,b)<=r for a,b,r in circles):
            result.update(latitude=candidate[0],longitude=candidate[1],browser_location=False,location_duration_ms=0)
            return result
        meters /= 2
    return result

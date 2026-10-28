"""Bounded school address reads with encrypted, place-bound local reuse."""
import json
import contextlib
import math
import os
import sqlite3
from pathlib import Path

from .errors import ToolError
from .policy import build_payload
from .vault import Vault

FRESH_SECONDS=86400
MAX_SECONDS=7*86400
MAX_DISTANCE_METERS=25


def valid_address(value):
    return (isinstance(value,str) and 0<len(value.strip())<=1000
        and not any(ord(c)<32 or c in '<>{}' for c in value))


def scope_for(account,instant):
    base=build_payload({**account,'variation':{'minutes':0,'meters':0}},instant)
    place=(account.get('location') or {}).get('preset','fixed')
    return json.dumps([place,base['latitude'],base['longitude'],'gcj02'],separators=(',',':'))


def nearby(a,b):
    lat,lng=a;other_lat,other_lng=b
    value=math.sin(math.radians(lat-other_lat)/2)**2+math.cos(math.radians(lat))*math.cos(math.radians(other_lat))*math.sin(math.radians(lng-other_lng)/2)**2
    return 6378137*2*math.asin(math.sqrt(min(1,max(0,value))))<=MAX_DISTANCE_METERS


class AddressCache:
    def __init__(self,directory):
        self.directory=Path(directory);self.vault=Vault(directory);self.path=self.directory/'geocode.sqlite3'
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS map_addresses(scope TEXT PRIMARY KEY,payload BLOB NOT NULL,expires_at REAL NOT NULL)')
        os.chmod(self.path,0o600)
    @contextlib.contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=2)
        try:
            with db:yield db
        finally:db.close()
    def load(self,scope,point,stamp):
        key=self.vault.digest('geocode',scope)
        with self.db() as db:
            row=db.execute('SELECT payload FROM map_addresses WHERE scope=? AND expires_at>?',(key,stamp)).fetchone()
        if not row:return None
        value=self.vault.open(row[0],'geocode:'+key)
        if not isinstance(value,dict) or not valid_address(value.get('address')):return None
        at=value.get('fetched_at');coords=[value.get('latitude'),value.get('longitude')]
        if type(at) not in (int,float) or not math.isfinite(at) or not 0<=stamp-at<MAX_SECONDS:return None
        if any(type(n) not in (int,float) or not math.isfinite(n) for n in coords) or not nearby(point,coords):return None
        return value
    def save(self,scope,point,address,stamp):
        if not valid_address(address):return
        key=self.vault.digest('geocode',scope)
        value={'address':address.strip(),'latitude':point[0],'longitude':point[1],'fetched_at':stamp}
        with self.db() as db:
            db.execute('DELETE FROM map_addresses WHERE expires_at<=?',(stamp,))
            db.execute('INSERT INTO map_addresses VALUES(?,?,?) ON CONFLICT(scope) DO UPDATE SET payload=excluded.payload,expires_at=excluded.expires_at',
                (key,self.vault.seal(value,'geocode:'+key),stamp+MAX_SECONDS))
            db.execute('DELETE FROM map_addresses WHERE scope NOT IN (SELECT scope FROM map_addresses ORDER BY expires_at DESC LIMIT 128)')


def transient(error):
    return error.reason in ('reverse_geocode_unavailable','timeout','network_error','connection_error','dns_error','invalid_json') or error.reason=='http_error' and (error.http_status==429 or type(error.http_status) is int and error.http_status>=500)


def resolve_address(school,account,payload,directory,*,clock,sleep,emit=lambda *a,**k:None):
    point=(payload['latitude'],payload['longitude']);instant=clock();day=instant.date();scope=scope_for(account,instant)
    cache=cached=None
    try:
        cache=AddressCache(directory);cached=cache.load(scope,point,instant.timestamp())
    except (OSError,sqlite3.Error,ToolError,ValueError,TypeError):cache=None
    if cached and instant.timestamp()-cached['fetched_at']<FRESH_SECONDS:
        emit('geocode',source='cache',attempts=0);return cached['address']
    for attempt in range(2):
        instant=clock()
        if instant.date()!=day:raise ToolError('business_date_changed','reverse_geocode')
        if account.get('_job_deadline') and instant.timestamp()>=account['_job_deadline']:raise ToolError('reserved_slot_expired','reverse_geocode')
        timeout=getattr(school.transport,'timeout',None)
        try:
            if timeout is not None:school.transport.timeout=min(timeout,5)
            address=school.reverse_geocode(*point)
            if not valid_address(address):raise ToolError('reverse_geocode_unavailable','reverse_geocode')
        except ToolError as error:
            if not transient(error):raise
            if cached and 0<=clock().timestamp()-cached['fetched_at']<MAX_SECONDS:
                emit('geocode',source='cached_after_failure',attempts=attempt+1);return cached['address']
            if attempt:raise
        else:
            if cache:
                try:cache.save(scope,point,address,clock().timestamp())
                except (OSError,sqlite3.Error,ToolError,ValueError,TypeError):pass
            emit('geocode',source='school',attempts=attempt+1);return address.strip()
        finally:
            if timeout is not None:school.transport.timeout=timeout
        sleep(0.6)

"""Exact enrolled Origin25 metadata gate, independent of legacy Origin21."""
import hashlib
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType

from deploy.local import origin21_schema

REFERENCE_SHA256=MappingProxyType({
    22:'374e1fce6301d9478447b09c6dc95e37feca2f1c16c41a07e407ed4225d5271e',
    23:'55df069b9e3e3c304edb09896326a577ed209f898068dbeefb666164162cf6ad',
    24:'07859b45777fe45deee54a5e06a697cfc66725c16bff8afd038fa2c25d571d9f',
    25:'4430464b2c5abccbe19679dbac19b7a5d4758482677d41fcbcd3ac2bf0e4fc59',
})
_REFERENCE_DIR=Path(__file__).resolve().parent
_SNAPSHOT_SQL=("SELECT pg_catalog.jsonb_build_object('database',pg_catalog.current_database(),"
    "'ledger',coalesce((SELECT pg_catalog.jsonb_agg(version ORDER BY version) FROM contour.schema_migrations),'[]'::jsonb),"
    "'inventory',(("+origin21_schema.inventory_sql().rstrip().removesuffix(';')+")::jsonb))::text;")
_LIMIT=8*1024*1024


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate inventory key')
        result[key]=value
    return result


def _reference(stage):
    if type(stage) is not int or stage not in REFERENCE_SHA256: raise ValueError('unsupported origin25 stage')
    path=_REFERENCE_DIR/('origin25_reference_%d_enrolled.json'%stage)
    if any(part.is_symlink() for part in (path,*path.parents)): raise ValueError('reference path is symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size>_LIMIT: raise ValueError('invalid reference file')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(_LIMIT+1)
        after=os.fstat(fd)
        current=os.stat(path,follow_symlinks=False)
        identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        if len(raw)>_LIMIT or not stat.S_ISREG(current.st_mode) or identity(before)!=identity(after) or identity(before)!=identity(current): raise ValueError('reference file changed')
    finally: os.close(fd)
    if hashlib.sha256(raw).hexdigest()!=REFERENCE_SHA256[stage]: raise ValueError('origin25 reference digest mismatch')
    value=json.loads(raw,object_pairs_hook=_unique)
    if (type(value) is not dict or set(value)!={'stage','phase','inventory'} or type(value['stage']) is not int or value['stage']!=stage or value['phase']!='enrolled'):
        raise ValueError('origin25 reference identity mismatch')
    inventory=value['inventory']
    if (type(inventory) is not dict or set(inventory)!={'version','server_major','items'} or type(inventory['version']) is not int or inventory['version']!=1 or type(inventory['server_major']) is not int or inventory['server_major']!=16 or type(inventory['items']) is not list or not inventory['items']):
        raise ValueError('invalid origin25 inventory')
    if (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()!=raw: raise ValueError('noncanonical origin25 reference')
    return inventory


def _check(psql,stage):
    if not callable(psql): raise ValueError('database callback required')
    expected=_reference(stage)
    raw=psql(_SNAPSHOT_SQL)
    if type(raw) is not str or len(raw.encode('utf-8'))>_LIMIT: raise RuntimeError('origin25 inventory output invalid')
    envelope=json.loads(raw,object_pairs_hook=_unique)
    if type(envelope) is not dict or set(envelope)!={'database','ledger','inventory'}: raise ValueError('invalid origin25 snapshot')
    ledger=envelope['ledger']
    if type(ledger) is not list or any(type(version) is not int for version in ledger) or ledger!=list(range(1,stage+1)): raise ValueError('exact origin25 ledger required')
    if envelope['database']!='contour_local': raise RuntimeError('wrong local database')
    actual=envelope['inventory']
    if json.dumps(actual,sort_keys=True,separators=(',',':'))!=json.dumps(expected,sort_keys=True,separators=(',',':')): raise RuntimeError('origin25 catalog drift')


def _require_migration_stage(psql,stage):
    if type(stage) is not int or stage not in (22,23,24): raise ValueError('unsupported migration stage')
    return _check(psql,stage)


def require_ready(psql):
    """Verify exact stage 25; no earlier or later ledger grants readiness."""
    return _check(psql,25)

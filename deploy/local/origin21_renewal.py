"""Internal committed-origin renewal; immutable initial policy, C-locked CAS.

The database is the current-policy authority. No runtime or CLI is exposed.
"""
import datetime
import fcntl
import json
import os
import stat
import tempfile
import time
from typing import NamedTuple
from pathlib import Path

from deploy.local import origin21_profile, capture_renew, origin21_lease, provision
from deploy.pilot import origin_credentials

PENDING='capture/private/origin-renew.pending'
LOCK='capture/private/origin-renew.lock'
PAGE_SIZE=128
HISTORY_DEADLINE_SECONDS=60
MAX_PROPOSALS=8
MAX_PENDING=(MAX_PROPOSALS+1)*((capture_renew.MAX_ENVELOPE+2)//3)*4+4096


def _public(profile):
    key=origin_credentials._file(profile.state/'capture/private/policy.key',16384)
    public=capture_renew.crypt('public',key,b'',profile=profile.capture,scratch=tempfile.gettempdir())
    if len(public)!=44 or public[-32:]!=origin_credentials._file(profile.state/'capture/runtime/policy.raw',32):
        raise ValueError('origin signer drift')
    return public


def _valid(profile, raw, public=None):
    public=public if public is not None else _public(profile)
    result=capture_renew.checked_envelope(raw,public,profile.capture,tempfile.gettempdir())
    from deploy.pilot.origin_enrollment import _local_timestamp
    _local_timestamp(result['issued_at']); _local_timestamp(result['expires_at'])
    return result


class History(NamedTuple):
    count: int
    initial: bytes
    head: bytes
    head_policy: dict


def artifacts(profile):
    """Validate only the fixed optional renewal files; never adopt extras."""
    if profile is not origin21_profile.BOUND and profile is not origin21_profile.MANAGED_BOUND and profile is not origin21_profile.HUMAN_BOUND: raise ValueError('unsupported origin profile')
    if profile is origin21_profile.HUMAN_BOUND: origin21_profile.require_context(origin21_profile.HUMAN)
    root=profile.state; lock=root/LOCK; path=root/PENDING
    present=set()
    if os.path.lexists(lock):
        info=os.lstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
            raise ValueError('origin renewal lock drift')
        present.add(LOCK)
    if os.path.lexists(path):
        if LOCK not in present: raise ValueError('origin renewal lock missing')
        raw=origin_credentials._file(path,MAX_PENDING)
        value=capture_renew.exact_json(raw)
        if not isinstance(value,dict) or set(value)!={'version','base','proposals'} or type(value['version']) is not int or value['version']!=2 or json.dumps(value,separators=(',',':')).encode()!=raw:
            raise ValueError('origin renewal journal drift')
        base=capture_renew.decoded(value['base']); old=_valid(profile,base)
        if not isinstance(value['proposals'],list) or not 1<=len(value['proposals'])<=MAX_PROPOSALS:
            raise ValueError('origin renewal proposals drift')
        proposals=[]
        for encoded in value['proposals']:
            proposal=capture_renew.decoded(encoded); new=_valid(profile,proposal)
            if new['revision']!=old['revision']+1 or any(prior[0]==proposal for prior in proposals):
                raise ValueError('origin renewal revision drift')
            proposals.append((proposal,new))
        present.add(PENDING)
        return present,(base,old,proposals)
    return present,None


def history(profile, psql, pending=None):
    """Verify contiguous signed pages, rejecting any observed head/count race.

    Every page uses the caller-provided ephemeral, time-bounded database session
    and includes the active head and total row count from its statement snapshot.
    It never begins or commits a caller-owned transaction. A final empty probe rechecks them;
    the subsequent C-locked CAS separately rechecks the head and total under lock.
    """
    if profile is not origin21_profile.BOUND and profile is not origin21_profile.MANAGED_BOUND and profile is not origin21_profile.HUMAN_BOUND: raise ValueError('unsupported origin profile')
    if profile is origin21_profile.HUMAN_BOUND: origin21_profile.require_context(origin21_profile.HUMAN)
    t=provision.sql_quote(provision.IDS[0]); c=provision.sql_quote(profile.capture.collector)
    deadline=time.monotonic()+HISTORY_DEADLINE_SECONDS
    public=_public(profile)
    initial=origin_credentials._file(profile.state/'capture/private/observer-policy.json',capture_renew.MAX_ENVELOPE)
    count=None; cursor=0; head_bytes=None; head_policy=None; pending_base=False
    while True:
        if time.monotonic()>=deadline: raise ValueError('origin history deadline')
        # Never aggregate a >MAX_ENVELOPE row into a large transport result;
        # NULL is an invalid sentinel and is rejected below.
        limit=0 if count is not None and cursor==count else PAGE_SIZE
        raw=psql(f"""SET statement_timeout='5s'; SELECT coalesce((SELECT json_build_object(
          'enabled',a.enabled,'revoked',a.revoked_at IS NOT NULL,'head',a.active_revision::text,
          'count',(SELECT count(*)::text FROM contour.policy_revisions x WHERE x.tenant_id={t} AND x.collector_id={c}),
          'rows',coalesce((SELECT json_agg(json_build_array(r.revision::text,CASE WHEN octet_length(r.signed_envelope)<={capture_renew.MAX_ENVELOPE} THEN encode(r.signed_envelope,'hex') ELSE NULL END) ORDER BY r.revision)
          FROM (SELECT revision,signed_envelope FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c}
            AND revision>{cursor} ORDER BY revision LIMIT {limit}) r),'[]'::json))
          FROM contour.collector_authorization a WHERE a.tenant_id={t} AND a.collector_id={c}),'null'::json)::text;""")
        if time.monotonic()>=deadline: raise ValueError('origin history deadline')
        value=capture_renew.exact_json(raw)
        if value is None:
            if count is not None: raise ValueError('origin policy head changed')
            return None
        if not isinstance(value,dict) or set(value)!={'enabled','revoked','head','count','rows'} or value['enabled'] is not True or value['revoked'] is not False:
            raise ValueError('origin authorization drift')
        text=value['count']
        if not isinstance(text,str) or not text.isascii() or not text.isdigit() or text.startswith('0'):
            raise ValueError('origin policy history drift')
        current=int(text)
        if not 1<=current<=18446744073709551615 or value['head']!=str(current): raise ValueError('origin policy history drift')
        if count is None: count=current
        elif count!=current: raise ValueError('origin policy head changed')
        rows=value['rows']
        expected=min(limit,count-cursor)
        if not isinstance(rows,list) or len(rows)!=expected: raise ValueError('origin policy page drift')
        for row in rows:
            cursor+=1
            if not isinstance(row,list) or len(row)!=2 or row[0]!=str(cursor) or not isinstance(row[1],str) or len(row[1])>2*capture_renew.MAX_ENVELOPE:
                raise ValueError('origin policy history drift')
            try: envelope=bytes.fromhex(row[1])
            except ValueError: raise ValueError('origin policy history drift') from None
            policy=_valid(profile,envelope,public)
            if time.monotonic()>=deadline: raise ValueError('origin history deadline')
            if policy['revision']!=cursor: raise ValueError('origin policy history drift')
            if cursor==1 and envelope!=initial: raise ValueError('origin initial policy drift')
            if pending and cursor==pending[1]['revision']:
                pending_base=envelope==pending[0]
            head_bytes,head_policy=envelope,policy
        if limit==0: break
    if pending:
        base,old,proposals=pending
        n=old['revision']
        if not pending_base or count not in (n,n+1): raise ValueError('origin pending head drift')
        if count==n+1 and head_bytes not in [item[0] for item in proposals]: raise ValueError('origin pending head drift')
    return History(count,initial,head_bytes,head_policy)


def _locked_cas(profile, psql, base, old, proposal, new, preflight):
    return origin21_lease.locked_transaction(base,old['revision'],proposal,new['revision'],new['issued_at'],new['expires_at'],preflight,profile.capture,executor=psql)


def renew_locked(profile, psql, now=None, check_source=lambda: True):
    """Call only while the validated setup lock is held."""
    if profile is not origin21_profile.BOUND and profile is not origin21_profile.MANAGED_BOUND and profile is not origin21_profile.HUMAN_BOUND: raise ValueError('unsupported origin profile')
    if profile is origin21_profile.HUMAN_BOUND: origin21_profile.require_context(origin21_profile.HUMAN)
    now=now or datetime.datetime.now(datetime.timezone.utc)
    root=profile.state; lock=root/LOCK; path=root/PENDING
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: raise ValueError('origin renewal lock drift')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        _,pending=artifacts(profile)
        rows=history(profile,psql,pending)
        if rows is None: raise ValueError('origin observer unavailable')
        if not check_source(): raise ValueError('setup sources changed')
        if pending:
            base,old,proposals=pending
            if rows.count==old['revision']+1:
                proposal,new=next(item for item in proposals if item[0]==rows.head)
            else:
                proposal,new=proposals[-1]
                status=_locked_cas(profile,psql,base,old,proposal,new,True)
                if status=='base_expired':
                    if len(proposals)>=MAX_PROPOSALS: raise ValueError('origin renewal proposal limit')
                    key=origin_credentials._file(root/'capture/private/policy.key',16384)
                    proposal=capture_renew.signed_policy(old,key,now,profile.capture)
                    new=_valid(profile,proposal)
                    if any(item[0]==proposal for item in proposals): raise ValueError('duplicate origin renewal proposal')
                    proposals.append((proposal,new))
                    record=json.dumps(dict(version=2,base=capture_renew.encoded(base),proposals=[capture_renew.encoded(item[0]) for item in proposals]),separators=(',',':')).encode()
                    capture_renew.replace_durable(path,record)
        else:
            base,old=rows.head,rows.head_policy
            key=origin_credentials._file(root/'capture/private/policy.key',16384)
            proposal=capture_renew.signed_policy(old,key,now,profile.capture)
            new=_valid(profile,proposal)
            record=json.dumps(dict(version=2,base=capture_renew.encoded(base),proposals=[capture_renew.encoded(proposal)]),separators=(',',':')).encode()
            capture_renew.replace_durable(path,record)
        if not check_source(): raise ValueError('setup sources changed')
        _locked_cas(profile,psql,base,old,proposal,new,False)
        if not check_source(): raise ValueError('setup sources changed after commit')
        capture_renew.remove_durable(path)
        return new
    finally: os.close(fd)

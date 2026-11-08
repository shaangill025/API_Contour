"""Closed synthetic observer and origin registry operators.

The evidence digest is a local operator fixture assertion, not a platform or
Docker attestation. No runtime qualification is performed here.
"""
import datetime
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from deploy.local import origin21_profile, capture_renew, provision
from deploy.pilot import origin_credentials, origin_setup_state as journal

TENANT, PROJECT, SERVICE, ENVIRONMENT = provision.IDS
POLICY = 'capture/private/observer-policy.json'
Q = provision.sql_quote


def _scope(profile):
    c=profile.capture
    return tuple(map(Q,(TENANT,PROJECT,SERVICE,ENVIRONMENT,c.collector,c.source,c.deployment,c.instance,c.nonce)))


def _result(psql, query):
    result=psql(query)
    if result not in (journal.ABSENT,journal.EXACT,journal.DRIFT): raise RuntimeError('enrollment inspection failed')
    return result


def _local_timestamp(value):
    """The closed initial profile emits only UTC with six fractional digits.

    This intentionally accepts a strict subset of core RFC3339 timestamps.
    """
    if not isinstance(value,str) or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z',value) is None:
        raise ValueError('initial policy timestamp format')
    try: parsed=datetime.datetime.strptime(value,'%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError: raise ValueError('initial policy timestamp format') from None
    if parsed.isoformat(timespec='microseconds')+'Z' != value:
        raise ValueError('initial policy timestamp format')
    return parsed.replace(tzinfo=datetime.timezone.utc)


class Observer:
    def __init__(self, profile, psql):
        if profile is not origin21_profile.BOUND and profile is not origin21_profile.MANAGED_BOUND: raise ValueError('unsupported origin profile')
        self.profile, self.psql = profile, psql
        self.path=profile.state/POLICY

    def policy(self):
        if not os.path.lexists(self.path): return None
        raw=origin_credentials._file(self.path,capture_renew.MAX_ENVELOPE)
        key=origin_credentials._file(self.profile.state/'capture/private/policy.key',16384)
        pub=capture_renew.crypt('public',key,b'',profile=self.profile.capture,scratch=tempfile.gettempdir())
        if len(pub)!=44 or pub[-32:]!=origin_credentials._file(self.profile.state/'capture/runtime/policy.raw',32):
            raise ValueError('policy signer drift')
        data=capture_renew.checked_envelope(raw,pub,self.profile.capture,tempfile.gettempdir())
        if data['revision']!=1: raise ValueError('initial policy revision drift')
        _local_timestamp(data['issued_at']); _local_timestamp(data['expires_at'])
        return raw,data

    def _new_policy(self):
        profile=self.profile.capture
        now=datetime.datetime.now(datetime.timezone.utc)
        stamp=lambda x:x.isoformat(timespec='microseconds').replace('+00:00','Z')
        fields=dict(capture_renew.FIELDS,collector_id=profile.collector,
                    approved_names=list(profile.approved_names),approved_route_segments=list(profile.approved_route_segments))
        policy=dict(fields,revision=1,issued_at=stamp(now-datetime.timedelta(seconds=30)),expires_at=stamp(now+datetime.timedelta(minutes=14)))
        payload=json.dumps(policy,separators=(',',':')).encode()
        key=origin_credentials._file(self.profile.state/'capture/private/policy.key',16384)
        signature=capture_renew.crypt('sign',key,capture_renew.DOMAIN+payload,profile=profile,scratch=tempfile.gettempdir())
        if len(signature)!=64: raise ValueError('policy signature invalid')
        raw=json.dumps(dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=capture_renew.encoded(payload),signature_base64url=capture_renew.encoded(signature)),separators=(',',':')).encode()
        origin_credentials._write(self.path,raw)
        return self.policy()

    def inspect(self):
        try: policy=self.policy()
        except (OSError,ValueError,RuntimeError): return journal.DRIFT
        t,p,s,e,c,src,d,i,n=_scope(self.profile)
        envelope=policy[0].hex() if policy else ''
        status = _result(self.psql,f"""SELECT CASE WHEN
          (SELECT count(*) FROM contour.collectors WHERE tenant_id={t} AND collector_id={c})=0 AND
          (SELECT count(*) FROM contour.deployments WHERE tenant_id={t} AND deployment_id={d})=0 AND
          (SELECT count(*) FROM contour.workload_instances WHERE tenant_id={t} AND instance_id={i})=0 AND
          (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND (collector_id={c} OR source_id={src}))=0
          THEN 'ABSENT'
        WHEN {('true' if policy else 'false')} AND
          (SELECT count(*) FROM contour.collectors WHERE tenant_id={t} AND collector_id={c})=1 AND
          (SELECT count(*) FROM contour.deployments WHERE tenant_id={t} AND deployment_id={d} AND project_id={p} AND service_id={s} AND environment_id={e})=1 AND
          (SELECT count(*) FROM contour.workload_instances WHERE tenant_id={t} AND deployment_id={d})=1 AND
          (SELECT count(*) FROM contour.workload_instances WHERE tenant_id={t} AND instance_id={i} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d})=1 AND
          (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c})=1 AND
          (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d} AND source_nonce={n} AND binding_mode='instance')=1 AND
          (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c})=1 AND
          (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d})=1 AND
          (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c})=1 AND
          (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d} AND instance_id={i})=1 AND
          (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c})=1 AND
          (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND technique='gateway' AND parser_profiles=ARRAY['http_json_v1'])=1 AND
          (SELECT count(*) FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c})>=1 AND
          (SELECT count(*) FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c} AND revision=1 AND signed_envelope=decode('{envelope}','hex'))=1 AND
          (SELECT count(*) FROM contour.collector_authorization WHERE tenant_id={t} AND collector_id={c} AND enabled AND revoked_at IS NULL AND active_revision>=1)=1
        THEN 'EXACT' ELSE 'DRIFT' END;""")
        if status == journal.EXACT:
            from deploy.local import origin21_renewal as origin_renewal
            try:
                _,pending=origin_renewal.artifacts(self.profile)
                if origin_renewal.history(self.profile,self.psql,pending) is None: return journal.DRIFT
            except (OSError,ValueError,RuntimeError): return journal.DRIFT
        return status

    def apply(self):
        policy=self.policy() or self._new_policy()
        raw,data=policy
        issued=datetime.datetime.fromisoformat(data['issued_at'].replace('Z','+00:00'))
        expires=datetime.datetime.fromisoformat(data['expires_at'].replace('Z','+00:00'))
        now=datetime.datetime.now(datetime.timezone.utc)
        if not issued<=now<expires: raise RuntimeError('initial observer policy not current; pending state retained')
        t,p,s,e,c,src,d,i,n=_scope(self.profile)
        # Legacy observer bootstrap uses only the existing public collector lock.
        # It never requests the origin Q gate after taking C.
        self.psql(f"""BEGIN; SELECT set_config('apicontour.tenant_id',{t},true); SET LOCAL ROLE contour_admin;
        SELECT contour.lock_collector({t},{c});
        DO $$ BEGIN IF pg_catalog.current_database()<>'contour_local' OR pg_catalog.clock_timestamp() < {Q(data['issued_at'])}::timestamptz OR pg_catalog.clock_timestamp() >= {Q(data['expires_at'])}::timestamptz
          OR EXISTS (SELECT 1 FROM contour.collectors WHERE tenant_id={t} AND collector_id={c}) THEN RAISE EXCEPTION 'observer state unavailable'; END IF; END $$;
        INSERT INTO contour.deployments VALUES ({t},{d},{p},{s},{e});
        INSERT INTO contour.collectors VALUES ({t},{c});
        INSERT INTO contour.workload_assignments VALUES ({t},{c},{p},{s},{e},{d});
        INSERT INTO contour.workload_instances VALUES ({t},{p},{s},{e},{d},{i});
        SELECT contour.register_instance_source({t},{src},{c},{p},{s},{e},{d},{n},{i});
        INSERT INTO contour.source_authorization VALUES ({t},{src},{c},'gateway',ARRAY['http_json_v1']);
        INSERT INTO contour.policy_revisions VALUES ({t},{c},1,decode('{raw.hex()}','hex'));
        UPDATE contour.collector_authorization SET active_revision=1,enabled=true WHERE tenant_id={t} AND collector_id={c}; COMMIT;""")


class Target:
    def __init__(self, profile, psql, slot):
        if (profile is not origin21_profile.BOUND and profile is not origin21_profile.MANAGED_BOUND) or not any(slot is item for item in profile.origins): raise ValueError('unsupported origin slot')
        self.profile,self.psql,self.slot=profile,psql,slot
    def inspect(self):
        t,p,s,e,*_=_scope(self.profile);d,i=map(Q,(self.slot.deployment,self.slot.instance))
        return _result(self.psql,f"""SELECT CASE WHEN
          (SELECT count(*) FROM contour.deployments WHERE tenant_id={t} AND deployment_id={d})=0 AND
          (SELECT count(*) FROM contour.workload_instances WHERE tenant_id={t} AND instance_id={i})=0 THEN 'ABSENT'
        WHEN (SELECT count(*) FROM contour.deployments WHERE tenant_id={t} AND deployment_id={d} AND project_id={p} AND service_id={s} AND environment_id={e})=1 AND
          (SELECT count(*) FROM contour.workload_instances WHERE tenant_id={t} AND deployment_id={d})=1 AND
          (SELECT count(*) FROM contour.workload_instances WHERE tenant_id={t} AND instance_id={i} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d})=1
        THEN 'EXACT' ELSE 'DRIFT' END;""")
    def apply(self):
        t,p,s,e,*_=_scope(self.profile);d,i=map(Q,(self.slot.deployment,self.slot.instance))
        self.psql(f"""BEGIN; SELECT set_config('apicontour.tenant_id',{t},true); SET LOCAL ROLE contour_admin;
        DO $$ BEGIN IF pg_catalog.current_database()<>'contour_local' THEN RAISE EXCEPTION 'wrong database'; END IF; END $$;
        INSERT INTO contour.deployments VALUES ({t},{d},{p},{s},{e});
        INSERT INTO contour.workload_instances VALUES ({t},{p},{s},{e},{d},{i}); COMMIT;""")


class Fact:
    def __init__(self, profile, psql, slot, kind, evidence):
        if (profile is not origin21_profile.BOUND and profile is not origin21_profile.MANAGED_BOUND) or not any(slot is item for item in profile.origins): raise ValueError('unsupported origin slot')
        if kind not in ('lifecycle','credential','grant') or not callable(evidence): raise ValueError('unknown origin fact')
        self.profile,self.psql,self.slot,self.kind,self.evidence=profile,psql,slot,kind,evidence
    def _leaf(self):
        index=next(i for i,item in enumerate(self.profile.origins,1) if item is self.slot)
        root=self.profile.state
        origin_credentials._dir(root); origin_credentials._dir(root/('replica'+str(index)))
        return hashlib.sha256(origin_credentials._file(root/('replica'+str(index))/'client.crt.der')).hexdigest()
    def inspect(self):
        t,p,s,e,c,src,d,*_=_scope(self.profile); slot=self.slot
        lifecycle,cred,grant,target,instance=map(Q,(slot.lifecycle,slot.credential,slot.grant,slot.deployment,slot.instance))
        leaf=self._leaf(); ev=self.evidence(slot)
        specs={
          'lifecycle':('origin_lifecycles','lifecycle_id',lifecycle,f"project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={target} AND instance_id={instance} AND platform_kind='trusted_platform_v1' AND platform_evidence_sha256=decode('{ev}','hex') AND fact_epoch>0"),
          'credential':('origin_credentials','credential_id',cred,f"lifecycle_id={lifecycle} AND leaf_sha256=decode('{leaf}','hex') AND fact_epoch>0"),
          'grant':('origin_observer_grants','grant_id',grant,f"lifecycle_id={lifecycle} AND source_id={src} AND collector_id={c} AND project_id={p} AND service_id={s} AND environment_id={e} AND deployment_id={d} AND fact_epoch>0")}
        table,col,idvalue,condition=specs[self.kind]
        extra={'lifecycle':f"instance_id={instance}",'credential':f"lifecycle_id={lifecycle} OR leaf_sha256=decode('{leaf}','hex')",'grant':f"lifecycle_id={lifecycle}"}[self.kind]
        # Terminal events of any type on this lifecycle invalidate every phase.
        terminal=f"""EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id={t} AND
           (z.lifecycle_id={lifecycle} OR z.credential_id={cred} OR z.grant_id={grant}))"""
        if self.kind=='credential':
            collision=f"(SELECT count(*) FROM contour.origin_credentials WHERE leaf_sha256=decode('{leaf}','hex'))>1 OR EXISTS (SELECT 1 FROM contour.origin_credentials WHERE leaf_sha256=decode('{leaf}','hex') AND (tenant_id<>{t} OR credential_id<>{cred}))"
        elif self.kind=='grant':
            allowed=','.join(Q(origin.grant) for origin in self.profile.origins)
            collision=f"EXISTS (SELECT 1 FROM contour.origin_observer_grants WHERE tenant_id={t} AND collector_id={c} AND grant_id NOT IN ({allowed}))"
        else:
            collision='false'
        return _result(self.psql,f"""SELECT CASE WHEN {terminal} OR {collision} THEN 'DRIFT'
          WHEN (SELECT count(*) FROM contour.{table} WHERE tenant_id={t} AND ({extra} OR {col}={idvalue}))=0 THEN 'ABSENT'
          WHEN (SELECT count(*) FROM contour.{table} WHERE tenant_id={t} AND ({extra} OR {col}={idvalue}))=1 AND
            (SELECT count(*) FROM contour.{table} WHERE tenant_id={t} AND {col}={idvalue} AND {condition})=1 THEN 'EXACT'
          ELSE 'DRIFT' END;""")
    def apply(self):
        t,p,s,e,c,src,d,*_=_scope(self.profile);slot=self.slot
        l,cred,g,target,i=map(Q,(slot.lifecycle,slot.credential,slot.grant,slot.deployment,slot.instance))
        call={'lifecycle':f"contour.enroll_origin({t},{l},{p},{s},{e},{target},{i},'trusted_platform_v1',decode('{self.evidence(slot)}','hex'))",
              'credential':f"contour.enroll_origin_credential({t},{cred},{l},decode('{self._leaf()}','hex'))",
              'grant':f"contour.grant_origin_observer({t},{g},{l},{src},{c},{p},{s},{e},{d})"}[self.kind]
        self.psql(f"BEGIN; DO $$ BEGIN IF pg_catalog.current_database()<>'contour_local' THEN RAISE EXCEPTION 'wrong database'; END IF; END $$; SELECT set_config('apicontour.tenant_id',{t},true); SET LOCAL ROLE contour_admin; SELECT {call}; COMMIT;")

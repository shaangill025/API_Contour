"""Closed output and owner-bound SQL20 receipt checks for synthetic HTTP qualification."""
import hashlib
import json
import re
import uuid

CHECKS = ('receiver-http-event', 'receiver-http-cross-route', 'receiver-http-mtls',
          'receiver-http-framing', 'receiver-http-connect-recovery', 'receiver-http-owner-readback')


def parse_result(returncode, stdout, stderr):
    if returncode == 0 and not stderr:
        match = re.fullmatch(rb'PASS receiver-http-probe ([0-9a-f]{64}) ([0-9a-f]{64})\n', stdout)
        if match: return ('passed', match.group(1).decode('ascii'), match.group(2).decode('ascii'))
    if returncode != 0 and stdout == b'':
        match = re.fullmatch(rb'RED receiver-http-pool-recovery ([0-9a-f]{64})\nFAIL receiver-http-probe\n', stderr)
        if match: return ('pool-recovery-red', None, match.group(1).decode('ascii'))
    raise RuntimeError('HTTP probe failed')


def verify_event_receipt(execute, payload, returned):
    """Reconstruct every returned HTTP event field from the owner-selected SQL20 row."""
    if type(returned) is not str or not re.fullmatch(r'[0-9a-f]{64}',returned): raise ValueError('event receipt digest')
    batch_raw=payload['batch'].encode('ascii'); batch=json.loads(batch_raw)
    tenant=payload['ids'][0]; runtime=payload['ids'][1]; batch_id=batch['batch_id']
    for value in (tenant,runtime,batch_id):
        if type(value) is not str or str(uuid.UUID(value))!=value: raise ValueError('event identity')
    if batch.get('tenant_id')!=tenant or batch.get('runtime_id')!=runtime or batch.get('session_epoch')!=1: raise ValueError('event scope')
    digest=hashlib.sha256(b'apicontour/causal-events/1\n'+batch_raw).hexdigest()
    # RFC3339 formatter emits UTC with no fractional component when it is zero.
    stamp="to_char(accepted_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN rtrim(to_char(accepted_at AT TIME ZONE 'UTC','US'),'0')='' THEN '' ELSE '.' || rtrim(to_char(accepted_at AT TIME ZONE 'UTC','US'),'0') END || 'Z'"
    fields="'accepted_at',"+stamp+",'batch_digest',encode(batch_digest,'hex'),'batch_id',batch_id::text,'runtime_id',runtime_id::text,'session_epoch',session_epoch,'status','duplicate'"
    def receipt_hash(receipt):
        return "encode(sha256(convert_to(contour.causal_json_canonical(jsonb_build_object("+fields+",'receipt_id',"+receipt+")),'UTF8')),'hex')"
    expected=receipt_hash('receipt_id::text')
    substituted=receipt_hash("CASE WHEN receipt_id='00000000-0000-4000-8000-000000000001'::uuid THEN '00000000-0000-4000-8000-000000000002' ELSE '00000000-0000-4000-8000-000000000001' END")
    sql=("SELECT (count(*)=1 AND bool_and(canonical_batch=decode('%s','hex') AND batch_digest=decode('%s','hex') AND event_count=1 AND receipt_digest=contour.causal_receipt_digest(tenant_id,runtime_id,session_epoch,batch_id,receipt_id,accepted_at,batch_digest,event_count) AND %s='%s' AND %s<>'%s'))::text FROM contour.causal_inbox_batches WHERE tenant_id='%s' AND runtime_id='%s' AND session_epoch=1 AND batch_id='%s';" % (batch_raw.hex(),digest,expected,returned,substituted,returned,tenant,runtime,batch_id))
    if execute(sql)!='true': raise RuntimeError('HTTP event receipt readback')

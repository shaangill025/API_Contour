"""Pure, bounded synthetic SQL29 fact construction; conveys no authority."""
import json
import re
import uuid

_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def canonical_fact(*, tenant, gateway, gateway_generation, runtime, epoch,
                   delivery_handle, local_root, binding_digest):
    """Construct a closed canonical receiver fact for an issued session's scope."""
    for value in (tenant, gateway, runtime):
        if type(value) is not str:
            raise ValueError('fact identity')
        try:
            parsed = uuid.UUID(value)
        except ValueError:
            raise ValueError('fact identity') from None
        if str(parsed) != value:
            raise ValueError('fact identity')
    for value in (gateway_generation, delivery_handle, local_root):
        if type(value) is not str or not _HEX32.fullmatch(value):
            raise ValueError('fact identifier')
    if type(binding_digest) is not str or not _HEX64.fullmatch(binding_digest):
        raise ValueError('fact digest')
    if type(epoch) is not str or not re.fullmatch(r'[1-9][0-9]{0,19}', epoch) or int(epoch) > 18446744073709551615:
        raise ValueError('fact epoch')
    fact = {'wire_version': 1, 'tenant_id': tenant, 'gateway_id': gateway,
            'gateway_generation': gateway_generation, 'delivery_handle': delivery_handle,
            'receiver_runtime_id': runtime, 'receiver_session_epoch': epoch,
            'local_root': local_root, 'binding_digest': binding_digest}
    return json.dumps(fact, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

CHECKS = ('receiver-fact-tls-first', 'receiver-fact-pre-observer-retry-denied',
          'receiver-fact-selectors', 'receiver-fact-leaf', 'receiver-fact-scope',
          'receiver-fact-role', 'receiver-fact-deadline', 'receiver-fact-revoked',
          'receiver-fact-owner-readback')


def require_matching_receipt_digest(returned, stored):
    """Bind a privately returned receipt digest to the exact owner-selected row."""
    if (type(returned) is not str or type(stored) is not str
        or not _HEX64.fullmatch(returned) or not _HEX64.fullmatch(stored)
        or returned != stored): raise ValueError('fact receipt mismatch')


def run(*, execute, openssl, write_private, private_dir, probe_call, issuer_payload, password):
    """Fixed synthetic TLS and SQL29 exercise. Callbacks are private qualifier internals."""
    import datetime
    import hashlib
    from pathlib import Path

    if not re.fullmatch(r'[0-9a-f]{64}', password): raise ValueError('fact password')
    if type(issuer_payload) is not dict or issuer_payload.get('mode') != 'positive': raise ValueError('fact issuer')
    i = issuer_payload.get('ids')
    if i != ['f0000000-0000-4000-8000-000000000001','fc000000-0000-4000-8000-000000000010','f6000000-0000-4000-8000-000000000003','f7000000-0000-4000-8000-000000000010','f1000000-0000-4000-8000-000000000001','f2000000-0000-4000-8000-000000000001','f3000000-0000-4000-8000-000000000001','f4000000-0000-4000-8000-000000000001','f5000000-0000-4000-8000-000000000010','f9000000-0000-4000-8000-000000000010'] or issuer_payload.get('epoch') != '1' or issuer_payload.get('user') != 'causal_issuer_login': raise ValueError('fact issuer')
    directory = Path(private_dir)
    def path(name): return str(directory / ('fact-' + name))
    def put(name, data):
        if not isinstance(data, bytes) or not data or len(data) > 65536: raise ValueError('fact material')
        write_private('fact-' + name, data)
    def command(args):
        result = openssl(args)
        if not isinstance(result, bytes) or not result or len(result) > 65536: raise ValueError('fact material')
        return result
    for name in ('ca', 'server', 'client', 'other'):
        put(name + '.key', command(['genpkey', '-algorithm', 'ED25519']))
    put('ca.pem', command(['req', '-new', '-x509', '-key', path('ca.key'), '-subj', '/CN=fixture-ca', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']))
    put('server.ext', b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
    put('client.ext', b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
    for serial, name in enumerate(('server', 'client', 'other'), 1):
        put(name + '.csr', command(['req', '-new', '-key', path(name + '.key'), '-subj', '/CN=fixture-' + name]))
        put(name + '.pem', command(['x509', '-req', '-in', path(name + '.csr'), '-CA', path('ca.pem'), '-CAkey', path('ca.key'), '-set_serial', str(serial), '-days', '1', '-extfile', path('server.ext' if name == 'server' else 'client.ext')]))
    def der(name): return command(['x509', '-in', path(name + '.pem'), '-outform', 'DER'])
    def key_der(name): return command(['pkey', '-in', path(name + '.key'), '-outform', 'DER'])
    ca, server, client, other = (der(x) for x in ('ca', 'server', 'client', 'other'))
    server_key, client_key, other_key = (key_der(x) for x in ('server', 'client', 'other'))
    leaf = hashlib.sha256(client).hexdigest()
    backend = hashlib.sha256(server).hexdigest()
    if len({leaf, backend, hashlib.sha256(other).hexdigest(), 'ed' * 32, 'e9' * 32}) != 5: raise ValueError('fact leaf collision')
    # Separate gateway lifecycle and policy; these are synthetic public enrollment inputs.
    t, _, _, _, p, service, env, deployment, _, _ = i
    gc='f6000000-0000-4000-8000-000000000021'; gs='f7000000-0000-4000-8000-000000000021'
    gi='f5000000-0000-4000-8000-000000000021'; gl='f9000000-0000-4000-8000-000000000021'; gid='fe000000-0000-4000-8000-000000000021'
    execute("INSERT INTO contour.workload_instances VALUES ('%s','%s','%s','%s','%s','%s');"%(t,p,service,env,deployment,gi))
    execute("BEGIN; SELECT set_config('apicontour.tenant_id','%s',true); SET LOCAL ROLE contour_admin; SELECT contour.lock_collector('%s','%s'); INSERT INTO contour.collectors VALUES ('%s','%s'); INSERT INTO contour.workload_assignments VALUES ('%s','%s','%s','%s','%s','%s'); SELECT contour.register_instance_source('%s','%s','%s','%s','%s','%s','%s','f8000000-0000-4000-8000-000000000021','%s'); INSERT INTO contour.source_authorization VALUES ('%s','%s','%s','gateway',ARRAY['http_json_v1']); INSERT INTO contour.policy_revisions VALUES ('%s','%s',1,decode('01','hex')); UPDATE contour.collector_authorization SET active_revision=1,enabled=true WHERE tenant_id='%s' AND collector_id='%s'; COMMIT;"%(t,t,gc,t,gc,t,gc,p,service,env,deployment,t,gs,gc,p,service,env,deployment,gi,t,gs,gc,t,gc,t,gc))
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SET ROLE contour_admin; SELECT contour.enroll_origin('%s','%s','%s','%s','%s','%s','%s','trusted_platform_v1',decode(repeat('cb',32),'hex')); RESET ROLE;"%(t,t,gl,p,service,env,deployment,gi))
    now=datetime.datetime.now(datetime.timezone.utc); stamp=lambda x:x.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    start=stamp(now-datetime.timedelta(minutes=1)); end=stamp(now+datetime.timedelta(minutes=8))
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SET ROLE contour_causal_evidence_provisioner; SELECT * FROM contour.enroll_causal_gateway(ROW('%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,'%s'::uuid,decode(repeat('c8',32),'hex'),decode(repeat('c9',32),'hex'),decode(repeat('ca',32),'hex'),1,decode('01','hex'),'%s'::timestamptz,'%s'::timestamptz,300000000)::contour.gateway_enrollment_claim); RESET ROLE;"%(t,t,gid,gc,gs,p,service,env,deployment,gi,start,end))
    gateway=execute("SELECT generation FROM contour.causal_gateway_enrollments WHERE tenant_id='%s' AND gateway_id='%s';"%(t,gid))
    if not _HEX32.fullmatch(gateway): raise ValueError('fact gateway')
    sql=("SELECT set_config('apicontour.tenant_id','%s',false); SET ROLE contour_causal_evidence_provisioner; "
         "SELECT * FROM contour.enroll_causal_receiver(ROW('%s'::uuid,'%s'::uuid,1,'%s'::uuid,'%s'::uuid,"
         "'fa000000-0000-4000-8000-000000000010'::uuid,decode(repeat('e9',32),'hex'),decode(repeat('ed',32),'hex'),"
         "decode('%s','hex'),decode('%s','hex'),decode(repeat('d8',32),'hex'),'%s'::timestamptz,'%s'::timestamptz,"
         "'%s'::timestamptz,'%s'::timestamptz,60000000)::contour.receiver_enrollment_claim); RESET ROLE;"%(t,t,i[1],i[8],i[9],backend,leaf,start,end,start,end))
    execute(sql)
    selected=json.loads(execute("SELECT json_build_object('generation',enrollment_generation,'credential',evidence_credential_id::text)::text FROM contour.causal_receiver_enrollments WHERE tenant_id='%s' AND runtime_id='%s' AND session_epoch=1;"%(t,i[1])).splitlines()[-1])
    if type(selected) is not dict or set(selected)!={'generation','credential'} or not _HEX32.fullmatch(selected['generation']): raise ValueError('fact enrollment')
    try:
        if str(uuid.UUID(selected['credential'])) != selected['credential']: raise ValueError('fact credential')
    except (ValueError,TypeError,AttributeError): raise ValueError('fact credential') from None
    fact=canonical_fact(tenant=t,gateway=gid,gateway_generation=gateway,runtime=i[1],epoch='1',delivery_handle='a1'*16,local_root='a2'*16,binding_digest='a3'*32)
    execute("CREATE ROLE causal_receiver_writer_login LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD '%s'; GRANT contour_causal_receiver_writer TO causal_receiver_writer_login; GRANT CONNECT ON DATABASE contour_local TO causal_receiver_writer_login;"%password)
    base={k:issuer_payload[k] for k in ('ca_pem','epoch','grant','grant_public','ids','nonce','peer','policy','policy_public','port')}
    base.update(issuer_password=issuer_payload['password'],writer_password=password,writer_user='causal_receiver_writer_login',fact=fact.decode(),server_cert_der=server.hex(),server_key_der=server_key.hex(),client_cert_der=client.hex(),client_key_der=client_key.hex(),client_ca_der=ca.hex(),**selected)
    def call(mode, **overrides):
        return probe_call(json.dumps(dict(base,mode=mode,**overrides),sort_keys=True,separators=(',',':')).encode())
    def usage():
        value=execute("SELECT coalesce((SELECT used_bytes::text FROM contour.origin_logical_usage WHERE tenant_id='%s'),'0');"%t)
        if not value.isdigit(): raise ValueError('fact usage')
        return int(value)
    baseline=usage()
    call('wrong-generation',generation=('e' if selected['generation']=='f'*32 else 'f')*32)
    call('wrong-credential',credential='fa000000-0000-4000-8000-000000000099')
    call('wrong-leaf',client_cert_der=other.hex(),client_key_der=other_key.hex())
    bad=json.loads(fact);bad['receiver_runtime_id']='fc000000-0000-4000-8000-000000000099'
    call('wrong-scope',fact=json.dumps(bad,sort_keys=True,separators=(',',':')))
    call('wrong-role',writer_user='causal_issuer_login',writer_password=issuer_payload['password'])
    call('deadline')
    if usage()!=baseline: raise RuntimeError('fact negative quota')
    returned_receipt_digest=call('positive')
    after=usage()
    call('retry-denied')
    if usage()!=after: raise RuntimeError('fact retry quota')
    digest=hashlib.sha256(b'apicontour/causal-evidence/receiver/1\n'+fact).hexdigest()
    query=("SELECT (count(*)=1 AND bool_and(i.canonical_fact=decode('%s','hex') AND i.fact_digest=decode('%s','hex') "
      "AND i.receipt=convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','receiver','fact_digest','%s','receipt_id',i.receipt_id,'status','stored')),'UTF8') "
      "AND a.evidence_peer_leaf=decode('%s','hex') AND a.enrollment_generation='%s' AND a.evidence_credential_id='%s'::uuid "
      "AND i.charged_bytes+a.charged_bytes+z.charged_bytes=%d))::text FROM contour.causal_receiver_inbox i "
      "JOIN contour.causal_receiver_assignments a USING(tenant_id,gateway_id,gateway_generation,delivery_handle) "
      "JOIN contour.causal_receiver_tombstones z USING(tenant_id,gateway_id,gateway_generation,delivery_handle) "
      "WHERE i.tenant_id='%s' AND i.gateway_id='%s' AND i.gateway_generation='%s' AND i.delivery_handle='%s';"%(fact.hex(),digest,digest,leaf,selected['generation'],selected['credential'],after-baseline,t,gid,gateway,'a1'*16))
    if execute(query)!='true': raise RuntimeError('fact readback')
    stored_receipt_digest=execute("SELECT encode(sha256(receipt),'hex') FROM contour.causal_receiver_inbox WHERE tenant_id='%s' AND gateway_id='%s' AND gateway_generation='%s' AND delivery_handle='%s';"%(t,gid,gateway,'a1'*16))
    require_matching_receipt_digest(returned_receipt_digest,stored_receipt_digest)
    execute("SELECT set_config('apicontour.tenant_id','%s',false); SET ROLE contour_causal_evidence_provisioner; SELECT contour.close_causal_receiver('%s','%s',1,'%s','operator_revoked'); RESET ROLE;"%(t,t,i[1],selected['generation']))
    call('revoked')
    if usage()!=after: raise RuntimeError('fact revoked quota')
    return CHECKS

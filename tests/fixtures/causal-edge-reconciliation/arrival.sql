-- SQL-only arrival cases. Origin REQUESTs are independently admitted through
-- the existing ingress/catalog fixture; marker/peer claims are synthetic and
-- do not claim signature verification or TLS possession.
CREATE TEMP TABLE arrival_inputs (
 n integer PRIMARY KEY, tenant uuid NOT NULL, gateway uuid NOT NULL, generation text NOT NULL, handle text NOT NULL,
 producer_runtime uuid NOT NULL, producer_epoch numeric NOT NULL, producer_peer bytea NOT NULL, producer_grant bytea NOT NULL, producer_body bytea NOT NULL,
 receiver_runtime uuid NOT NULL, receiver_epoch numeric NOT NULL, receiver_peer bytea NOT NULL, receiver_grant bytea NOT NULL, receiver_body bytea NOT NULL,
 observer_raw bytea NOT NULL, observer_proof contour.verified_observer_claim NOT NULL,
 receiver_raw bytea NOT NULL, receiver_proof contour.verified_receiver_claim NOT NULL
);
GRANT SELECT ON observer_seed,receiver_claim29,receiver_enrollment29,receiver_product29 TO contour_owner;
GRANT INSERT ON arrival_inputs TO contour_owner;
SET ROLE contour_owner;
DO $$ DECLARE s record; c record; enrollment record; i integer; rec uuid; attempt text; marker_root text; activity text; local_root text; h text; signed_marker text; marker_hash bytea; observer jsonb; binding jsonb; receiver jsonb; pbatch jsonb; rbatch jsonb; BEGIN
 SELECT * INTO STRICT s FROM observer_seed;
 SELECT * INTO STRICT c FROM receiver_claim29;
 SELECT * INTO STRICT enrollment FROM receiver_enrollment29;
 FOR i IN 1..24 LOOP
  rec:=('31000000-0000-4000-8000-'||lpad(to_hex(511+i),12,'0'))::uuid;
  IF NOT EXISTS (SELECT 1 FROM contour.origin_proofs p JOIN contour.observation_windows w USING(tenant_id,collector_id,batch_id,record_id)
   WHERE p.tenant_id=((s.proof).producer_claim).tenant_id AND p.collector_id=(convert_from(s.raw,'UTF8')::jsonb->'binding'->>'collector_id')::uuid
    AND p.batch_id='31000000-0000-4000-8000-000000000100'::uuid AND p.record_id=rec)
  THEN RAISE EXCEPTION 'arrival committed request proof unavailable'; END IF;
  attempt:=lpad(to_hex(4096+i),32,'0'); marker_root:=lpad(to_hex(8192+i),32,'0'); activity:=lpad(to_hex(12288+i),32,'0');
  local_root:=lpad(to_hex(16384+i),32,'0'); h:=lpad(to_hex(20480+i),32,'0');
  signed_marker:='ac1.fixture.arrival-'||i::text;
  marker_hash:=sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||signed_marker,'UTF8'));
  observer:=convert_from(s.raw,'UTF8')::jsonb;
  binding:=observer->'binding';
  binding:=jsonb_set(binding,'{record_id}',to_jsonb(rec::text));
  binding:=jsonb_set(binding,'{producer_attempt_id}',to_jsonb(attempt));
  binding:=jsonb_set(binding,'{marker_digest}',to_jsonb(encode(marker_hash,'hex')));
  binding:=jsonb_set(binding,'{receiver_runtime_id}',to_jsonb((c.claim).runtime_id::text));
  binding:=jsonb_set(binding,'{receiver_session_epoch}',to_jsonb(c.epoch::text));
  binding:=jsonb_set(binding,'{delivery_handle}',to_jsonb(h));
  binding:=jsonb_set(binding,'{retry_of}','null'::jsonb);
  observer:=jsonb_set(jsonb_set(jsonb_set(observer,'{binding}',binding),'{batch_id}',to_jsonb('31000000-0000-4000-8000-000000000100'::text)),'{signed_marker}',to_jsonb(signed_marker));
  receiver:=jsonb_build_object('wire_version',1,'tenant_id',binding->>'tenant_id','gateway_id',binding->>'gateway_id','gateway_generation',binding->>'gateway_generation',
   'delivery_handle',h,'receiver_runtime_id',(c.claim).runtime_id::text,'receiver_session_epoch',c.epoch::text,'local_root',local_root,
   'binding_digest',encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||convert_to(contour.causal_json_canonical(binding),'UTF8')),'hex'));
  pbatch:=jsonb_build_object('batch_id',('31000000-0000-4000-8001-'||lpad(to_hex(i),12,'0'))::uuid,'tenant_id',((s.proof).producer_claim).tenant_id,
   'runtime_id',((s.proof).producer_claim).runtime_id,'session_epoch',(s.proof).producer_epoch,'wire_version',1,'first_seq',100+i,'last_seq',100+i,
   'events',jsonb_build_array(jsonb_build_object('event_id',lpad(to_hex(24576+i),32,'0'),'kind','attempt','seq',100+i,'root',marker_root,'activity',activity,'attempt',attempt,'marker_digest',encode(marker_hash,'hex'))));
  rbatch:=jsonb_build_object('batch_id',('31000000-0000-4000-8002-'||lpad(to_hex(i),12,'0'))::uuid,'tenant_id',(c.claim).tenant_id,
   'runtime_id',(c.claim).runtime_id,'session_epoch',c.epoch,'wire_version',1,'first_seq',100+i,'last_seq',100+i,
   'events',jsonb_build_array(jsonb_build_object('event_id',lpad(to_hex(28672+i),32,'0'),'kind','root','seq',100+i,'root',local_root)));
  INSERT INTO arrival_inputs VALUES(i,((s.proof).producer_claim).tenant_id,(binding->>'gateway_id')::uuid,binding->>'gateway_generation',h,
   ((s.proof).producer_claim).runtime_id,(s.proof).producer_epoch,((s.proof).producer_claim).export_leaf,((s.proof).producer_claim).grant_digest,convert_to(contour.causal_json_canonical(pbatch),'UTF8'),
   (c.claim).runtime_id,c.epoch,(c.claim).export_leaf,(c.claim).grant_digest,convert_to(contour.causal_json_canonical(rbatch),'UTF8'),
   convert_to(contour.causal_json_canonical(observer),'UTF8'),ROW((s.proof).gateway_peer_leaf,(s.proof).producer_claim,(s.proof).producer_epoch,(s.proof).marker_public,(s.proof).marker_generation,marker_root,activity,attempt,marker_hash)::contour.verified_observer_claim,
   convert_to(contour.causal_json_canonical(receiver),'UTF8'),ROW(decode(repeat('d9',32),'hex'),enrollment.generation,enrollment.credential_id)::contour.verified_receiver_claim);
 END LOOP;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM arrival_inputs)<>24 OR
    (SELECT count(DISTINCT p.proof_id) FROM arrival_inputs i JOIN contour.origin_proofs p
     ON (p.tenant_id,p.collector_id,p.batch_id,p.record_id)=(i.tenant,(convert_from(i.observer_raw,'UTF8')::jsonb->'binding'->>'collector_id')::uuid,
      '31000000-0000-4000-8000-000000000100'::uuid,(convert_from(i.observer_raw,'UTF8')::jsonb->'binding'->>'record_id')::uuid))<>24
 THEN RAISE EXCEPTION 'arrival proof identities not distinct'; END IF;
END $$;
GRANT SELECT ON arrival_inputs TO contour_causal_inbox_writer,contour_causal_observer_writer,contour_causal_receiver_writer,contour_causal_reconciler;
CREATE TEMP TABLE arrival_receipts(n integer,kind text,ok boolean NOT NULL);
GRANT INSERT ON arrival_receipts TO contour_causal_inbox_writer,contour_causal_observer_writer,contour_causal_receiver_writer;
CREATE TEMP TABLE arrival_checks(n integer,step integer,before_used bigint,edge bytea,PRIMARY KEY(n,step));
GRANT SELECT,UPDATE ON arrival_checks TO contour_causal_reconciler;
GRANT SELECT ON arrival_inputs,arrival_checks TO contour_owner;
-- Case readback checks expectations independently; it never writes protected
-- rows. The three deliberately wrong arguments below exercise the guard.
GRANT SELECT ON arrival_inputs,arrival_checks TO contour_owner;
CREATE FUNCTION pg_temp.arrival_edge_matches(case_no integer, expected_proof uuid, expected_root text, expected_delta bigint)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE i arrival_inputs; e contour.causal_resolved_edges; p contour.origin_proofs;
 pb contour.causal_runtime_bindings; rb contour.causal_runtime_bindings; marker contour.causal_marker_bindings;
 gateway contour.causal_gateway_enrollments; pe contour.causal_inbox_events; re contour.causal_inbox_events;
 pbatch contour.causal_inbox_batches; rbatch contour.causal_inbox_batches;
 oj jsonb; binding jsonb; rj jsonb; pj jsonb; rbatch_json jsonb; expected_edge bytea; expected_provenance bytea; stamp text; delta bigint;
BEGIN
 SELECT * INTO STRICT i FROM arrival_inputs WHERE n=case_no;
 oj:=convert_from(i.observer_raw,'UTF8')::jsonb; binding:=oj->'binding'; rj:=convert_from(i.receiver_raw,'UTF8')::jsonb;
 pj:=convert_from(i.producer_body,'UTF8')::jsonb; rbatch_json:=convert_from(i.receiver_body,'UTF8')::jsonb;
 SELECT * INTO STRICT e FROM contour.causal_resolved_edges WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=(i.tenant,i.gateway,i.generation,i.handle);
 SELECT * INTO STRICT p FROM contour.origin_proofs WHERE (tenant_id,collector_id,batch_id,record_id)=(i.tenant,(binding->>'collector_id')::uuid,(oj->>'batch_id')::uuid,(binding->>'record_id')::uuid);
 SELECT * INTO STRICT pb FROM contour.causal_runtime_bindings WHERE (tenant_id,runtime_id)=(i.tenant,i.producer_runtime);
 SELECT * INTO STRICT rb FROM contour.causal_runtime_bindings WHERE (tenant_id,runtime_id)=(i.tenant,i.receiver_runtime);
 SELECT * INTO STRICT marker FROM contour.causal_marker_bindings WHERE (tenant_id,runtime_id,epoch)=(i.tenant,i.producer_runtime,i.producer_epoch);
 SELECT * INTO STRICT gateway FROM contour.causal_gateway_enrollments WHERE (tenant_id,gateway_id,generation)=(i.tenant,i.gateway,i.generation);
 SELECT * INTO STRICT pbatch FROM contour.causal_inbox_batches WHERE (tenant_id,runtime_id,session_epoch,batch_id)=(i.tenant,i.producer_runtime,i.producer_epoch,(pj->>'batch_id')::uuid);
 SELECT * INTO STRICT rbatch FROM contour.causal_inbox_batches WHERE (tenant_id,runtime_id,session_epoch,batch_id)=(i.tenant,i.receiver_runtime,i.receiver_epoch,(rbatch_json->>'batch_id')::uuid);
 SELECT * INTO STRICT pe FROM contour.causal_inbox_events WHERE (tenant_id,runtime_id,session_epoch,batch_id)=(i.tenant,i.producer_runtime,i.producer_epoch,pbatch.batch_id);
 SELECT * INTO STRICT re FROM contour.causal_inbox_events WHERE (tenant_id,runtime_id,session_epoch,batch_id)=(i.tenant,i.receiver_runtime,i.receiver_epoch,rbatch.batch_id);
 SELECT u.used_bytes-c.before_used INTO STRICT delta FROM contour.origin_logical_usage u JOIN arrival_checks c ON c.n=case_no AND c.step=4 WHERE u.tenant_id=i.tenant;
 IF p.proof_id IS DISTINCT FROM expected_proof OR contour.verify_origin_proof(i.tenant,p.proof_id) IS NOT TRUE OR rj->>'local_root' IS DISTINCT FROM expected_root
 OR delta IS DISTINCT FROM expected_delta OR delta IS DISTINCT FROM e.edge_charge+e.provenance_charge
 OR e.edge_charge IS DISTINCT FROM octet_length(e.canonical_edge)+256 OR e.provenance_charge IS DISTINCT FROM octet_length(e.provenance)+256
 OR e.expires_at IS DISTINCT FROM e.resolved_at+interval '30 days'
 OR pbatch.canonical_batch IS DISTINCT FROM i.producer_body OR rbatch.canonical_batch IS DISTINCT FROM i.receiver_body
 OR contour.causal_committed_batch_valid(i.tenant,i.producer_runtime,i.producer_epoch,pbatch.batch_id) IS NOT TRUE
 OR contour.causal_committed_batch_valid(i.tenant,i.receiver_runtime,i.receiver_epoch,rbatch.batch_id) IS NOT TRUE
 OR (pe.event_id,pe.kind,pe.root,pe.activity,pe.attempt,pe.marker_digest) IS DISTINCT FROM
    (pj->'events'->0->>'event_id','attempt',pj->'events'->0->>'root',pj->'events'->0->>'activity',binding->>'producer_attempt_id',binding->>'marker_digest')
 OR (pe.root,pe.activity,pe.attempt,pe.marker_digest) IS DISTINCT FROM
    ((i.observer_proof).marker_root,(i.observer_proof).marker_activity,(i.observer_proof).marker_attempt,encode((i.observer_proof).marker_wire_digest,'hex'))
 OR (i.observer_proof).marker_public IS DISTINCT FROM marker.marker_public_key
 OR (i.observer_proof).marker_generation IS DISTINCT FROM marker.generation
 OR (i.observer_proof).marker_wire_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(oj->>'signed_marker'),'UTF8'))
 OR (re.event_id,re.kind,re.root) IS DISTINCT FROM (rbatch_json->'events'->0->>'event_id','root',expected_root)
 OR (e.request_collector_id,e.request_batch_id,e.request_record_id,e.producer_project_id,e.producer_service_id,e.receiver_project_id,e.receiver_service_id)
    IS DISTINCT FROM ((binding->>'collector_id')::uuid,(oj->>'batch_id')::uuid,(binding->>'record_id')::uuid,pb.project_id,pb.service_id,rb.project_id,rb.service_id)
 THEN RETURN false; END IF;
 stamp:=to_char(e.resolved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
 expected_edge:=convert_to(contour.causal_json_canonical(jsonb_build_object(
  'wire_version',1,'tenant_id',i.tenant,'gateway_id',i.gateway,'gateway_generation',i.generation,'delivery_handle',i.handle,
  'producer_runtime_id',i.producer_runtime,'producer_session_epoch',i.producer_epoch::text,'producer_root',pe.root,'producer_activity',pe.activity,
  'receiver_runtime_id',i.receiver_runtime,'receiver_session_epoch',i.receiver_epoch::text,'receiver_root',expected_root,'resolved_at',stamp)),'UTF8');
 expected_provenance:=convert_to(contour.causal_json_canonical(jsonb_build_object(
  'wire_version',1,'tenant_id',i.tenant,'gateway_id',i.gateway,'gateway_generation',i.generation,'delivery_handle',i.handle,
  'producer_project_id',pb.project_id,'producer_service_id',pb.service_id,'producer_environment_id',pb.environment_id,'producer_deployment_id',pb.deployment_id,'producer_instance_id',pb.instance_id,
  'receiver_project_id',rb.project_id,'receiver_service_id',rb.service_id,'receiver_environment_id',rb.environment_id,'receiver_deployment_id',rb.deployment_id,'receiver_instance_id',rb.instance_id,
  'producer_batch_id',pbatch.batch_id,'producer_event_id',pe.event_id,'producer_event_digest',encode(pe.event_digest,'hex'),
  'producer_batch_digest',encode(pbatch.batch_digest,'hex'),'producer_receipt_id',pbatch.receipt_id,'producer_receipt_digest',encode(pbatch.receipt_digest,'hex'),
  'receiver_batch_digest',encode(rbatch.batch_digest,'hex'),'receiver_receipt_id',rbatch.receipt_id,'receiver_receipt_digest',encode(rbatch.receipt_digest,'hex'),
  'receiver_batch_id',rbatch.batch_id,'receiver_event_id',re.event_id,'receiver_event_digest',encode(re.event_digest,'hex'),
  'observer_digest',encode(sha256(convert_to(E'apicontour/causal-evidence/observer/1\n','UTF8')||i.observer_raw),'hex'),'observer_predecessors','[]'::jsonb,
  'receiver_digest',encode(sha256(convert_to(E'apicontour/causal-evidence/receiver/1\n','UTF8')||i.receiver_raw),'hex'),
  'collector_id',(binding->>'collector_id')::uuid,'request_batch_id',(oj->>'batch_id')::uuid,'request_record_id',(binding->>'record_id')::uuid,'origin_proof_id',expected_proof,
  'producer_attempt',binding->>'producer_attempt_id','marker_root',pe.root,'marker_activity',pe.activity,'marker_public',encode((i.observer_proof).marker_public,'hex'),
  'marker_nonce',marker.nonce,'marker_generation',encode(marker.generation,'hex'),'marker_credential_id',marker.product_credential_id,'marker_product_leaf',encode(marker.product_leaf_sha256,'hex'),
  'marker_lifecycle_id',marker.lifecycle_id,'marker_instance_id',marker.instance_id,'marker_profile_id',marker.profile_id,'marker_artifact',encode(marker.artifact_sha256,'hex'),
  'request_source_id',(gateway.claim).source_id,'marker_digest',binding->>'marker_digest','binding_digest',rj->>'binding_digest','resolved_at',stamp)),'UTF8');
 RETURN e.canonical_edge=expected_edge AND e.provenance=expected_provenance;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN false;
END $$;
GRANT EXECUTE ON FUNCTION pg_temp.arrival_edge_matches(integer,uuid,text,bigint) TO contour_owner;

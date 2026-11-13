-- Run in the SQL29 same-backend fixture after SQL31. These invalid bounds
-- must fail before any lock-dependent predicate. Valid-clock differential and
-- deterministic backward-jump tests require a separate controlled harness.
DO $$ DECLARE a contour.causal_receiver_assignments; r contour.causal_receiver_enrollments;
 s contour.causal_sessions; b contour.causal_runtime_bindings; o contour.causal_observer_inbox;
 result contour.causal31_clock_result; t timestamptz:=clock_timestamp(); lower_at timestamptz;
BEGIN
 SELECT x.* INTO STRICT a FROM contour.causal_receiver_assignments x JOIN receiver_pairs p
  ON p.name='observer-first' AND x.delivery_handle=convert_from(p.receiver_raw,'UTF8')::jsonb->>'delivery_handle';
 SELECT * INTO STRICT r FROM contour.causal_receiver_enrollments x WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch);
 SELECT * INTO STRICT s FROM contour.causal_sessions x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch);
 SELECT * INTO STRICT b FROM contour.causal_runtime_bindings x WHERE (x.tenant_id,x.runtime_id)=(a.tenant_id,a.receiver_runtime_id);
 SELECT * INTO STRICT o FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle);
 FOREACH lower_at IN ARRAY ARRAY[NULL::timestamptz,'infinity'::timestamptz,t-interval '1 microsecond'] LOOP
  result:=contour.causal31_receiver_claim_checked(r.claim,s,b,t,lower_at);
  IF result.valid IS TRUE THEN RAISE EXCEPTION 'receiver claim accepted invalid lower bound'; END IF;
  result:=contour.causal31_receiver_enrollment_checked(a,t,lower_at);
  IF result.valid IS TRUE THEN RAISE EXCEPTION 'receiver enrollment accepted invalid lower bound'; END IF;
  result:=contour.causal31_receiver_assignment_checked(a,t,lower_at);
  IF result.valid IS TRUE THEN RAISE EXCEPTION 'receiver assignment accepted invalid lower bound'; END IF;
  result:=contour.causal31_receiver_observer_checked(a,t,lower_at);
  IF result.valid IS TRUE THEN RAISE EXCEPTION 'observer scope accepted invalid lower bound'; END IF;
  result:=contour.causal31_scopes_checked(a,a,o,s,t,lower_at);
  IF result.valid IS TRUE THEN RAISE EXCEPTION 'scope composition accepted invalid lower bound'; END IF;
 END LOOP;
 result:=contour.causal31_receiver_claim_checked(r.claim,s,b,'infinity'::timestamptz,'infinity'::timestamptz);
 IF result.valid IS TRUE THEN RAISE EXCEPTION 'receiver claim accepted nonfinite time'; END IF;
 result:=contour.causal31_scopes_checked(a,a,o,s,'infinity'::timestamptz,'infinity'::timestamptz);
 IF result.valid IS TRUE THEN RAISE EXCEPTION 'scope composition accepted nonfinite time'; END IF;
END $$;
DO $$ BEGIN
 IF has_function_privilege('contour_causal_reconciler','contour.causal31_runtime_checked(contour.causal_session_claim,timestamp with time zone)','EXECUTE')
 OR has_function_privilege('contour_causal_reconciler','contour.causal31_session_checked(contour.causal_session_claim,numeric,timestamp with time zone)','EXECUTE')
 OR has_function_privilege('contour_causal_reconciler','contour.causal31_receiver_assignment_checked(contour.causal_receiver_assignments,timestamp with time zone,timestamp with time zone)','EXECUTE')
 OR has_function_privilege('contour_runtime','contour.causal31_receiver_observer_checked(contour.causal_receiver_assignments,timestamp with time zone,timestamp with time zone)','EXECUTE')
 THEN RAISE EXCEPTION 'checked-time helper exposed'; END IF;
END $$;

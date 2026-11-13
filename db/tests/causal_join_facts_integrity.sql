-- Disposable SQL31 helper controls. The owning harness must FIRST commit a
-- valid observer-first pair and SQL20 attempt/root using the public admission
-- APIs, with the producer/receiver scope in pg_temp.receiver_pairs. No INSERT
-- fabricates origin, request, marker, or catalog proof.
CREATE FUNCTION pg_temp.join_check(expected boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE j jsonb; got boolean;
BEGIN
 SELECT convert_from(receiver_raw,'UTF8')::jsonb INTO STRICT j FROM receiver_pairs WHERE name='observer-first';
 got:=contour.causal_join_facts_valid((j->>'tenant_id')::uuid,(j->>'gateway_id')::uuid,j->>'gateway_generation',j->>'delivery_handle',clock_timestamp());
 IF got IS DISTINCT FROM expected THEN RAISE EXCEPTION 'causal join control mismatch'; END IF;
END $$;
DO $$ BEGIN
 IF has_function_privilege('contour_runtime','contour.causal_join_facts_valid(uuid,uuid,text,text,timestamp with time zone)','EXECUTE')
 OR has_function_privilege('contour_causal_receiver_writer','contour.causal_join_facts_valid(uuid,uuid,text,text,timestamp with time zone)','EXECUTE')
 THEN RAISE EXCEPTION 'private join helper executable'; END IF;
END $$;
SELECT pg_temp.join_check(true);
-- The exact original cutoff is exclusive; the helper must also reject a
-- non-finite authorization clock. No admission timestamp is refreshed.
DO $$ DECLARE o contour.causal_observer_inbox; rejected boolean; BEGIN
 SELECT x.* INTO STRICT o FROM contour.causal_observer_inbox x JOIN receiver_pairs p
 ON x.delivery_handle=convert_from(p.receiver_raw,'UTF8')::jsonb->>'delivery_handle'
 WHERE p.name='observer-first';
 rejected:=false;
 BEGIN PERFORM contour.causal_join_facts_valid(o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle,o.expires_at);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'observer cutoff accepted'; END IF;
 rejected:=false;
 BEGIN PERFORM contour.causal_join_facts_valid(o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle,'infinity'::timestamptz);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'nonfinite join clock accepted'; END IF;
END $$;
BEGIN;
ALTER TABLE contour.causal_inbox_events DISABLE TRIGGER causal_inbox_event_immutable;
ALTER TABLE contour.causal_observer_inbox DISABLE TRIGGER observer_immutable;
SAVEPOINT original;
-- The SQL29 observer-first fixture has a committed predecessor and successor.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM contour.causal_observer_inbox selected JOIN receiver_pairs p
  ON p.name='observer-first' AND selected.delivery_handle=convert_from(p.receiver_raw,'UTF8')::jsonb->>'delivery_handle'
  JOIN contour.causal_observer_inbox parent ON (parent.tenant_id,parent.gateway_id,parent.gateway_generation,parent.delivery_handle)=
   (selected.tenant_id,selected.gateway_id,selected.gateway_generation,selected.retry_of)
  JOIN contour.causal_observer_inbox child ON (child.tenant_id,child.gateway_id,child.gateway_generation,child.retry_of)=
   (selected.tenant_id,selected.gateway_id,selected.gateway_generation,selected.delivery_handle))
 THEN RAISE EXCEPTION 'predecessor/successor fixture missing'; END IF;
END $$;
-- A stale required predecessor denies the join without changing its timestamp.
UPDATE contour.causal_observer_inbox parent
 SET accepted_at=statement_timestamp()-interval '25 hours',expires_at=statement_timestamp()-interval '1 hour'
 FROM contour.causal_observer_inbox selected,receiver_pairs p
 WHERE p.name='observer-first'
 AND selected.delivery_handle=convert_from(p.receiver_raw,'UTF8')::jsonb->>'delivery_handle'
 AND (parent.tenant_id,parent.gateway_id,parent.gateway_generation,parent.delivery_handle)=
     (selected.tenant_id,selected.gateway_id,selected.gateway_generation,selected.retry_of);
DO $$ DECLARE rejected boolean:=false; BEGIN
 BEGIN PERFORM pg_temp.join_check(true); EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'expired predecessor accepted'; END IF;
END $$;
ROLLBACK TO original;
-- An expired later successor cannot shorten the selected delivery's lifetime.
UPDATE contour.causal_observer_inbox child
 SET accepted_at=statement_timestamp()-interval '25 hours',expires_at=statement_timestamp()-interval '1 hour'
 FROM contour.causal_observer_inbox selected,receiver_pairs p
 WHERE p.name='observer-first'
 AND selected.delivery_handle=convert_from(p.receiver_raw,'UTF8')::jsonb->>'delivery_handle'
 AND (child.tenant_id,child.gateway_id,child.gateway_generation,child.retry_of)=
     (selected.tenant_id,selected.gateway_id,selected.gateway_generation,selected.delivery_handle);
SELECT pg_temp.join_check(true);
ROLLBACK TO original;
-- Missing producer attempt is unresolved.
DELETE FROM contour.causal_inbox_events e USING contour.causal_observer_inbox o
 WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.attempt)=(o.tenant_id,o.runtime_id,o.session_epoch,'attempt',o.attempt)
 AND o.delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='observer-first');
SELECT pg_temp.join_check(false);
ROLLBACK TO original;
-- A contradictory attempt is corruption rather than a missing fact.
UPDATE contour.causal_inbox_events e SET marker_digest=repeat('0',64) FROM contour.causal_observer_inbox o
 WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.attempt)=(o.tenant_id,o.runtime_id,o.session_epoch,'attempt',o.attempt)
 AND o.delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='observer-first');
DO $$ DECLARE rejected boolean:=false; BEGIN
 BEGIN PERFORM pg_temp.join_check(true); EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'wrong attempt accepted'; END IF;
END $$;
ROLLBACK TO original;
-- A second attempt row is ambiguous even if it has the same scope.
INSERT INTO contour.causal_inbox_events
 SELECT e.tenant_id,e.runtime_id,e.session_epoch,e.batch_id,e.seq+10000,repeat('f',32),e.kind,e.root,e.activity,e.parent,e.attempt,e.marker_digest,e.first_missing_seq,e.last_missing_seq,e.reason,e.event_digest
 FROM contour.causal_inbox_events e JOIN contour.causal_observer_inbox o ON (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.attempt)=(o.tenant_id,o.runtime_id,o.session_epoch,'attempt',o.attempt)
 WHERE o.delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='observer-first');
DO $$ DECLARE rejected boolean:=false; BEGIN
 BEGIN PERFORM pg_temp.join_check(true); EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'ambiguous attempt accepted'; END IF;
END $$;
ROLLBACK TO original;
-- Missing receiver root is unresolved.
DELETE FROM contour.causal_inbox_events e USING contour.causal_receiver_assignments a
 WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.root)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch,'root',a.local_root)
 AND a.delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='observer-first');
SELECT pg_temp.join_check(false);
ROLLBACK TO original;
-- Two roots with the same exact local root are ambiguous.
INSERT INTO contour.causal_inbox_events
 SELECT e.tenant_id,e.runtime_id,e.session_epoch,e.batch_id,e.seq+10000,repeat('e',32),e.kind,e.root,e.activity,e.parent,e.attempt,e.marker_digest,e.first_missing_seq,e.last_missing_seq,e.reason,e.event_digest
 FROM contour.causal_inbox_events e JOIN contour.causal_receiver_assignments a
 ON (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.root)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch,'root',a.local_root)
 WHERE a.delivery_handle=(SELECT convert_from(receiver_raw,'UTF8')::jsonb->>'delivery_handle' FROM receiver_pairs WHERE name='observer-first');
DO $$ DECLARE rejected boolean:=false; BEGIN
 BEGIN PERFORM pg_temp.join_check(true); EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'ambiguous receiver root accepted'; END IF;
END $$;
ROLLBACK TO original;
SELECT pg_temp.join_check(true);
ROLLBACK;

-- Human reader for committed historical edges. Trusted backend identity only.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,31))
 THEN RAISE EXCEPTION 'trusted human causal reader migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_human_causal_reader NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_human_lookup, contour_catalog_reader TO contour_human_causal_reader;
SET LOCAL ROLE contour_owner;
CREATE POLICY human_causal_reader ON contour.causal_resolved_edges FOR SELECT TO contour_human_causal_reader
 USING (tenant_id=contour.tenant_context());
GRANT SELECT ON contour.causal_resolved_edges TO contour_human_causal_reader;
GRANT EXECUTE ON FUNCTION contour.causal_json_canonical(jsonb) TO contour_human_causal_reader;
-- Typed keys are supplied by SQL31 and checked against provenance below.
-- Work is constrained by the tenant quota and original statement deadline;
-- the index supports scoped lookups, with plan verification required in integration.
CREATE INDEX causal_resolved_observation_idx ON contour.causal_resolved_edges
 (tenant_id, request_collector_id, request_batch_id, request_record_id,
  gateway_id, gateway_generation COLLATE "C", delivery_handle COLLATE "C")
 INCLUDE (producer_project_id, producer_service_id, receiver_project_id, receiver_service_id, resolved_at, expires_at);

-- Internal invoker-only snapshot: filter current scope authorization and retention
-- before limiting and before parsing any provenance. Cursor belongs to the same set.
CREATE FUNCTION contour.human_causal_snapshot(t uuid, col uuid, bid uuid, rid uuid, actor uuid,
 cg uuid, cgen text, ch text, page_limit integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog SET TimeZone='UTC' AS $$
DECLARE r record; p jsonb; e jsonb; v text; k text;
 items jsonb:='[]'::jsonb; cursor_scope jsonb:=NULL; cursor_expires timestamptz:=NULL; found_cursor boolean:=cg IS NULL;
 endpoint text; projected jsonb; item jsonb;
BEGIN
 FOR r IN
  WITH eligible AS NOT MATERIALIZED (
   SELECT z.* FROM contour.causal_resolved_edges z
   WHERE z.tenant_id=t AND z.request_collector_id=col AND z.request_batch_id=bid AND z.request_record_id=rid
    AND z.resolved_at<=clock_timestamp() AND clock_timestamp()<z.expires_at
    AND EXISTS(SELECT 1 FROM contour.human_project_memberships m WHERE m.tenant_id=t AND m.actor_id=actor
     AND m.project_id=z.producer_project_id AND m.enabled)
    AND EXISTS(SELECT 1 FROM contour.human_service_roles s WHERE s.tenant_id=t AND s.actor_id=actor
     AND s.project_id=z.producer_project_id AND s.service_id=z.producer_service_id
     AND s.role IN ('viewer','service_owner') AND s.enabled)
    AND EXISTS(SELECT 1 FROM contour.human_project_memberships m WHERE m.tenant_id=t AND m.actor_id=actor
     AND m.project_id=z.receiver_project_id AND m.enabled)
    AND EXISTS(SELECT 1 FROM contour.human_service_roles s WHERE s.tenant_id=t AND s.actor_id=actor
     AND s.project_id=z.receiver_project_id AND s.service_id=z.receiver_service_id
     AND s.role IN ('viewer','service_owner') AND s.enabled)
  ), page AS (
   SELECT x.*,false AS is_cursor FROM eligible x
   WHERE cg IS NULL OR (x.gateway_id,x.gateway_generation COLLATE "C",x.delivery_handle COLLATE "C")>(cg,cgen COLLATE "C",ch COLLATE "C")
   ORDER BY x.gateway_id,x.gateway_generation COLLATE "C",x.delivery_handle COLLATE "C" LIMIT page_limit+1
  )
  SELECT * FROM (
   SELECT * FROM page
   UNION ALL
   SELECT x.*,true AS is_cursor FROM eligible x
    WHERE cg IS NOT NULL AND (x.gateway_id,x.gateway_generation COLLATE "C",x.delivery_handle COLLATE "C")=(cg,cgen COLLATE "C",ch COLLATE "C")
  ) selected ORDER BY is_cursor, gateway_id, gateway_generation COLLATE "C", delivery_handle COLLATE "C"
 LOOP
  p:=convert_from(r.provenance,'UTF8')::jsonb; e:=convert_from(r.canonical_edge,'UTF8')::jsonb;
  IF jsonb_typeof(p)<>'object' OR jsonb_typeof(e)<>'object'
   OR convert_to(contour.causal_json_canonical(p),'UTF8') IS DISTINCT FROM r.provenance
   OR convert_to(contour.causal_json_canonical(e),'UTF8') IS DISTINCT FROM r.canonical_edge
   OR p->'wire_version' IS DISTINCT FROM '1'::jsonb OR e->'wire_version' IS DISTINCT FROM '1'::jsonb
   OR (p->>'collector_id',p->>'request_batch_id',p->>'request_record_id',p->>'producer_project_id',p->>'producer_service_id',p->>'receiver_project_id',p->>'receiver_service_id')
     IS DISTINCT FROM (r.request_collector_id::text,r.request_batch_id::text,r.request_record_id::text,r.producer_project_id::text,r.producer_service_id::text,r.receiver_project_id::text,r.receiver_service_id::text)
   OR (p->>'tenant_id',p->>'gateway_id',p->>'gateway_generation',p->>'delivery_handle')
     IS DISTINCT FROM (t::text,r.gateway_id::text,r.gateway_generation,r.delivery_handle)
   OR (e->>'tenant_id',e->>'gateway_id',e->>'gateway_generation',e->>'delivery_handle')
     IS DISTINCT FROM (t::text,r.gateway_id::text,r.gateway_generation,r.delivery_handle)
   OR r.gateway_generation COLLATE "C" !~ '^[0-9a-f]{32}$' OR r.delivery_handle COLLATE "C" !~ '^[0-9a-f]{32}$'
   OR NOT isfinite(r.resolved_at) OR NOT isfinite(r.expires_at) OR r.expires_at<>r.resolved_at+interval '30 days'
   OR p->>'resolved_at' IS DISTINCT FROM to_char(r.resolved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
   OR e->>'resolved_at' IS DISTINCT FROM p->>'resolved_at'
  THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
  FOREACH endpoint IN ARRAY ARRAY['producer','receiver'] LOOP
   FOREACH k IN ARRAY ARRAY['project_id','service_id','environment_id','deployment_id','instance_id','batch_id','event_id','receipt_id'] LOOP
    v:=p->>(endpoint||'_'||k);
    IF v IS NULL OR jsonb_typeof(p->(endpoint||'_'||k)) IS DISTINCT FROM 'string'
     OR (k='event_id' AND v COLLATE "C" !~ '^[0-9a-f]{32}$')
     OR (k<>'event_id' AND v COLLATE "C" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
   END LOOP;
  END LOOP;
  IF r.is_cursor THEN
   found_cursor:=true;
   cursor_scope:=jsonb_build_array(p->>'producer_project_id',p->>'producer_service_id',p->>'receiver_project_id',p->>'receiver_service_id');
   cursor_expires:=r.expires_at;
  ELSE
   projected:='{}'::jsonb;
   FOREACH endpoint IN ARRAY ARRAY['producer','receiver'] LOOP
    item:='{}'::jsonb;
    FOREACH k IN ARRAY ARRAY['project_id','service_id','environment_id','deployment_id','instance_id','batch_id','event_id','receipt_id'] LOOP
     item:=item||jsonb_build_object(k,p->>(endpoint||'_'||k));
    END LOOP;
    projected:=projected||jsonb_build_object(endpoint,item);
   END LOOP;
   item:=jsonb_build_object('resolved_at',to_char(r.resolved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'expires_at',to_char(r.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))||projected;
   items:=items||jsonb_build_array(jsonb_build_object('key',r.gateway_id::text||'.'||r.gateway_generation||'.'||r.delivery_handle,
     'scope',jsonb_build_array(p->>'producer_project_id',p->>'producer_service_id',p->>'receiver_project_id',p->>'receiver_service_id'), 'item',item));
  END IF;
 END LOOP;
 IF NOT found_cursor THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
 RETURN jsonb_build_object('rows',items,'cursor_scope',cursor_scope,'cursor_expires',cursor_expires);
END $$;
REVOKE ALL ON FUNCTION contour.human_causal_snapshot(uuid,uuid,uuid,uuid,uuid,uuid,text,text,integer) FROM PUBLIC;

CREATE FUNCTION contour.human_causal_connections(t uuid, project uuid, service uuid, environment uuid, operation uuid, observation uuid,
 p_issuer text, p_subject text, cg uuid, cgen text, ch text, page_limit integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET TimeZone='UTC' AS $$
DECLARE actor uuid; enabled boolean; w record; before_page jsonb; after_page jsonb; entry jsonb; scope jsonb;
 projects uuid[]:=ARRAY[project]; scopes text[]:=ARRAY[project::text||'/'||service::text]; key text; proj uuid; svc uuid;
 out_items jsonb:='[]'::jsonb; next_key text:=NULL; i integer; role_enabled boolean;
BEGIN
 IF t IS NULL OR t IS DISTINCT FROM contour.tenant_context() OR project IS NULL OR service IS NULL OR environment IS NULL
  OR operation IS NULL OR observation IS NULL OR p_issuer IS NULL OR p_subject IS NULL OR page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 50
  OR ((cg IS NULL)::int+(cgen IS NULL)::int+(ch IS NULL)::int) NOT IN (0,3)
  OR (cg IS NOT NULL AND (cgen COLLATE "C" !~ '^[0-9a-f]{32}$' OR ch COLLATE "C" !~ '^[0-9a-f]{32}$'))
 THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
 SELECT h.actor_id,h.enabled INTO actor,enabled FROM contour.human_identities h WHERE h.issuer=p_issuer AND h.subject=p_subject FOR SHARE;
 IF NOT FOUND OR NOT enabled THEN RAISE EXCEPTION 'human access denied' USING ERRCODE='42501'; END IF;
 SELECT h.enabled INTO enabled FROM contour.human_actors h WHERE h.actor_id=actor FOR SHARE;
 IF NOT FOUND OR NOT enabled THEN RAISE EXCEPTION 'human access denied' USING ERRCODE='42501'; END IF;
 SELECT h.enabled INTO enabled FROM contour.human_tenant_memberships h WHERE h.tenant_id=t AND h.actor_id=actor FOR SHARE;
 IF NOT FOUND OR NOT enabled THEN RAISE EXCEPTION 'human access denied' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM contour.human_project_memberships m WHERE m.tenant_id=t AND m.actor_id=actor AND m.project_id=project AND m.enabled)
  OR NOT EXISTS(SELECT 1 FROM contour.human_service_roles s WHERE s.tenant_id=t AND s.actor_id=actor AND s.project_id=project
   AND s.service_id=service AND s.role IN ('service_owner','viewer') AND s.enabled)
 THEN RAISE EXCEPTION 'human access denied' USING ERRCODE='42501'; END IF;
 SELECT x.collector_id,x.batch_id,x.record_id INTO w FROM contour.observation_windows x
 WHERE (x.tenant_id,x.project_id,x.service_id,x.environment_id,x.operation_id,x.observation_id)=(t,project,service,environment,operation,observation);
 IF NOT FOUND THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
 before_page:=contour.human_causal_snapshot(t,w.collector_id,w.batch_id,w.record_id,actor,cg,cgen,ch,page_limit);
 FOR scope IN SELECT value->'scope' FROM jsonb_array_elements(before_page->'rows') UNION ALL SELECT before_page->'cursor_scope' LOOP
  IF scope IS NOT NULL AND scope<>'null'::jsonb THEN
   projects:=array_append(projects,(scope->>0)::uuid); projects:=array_append(projects,(scope->>2)::uuid);
   scopes:=array_append(scopes,(scope->>0)||'/'||(scope->>1)); scopes:=array_append(scopes,(scope->>2)||'/'||(scope->>3));
  END IF;
 END LOOP;
 FOR proj IN SELECT DISTINCT unnest(projects) ORDER BY 1 LOOP
  PERFORM 1 FROM contour.human_project_memberships m WHERE m.tenant_id=t AND m.actor_id=actor AND m.project_id=proj ORDER BY m.project_id FOR SHARE;
 END LOOP;
 FOR key IN SELECT DISTINCT unnest(scopes) ORDER BY 1 LOOP
  proj:=split_part(key,'/',1)::uuid; svc:=split_part(key,'/',2)::uuid;
  PERFORM 1 FROM contour.human_service_roles s WHERE s.tenant_id=t AND s.actor_id=actor AND s.project_id=proj AND s.service_id=svc
   AND s.role IN ('service_owner','viewer') ORDER BY s.role FOR SHARE;
 END LOOP;
 SELECT m.enabled INTO enabled FROM contour.human_project_memberships m WHERE m.tenant_id=t AND m.actor_id=actor AND m.project_id=project;
 SELECT coalesce(bool_or(s.enabled),false) INTO role_enabled FROM contour.human_service_roles s WHERE s.tenant_id=t AND s.actor_id=actor
  AND s.project_id=project AND s.service_id=service AND s.role IN ('service_owner','viewer');
 IF NOT coalesce(enabled,false) OR NOT role_enabled THEN RAISE EXCEPTION 'human access denied' USING ERRCODE='42501'; END IF;
 -- The final READ COMMITTED statement snapshot is the page authorization point.
 after_page:=contour.human_causal_snapshot(t,w.collector_id,w.batch_id,w.record_id,actor,cg,cgen,ch,page_limit);
 IF before_page IS DISTINCT FROM after_page THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
 IF cg IS NOT NULL AND (after_page->>'cursor_expires')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(after_page->'rows') LOOP
  IF (entry->'item'->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOR i IN 0..least(jsonb_array_length(after_page->'rows'),page_limit)-1 LOOP
  entry:=after_page->'rows'->i;
  IF (entry->'item'->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'causal connections unavailable' USING ERRCODE='23514'; END IF;
  out_items:=out_items||jsonb_build_array(entry->'item');
 END LOOP;
 IF jsonb_array_length(after_page->'rows')>page_limit THEN next_key:=after_page->'rows'->(page_limit-1)->>'key'; END IF;
 RETURN jsonb_build_object('items',out_items,'next_cursor',next_key);
END $$;
REVOKE ALL ON FUNCTION contour.human_causal_connections(uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,text,integer) FROM PUBLIC;
RESET ROLE;
ALTER FUNCTION contour.human_causal_snapshot(uuid,uuid,uuid,uuid,uuid,uuid,text,text,integer) OWNER TO contour_human_causal_reader;
ALTER FUNCTION contour.human_causal_connections(uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,text,integer) OWNER TO contour_human_causal_reader;
GRANT EXECUTE ON FUNCTION contour.human_causal_connections(uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,text,integer) TO contour_catalog_reader;
SET LOCAL ROLE contour_owner;
INSERT INTO contour.schema_migrations(version) VALUES (32);
COMMIT;

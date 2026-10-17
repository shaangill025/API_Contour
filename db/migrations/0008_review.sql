-- Immutable review request and terminal decision. Head CAS belongs to the adapter.
BEGIN;
SET LOCAL ROLE contour_owner;
GRANT USAGE ON SCHEMA contour TO contour_review_writer, contour_review_reader;
GRANT EXECUTE ON FUNCTION contour.tenant_context() TO contour_review_writer, contour_review_reader;
ALTER TABLE contour.comparisons ADD CONSTRAINT comparison_review_scope
    UNIQUE (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id);
CREATE TABLE contour.review_requests (
    tenant_id uuid NOT NULL,
    review_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    comparison_id uuid NOT NULL,
    candidate_version_id uuid NOT NULL,
    expected_event_id uuid,
    creator_actor_id uuid NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision=1),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id,review_id),
    FOREIGN KEY (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.comparisons
            (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,candidate_version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.declared_versions
            (tenant_id,version_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,expected_event_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.approval_events
            (tenant_id,event_id,operation_id,project_id,service_id,environment_id)
);
CREATE TABLE contour.review_decisions (
    tenant_id uuid NOT NULL,
    review_id uuid NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approve','reject')),
    expected_revision bigint NOT NULL CHECK (expected_revision=1),
    revision bigint NOT NULL DEFAULT 2 CHECK (revision=2),
    actor_id uuid NOT NULL,
    approval_event_id uuid,
    decided_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id,review_id),
    UNIQUE (tenant_id,approval_event_id),
    CHECK ((decision='approve')=(approval_event_id IS NOT NULL)),
    FOREIGN KEY (tenant_id,review_id) REFERENCES contour.review_requests (tenant_id,review_id),
    FOREIGN KEY (tenant_id,approval_event_id) REFERENCES contour.approval_events (tenant_id,event_id)
);
-- Invoker guards use only metadata granted to the new writer. Foreign keys also
-- enforce tenant and operation scope; these guards bind the *exact* input pair.
CREATE FUNCTION contour.check_review_request() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,contour AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'review tenant context required' USING ERRCODE='42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM contour.comparisons c
        WHERE c.tenant_id=NEW.tenant_id AND c.comparison_id=NEW.comparison_id
        AND c.operation_id=NEW.operation_id AND c.project_id=NEW.project_id
        AND c.service_id=NEW.service_id AND c.environment_id=NEW.environment_id
        AND c.right_kind='declared' AND c.right_version_id=NEW.candidate_version_id
        AND ((NEW.expected_event_id IS NULL AND c.left_kind='declared')
            OR (c.left_kind='approved' AND c.left_event_id=NEW.expected_event_id))) THEN
        RAISE EXCEPTION 'review inputs do not match comparison' USING ERRCODE='23503';
    END IF;
    RETURN NEW;
END $$;
CREATE FUNCTION contour.check_review_decision() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,contour AS $$
BEGIN
    IF NEW.decision='approve' AND NOT EXISTS (
        SELECT 1 FROM contour.review_requests r JOIN contour.approval_events e
            ON e.tenant_id=r.tenant_id AND e.event_id=NEW.approval_event_id
        WHERE r.tenant_id=NEW.tenant_id AND r.review_id=NEW.review_id
            AND e.operation_id=r.operation_id AND e.project_id=r.project_id
            AND e.service_id=r.service_id AND e.environment_id=r.environment_id
            AND e.version_id=r.candidate_version_id AND e.actor_id=NEW.actor_id
            AND e.expected_event_id IS NOT DISTINCT FROM r.expected_event_id) THEN
        RAISE EXCEPTION 'decision approval association does not match review' USING ERRCODE='23503';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION contour.check_review_request(),contour.check_review_decision() FROM PUBLIC;
CREATE TRIGGER checked_review_request BEFORE INSERT ON contour.review_requests
    FOR EACH ROW EXECUTE FUNCTION contour.check_review_request();
CREATE TRIGGER checked_review_decision BEFORE INSERT ON contour.review_decisions
    FOR EACH ROW EXECUTE FUNCTION contour.check_review_decision();
CREATE TRIGGER immutable_review_request BEFORE UPDATE OR DELETE ON contour.review_requests
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER immutable_review_decision BEFORE UPDATE OR DELETE ON contour.review_decisions
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
ALTER TABLE contour.review_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.review_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE contour.review_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.review_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY review_request_tenant ON contour.review_requests
    TO contour_review_writer,contour_review_reader
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
CREATE POLICY review_decision_tenant ON contour.review_decisions
    TO contour_review_writer,contour_review_reader
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
GRANT SELECT ON contour.review_requests,contour.review_decisions
    TO contour_review_writer,contour_review_reader;
-- PostgreSQL row locking requires UPDATE on at least one column. This grant
-- permits SELECT FOR UPDATE; the immutable trigger rejects actual UPDATE.
GRANT UPDATE (review_id) ON contour.review_requests TO contour_review_writer;
GRANT INSERT (tenant_id,review_id,operation_id,project_id,service_id,environment_id,
    comparison_id,candidate_version_id,expected_event_id,creator_actor_id)
    ON contour.review_requests TO contour_review_writer;
GRANT INSERT (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
    ON contour.review_decisions TO contour_review_writer;
GRANT SELECT (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,left_event_id,right_kind,right_version_id,right_event_id)
    ON contour.comparisons TO contour_review_writer;
CREATE POLICY review_comparison_read ON contour.comparisons FOR SELECT
    TO contour_review_writer USING (tenant_id=contour.tenant_context());
GRANT SELECT (tenant_id,event_id,version_id,operation_id,project_id,service_id,environment_id,
    expected_event_id,actor_id) ON contour.approval_events TO contour_review_writer;
CREATE POLICY review_approval_read ON contour.approval_events FOR SELECT
    TO contour_review_writer USING (tenant_id=contour.tenant_context());
-- A terminal decision is itself the immutable actor audit association. Applications
-- derive status/revision with a LEFT JOIN, using request revision 1 until decision 2.
-- No review role can change approval heads, grant itself roles, or read graph bytes.
-- transaction failure probe: fixture injects after all DDL and grants.
INSERT INTO contour.schema_migrations(version) VALUES (8);
COMMIT;

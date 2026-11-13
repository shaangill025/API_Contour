\echo receiver-case=revoked-product
SELECT set_config('apicontour.tenant_id',(SELECT convert_from(raw,'UTF8')::jsonb->>'tenant_id' FROM public.receiver29_race_seed WHERE name='left'),false);
SET ROLE contour_admin;
SELECT contour.end_origin((SELECT (convert_from(raw,'UTF8')::jsonb->>'tenant_id')::uuid FROM public.receiver29_race_seed WHERE name='left'),'credential_revoked','00000000-0000-4000-8000-00000000ce10');
RESET ROLE;
SET ROLE contour_causal_receiver_writer;
DO $$ DECLARE pair record; BEGIN
 SELECT * INTO STRICT pair FROM public.receiver29_race_seed WHERE name='left';
 BEGIN PERFORM contour.accept_causal_receiver(pair.raw,pair.proof); RAISE EXCEPTION 'revoked receiver returned receipt'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;

"""Exact, fail-closed v21 catalog inventory for the local origin pilot.

The inventory exposes schema metadata, never table data, role password hashes,
keys or policy envelopes. References are fixed captures from a root-owned clean
pinned database, compared exactly. This is not a general PostgreSQL attestation.
"""
import hashlib
import json
from pathlib import Path

# Fixed, reviewed captures from the pinned owned PostgreSQL reference.
REFERENCE_SHA256 = {(14, 'pre'): '792e7bc67a9c6468a09dfc3ea43a9998cd361adc204d7a766b05c862bdc55aa6', (14, 'groups'): '35eea9d25ac19cc4cbb2ca9c0054052c3c49fa7304f71a1202de1649a19f906c', (15, 'pre'): '6a79f7a8f23a73dfc690fb8ae85ca295937e35dc62ab58e5a9bc8543f495fd2f', (16, 'pre'): 'e9b9d9f5368e30073d6b34f6c794f96c1bd7489414802a4563d3e308e52ba643', (17, 'pre'): 'aca40b20b4cd69b8476cf90f664d5b50c18716b38c13544edbf2a8fde31b331b', (18, 'pre'): '886201849bb7a5941465b975e47494053d06346e49c6bb2cb549bcdc225dd845', (19, 'pre'): '74dd25e366aa8ca159e5be478630601fff0a802884d327c0025444777605f6d0', (20, 'pre'): '7b20044860cdb3181c2002faff120ed3c1f6ca55fdb3f7c4dabc40aeabf11f12', (21, 'pre'): '6316a3f1866a7fb014386f5e4842fca2abe5319e20aecb6798d031ae26b87a81', (21, 'enrolled'): '8245ccc118fecb4cf09e4bbe7a8b64d830fb90f40f0ddcac490e2e724f006e52'}


def require_ledger(versions, stage=21):
    if type(stage) is not int or stage not in range(14,22): raise ValueError('unsupported version 21 stage')
    if type(versions) is not list or any(type(v) is not int for v in versions) or versions != list(range(1, stage+1)):
        raise ValueError('exact stage ledger required')


def reference_path(stage, phase):
    if (stage,phase) not in REFERENCE_SHA256: raise ValueError('unsupported reference stage')
    return Path(__file__).with_name('origin21_reference_%d_%s.json' % (stage,phase))


def inventory_sql():
    """Return one deterministic JSONB metadata value for an explicitly chosen DB.

    Sorted names/definitions avoid installation-specific object OIDs. The role
    inventory excludes passwords and includes all contour roles and all edges
    into or out of them; callers must compare any authorized post-setup changes
    explicitly, not silently remove unknown roles or privileges.
    """
    return r"""WITH
ns AS (SELECT oid,nspowner,nspacl FROM pg_catalog.pg_namespace WHERE nspname='contour'),
rels AS (SELECT c.* FROM pg_catalog.pg_class c JOIN ns ON c.relnamespace=ns.oid
         WHERE c.relkind IN ('r','p','v','m','S','i','I','f','c')),
procs AS (SELECT p.* FROM pg_catalog.pg_proc p JOIN ns ON p.pronamespace=ns.oid),
types AS (SELECT t.* FROM pg_catalog.pg_type t JOIN ns ON t.typnamespace=ns.oid
          WHERE t.typtype IN ('c','d','e','r','m') AND (t.typrelid=0 OR EXISTS (SELECT 1 FROM rels r WHERE r.oid=t.typrelid AND r.relkind IN ('r','p','c')))),
roles AS (SELECT r.* FROM pg_catalog.pg_roles r WHERE r.rolname LIKE 'contour\_%' ESCAPE '\'),
items AS (
 SELECT 'schema' kind, jsonb_build_object('owner',pg_catalog.pg_get_userbyid(nspowner),'acl',nspacl::text) value FROM ns
 UNION ALL SELECT 'relation',jsonb_build_object('name',r.relname,'kind',r.relkind,'owner',pg_catalog.pg_get_userbyid(r.relowner),'rls',r.relrowsecurity,'force_rls',r.relforcerowsecurity,'acl',r.relacl::text,'persistence',r.relpersistence,'options',r.reloptions,'view_definition',CASE WHEN r.relkind IN ('v','m') THEN pg_catalog.pg_get_viewdef(r.oid,true) ELSE NULL END,'replica_identity',r.relreplident,'is_partition',r.relispartition,'partition_bound',pg_catalog.pg_get_expr(r.relpartbound,r.oid),'partition_key',pg_catalog.pg_get_partkeydef(r.oid),'index',CASE WHEN r.relkind IN ('i','I') THEN pg_catalog.pg_get_indexdef(r.oid) ELSE NULL END,'index_valid',i.indisvalid,'index_ready',i.indisready,'index_live',i.indislive) FROM rels r LEFT JOIN pg_catalog.pg_index i ON i.indexrelid=r.oid
 UNION ALL SELECT 'column',jsonb_build_object('relation',r.relname,'number',a.attnum,'name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid),'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE (SELECT n.nspname||'.'||c.collname FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE c.oid=a.attcollation) END,'acl',a.attacl::text)
 FROM rels r JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=r.oid AND d.adnum=a.attnum WHERE r.relkind IN ('r','p','v','m','f','c')
 UNION ALL SELECT 'inheritance',jsonb_build_object('child',child.relname,'parent',parent.relname,'sequence',h.inhseqno,'detach_pending',h.inhdetachpending) FROM rels child JOIN pg_catalog.pg_inherits h ON h.inhrelid=child.oid JOIN pg_catalog.pg_class parent ON parent.oid=h.inhparent
 UNION ALL SELECT 'constraint',jsonb_build_object('relation',r.relname,'name',c.conname,'type',c.contype,'deferrable',c.condeferrable,'deferred',c.condeferred,'validated',c.convalidated,'definition',pg_catalog.pg_get_constraintdef(c.oid,true)) FROM rels r JOIN pg_catalog.pg_constraint c ON c.conrelid=r.oid
 UNION ALL SELECT 'trigger',jsonb_build_object('relation',r.relname,'name',t.tgname,'enabled',t.tgenabled,'definition',pg_catalog.pg_get_triggerdef(t.oid,true)) FROM rels r JOIN pg_catalog.pg_trigger t ON t.tgrelid=r.oid WHERE NOT t.tgisinternal
 UNION ALL SELECT 'internal_trigger',jsonb_build_object('relation',r.relname,'constraint',c.conname,'constraint_type',c.contype,'function_schema',fn.nspname,'function',p.proname,'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),'event_bits',t.tgtype,'enabled',t.tgenabled,'deferrable',t.tgdeferrable,'initially_deferred',t.tginitdeferred,'referenced_relation',CASE WHEN t.tgconstrrelid=0 THEN NULL ELSE t.tgconstrrelid::regclass::text END)
 FROM rels r JOIN pg_catalog.pg_trigger t ON t.tgrelid=r.oid AND t.tgisinternal JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid JOIN pg_catalog.pg_namespace fn ON fn.oid=p.pronamespace LEFT JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
 UNION ALL SELECT 'rule',jsonb_build_object('relation',r.relname,'name',rw.rulename,'event_type',rw.ev_type,'instead',rw.is_instead,'enabled',rw.ev_enabled,'definition',pg_catalog.pg_get_ruledef(rw.oid,true)) FROM rels r JOIN pg_catalog.pg_rewrite rw ON rw.ev_class=r.oid
 UNION ALL SELECT 'policy',jsonb_build_object('relation',r.relname,'name',p.polname,'command',p.polcmd,'permissive',p.polpermissive,'roles',coalesce((SELECT jsonb_agg(CASE WHEN x.oid=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(x.oid) END ORDER BY CASE WHEN x.oid=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(x.oid) END) FROM unnest(p.polroles) x(oid)),'[]'::jsonb),'using',pg_catalog.pg_get_expr(p.polqual,p.polrelid),'check',pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)) FROM rels r JOIN pg_catalog.pg_policy p ON p.polrelid=r.oid
 UNION ALL SELECT 'function',jsonb_build_object('name',p.proname,'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),'result',pg_catalog.pg_get_function_result(p.oid),'owner',pg_catalog.pg_get_userbyid(p.proowner),'kind',p.prokind,'security_definer',p.prosecdef,'config',p.proconfig,'acl',p.proacl::text,'definition',CASE WHEN p.prokind='a' THEN NULL ELSE pg_catalog.pg_get_functiondef(p.oid) END) FROM procs p
 UNION ALL SELECT 'type',jsonb_build_object('name',t.typname,'kind',t.typtype,'owner',pg_catalog.pg_get_userbyid(t.typowner),'acl',t.typacl::text,'not_null',t.typnotnull,'default',t.typdefault,'definition',pg_catalog.format_type(t.oid,NULL)) FROM types t
 UNION ALL SELECT 'type_attribute',jsonb_build_object('type',t.typname,'number',a.attnum,'name',a.attname,'definition',pg_catalog.format_type(a.atttypid,a.atttypmod)) FROM types t JOIN pg_catalog.pg_attribute a ON a.attrelid=t.typrelid AND a.attnum>0 AND NOT a.attisdropped WHERE t.typrelid<>0
 UNION ALL SELECT 'enum_label',jsonb_build_object('type',t.typname,'label',e.enumlabel,'order',e.enumsortorder) FROM types t JOIN pg_catalog.pg_enum e ON e.enumtypid=t.oid
 UNION ALL SELECT 'domain_constraint',jsonb_build_object('type',t.typname,'name',c.conname,'definition',pg_catalog.pg_get_constraintdef(c.oid,true),'validated',c.convalidated) FROM types t JOIN pg_catalog.pg_constraint c ON c.contypid=t.oid
 UNION ALL SELECT 'default_acl',jsonb_build_object('owner',pg_catalog.pg_get_userbyid(d.defaclrole),'object_kind',d.defaclobjtype,'schema',CASE WHEN d.defaclnamespace=0 THEN NULL ELSE 'contour' END,'acl',d.defaclacl::text) FROM pg_catalog.pg_default_acl d WHERE d.defaclnamespace=(SELECT oid FROM ns) OR (d.defaclnamespace=0 AND d.defaclrole IN (SELECT oid FROM roles))
 UNION ALL SELECT 'role_setting',jsonb_build_object('role',CASE WHEN d.setrole=0 THEN NULL ELSE pg_catalog.pg_get_userbyid(d.setrole) END,'database',CASE WHEN d.setdatabase=0 THEN NULL ELSE (SELECT datname FROM pg_catalog.pg_database WHERE oid=d.setdatabase) END,'settings',d.setconfig) FROM pg_catalog.pg_db_role_setting d WHERE d.setrole IN (SELECT oid FROM roles) OR (d.setrole=0 AND d.setdatabase=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()))
 UNION ALL SELECT 'database_acl',jsonb_build_object('grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,'grantor',pg_catalog.pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable) FROM pg_catalog.pg_database d CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) a WHERE d.datname=current_database()
 UNION ALL SELECT 'role',jsonb_build_object('name',r.rolname,'login',r.rolcanlogin,'inherit',r.rolinherit,'superuser',r.rolsuper,'bypass_rls',r.rolbypassrls,'create_role',r.rolcreaterole,'create_db',r.rolcreatedb,'replication',r.rolreplication,'connection_limit',r.rolconnlimit,'valid_until',r.rolvaliduntil,'config',r.rolconfig) FROM roles r
 UNION ALL SELECT 'membership',jsonb_build_object('role',pg_catalog.pg_get_userbyid(m.roleid),'member',pg_catalog.pg_get_userbyid(m.member),'grantor',pg_catalog.pg_get_userbyid(m.grantor),'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option) FROM pg_catalog.pg_auth_members m WHERE m.roleid IN (SELECT oid FROM roles) OR m.member IN (SELECT oid FROM roles)
)
SELECT jsonb_build_object('version',1,'server_major',current_setting('server_version_num')::integer/10000,
 'items',coalesce((SELECT jsonb_agg(jsonb_build_object('kind',kind,'value',value) ORDER BY kind,value::text) FROM items),'[]'::jsonb))::text;"""


def require_reference(stage=21, phase='pre'):
    path=reference_path(stage,phase)
    digest=REFERENCE_SHA256[(stage,phase)]
    if not isinstance(digest,str) or len(digest)!=64:
        raise RuntimeError('version 21 reference and comparator not installed')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=digest: raise ValueError('version 21 reference digest mismatch')
    value=json.loads(raw)
    if not isinstance(value,dict) or set(value)!={'stage','phase','inventory'} or type(value['stage']) is not int or value['stage']!=stage or value['phase']!=phase:
        raise ValueError('invalid version 21 reference identity')
    inventory=value['inventory']
    if not isinstance(inventory,dict) or set(inventory)!={'version','server_major','items'} or type(inventory['version']) is not int or inventory['version']!=1 or type(inventory['server_major']) is not int or not isinstance(inventory['items'],list) or not inventory['items']:
        raise ValueError('invalid version 21 reference')
    if (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()!=raw: raise ValueError('noncanonical version 21 reference')
    return inventory


def require_ready(versions, psql, *, stage=21, phase='pre'):
    require_ledger(versions,stage)
    expected=require_reference(stage,phase)
    if not callable(psql): raise ValueError('database callback required')
    if psql('SELECT pg_catalog.current_database()::text;')!='contour_local': raise RuntimeError('wrong local database')
    actual=json.loads(psql(inventory_sql()))
    if actual!=expected: raise RuntimeError('version 21 catalog drift')

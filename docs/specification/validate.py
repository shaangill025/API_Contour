#!/usr/bin/env python3
"""Offline checks for this specification, not a product acceptance runner.

The schema interpreter supports only the vocabulary used in the batch schemas.
It rejects unknown keywords. It is not a full JSON Schema conformance validator.
"""
import datetime
import copy
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f'duplicate JSON key: {key}')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs)


def load_traceability():
    directory = ROOT/'backlog'
    data = load(directory/'traceability.json')
    for key in ('requirements', 'phases', 'capabilities'):
        data[key] = load(directory/data[key]['$ref'])
    for key in ('tasks', 'acceptance'):
        data[key] = [row for part in data[key] for row in load(directory/part['$ref'])]
    return data


def resolve_local(reference, path):
    require('://' not in reference, 'remote contract reference')
    file_part, _, fragment = reference.partition('#')
    target = load(path.parent/file_part) if file_part else load(path)
    for token in fragment.strip('/').split('/') if fragment else []:
        target = target[token.replace('~1', '/').replace('~0', '~')]
    return target


def causal_semantic_check(body):
    events = body['events']
    require(events[0]['seq'] == body['first_seq'] and events[-1]['seq'] == body['last_seq'], 'causal endpoints')
    require(all(a['seq'] < b['seq'] for a, b in zip(events, events[1:])), 'causal ordering')
    require(len({e['event_id'] for e in events}) == len(events), 'causal duplicate event')
    roots, activities, attempts, activity_roots = set(), {}, {}, {}
    for e in events:
        kind = e['kind']
        if kind == 'root':
            require(e['root'] not in roots, 'duplicate root'); roots.add(e['root'])
        if kind in ('delivery', 'attempt'):
            require(e['activity'] not in activity_roots or activity_roots[e['activity']] == e['root'], 'contradictory activity root')
            activity_roots[e['activity']] = e['root']
            key = e['activity'] if kind == 'delivery' else e['attempt']
            value = (e['root'], e['parent']) if kind == 'delivery' else (e['root'], e['activity'], e['marker_digest'])
            seen = activities if kind == 'delivery' else attempts
            require(key not in seen or seen[key] == value, 'contradictory identifier'); seen[key] = value
        if kind == 'loss':
            a, b = e['first_missing_seq'], e['last_missing_seq']
            require(a <= b < e['seq'] and not any(a <= x['seq'] <= b for x in events), 'invalid loss range')


    for e in events:
        if e['kind'] == 'delivery':
            require(e['activity'] != e['parent'] and e['activity'] not in roots, 'contradictory delivery activity')
        if e['kind'] == 'attempt':
            require(e['activity'] not in roots or e['activity'] == e['root'], 'contradictory root activity')


def grant_timestamp_nanos(value):
    # Match the Rust Timestamp grammar and retain all nine fractional digits.
    require(isinstance(value, str) and len(value) <= 35, 'grant timestamp length')
    match = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})', value)
    require(match is not None, 'grant timestamp syntax')
    year, month, day, hour, minute, second = map(int, match.group(1, 2, 3, 4, 5, 6))
    require(year != 0 and second <= 59, 'grant timestamp range')
    try:
        day_number = datetime.date(year, month, day).toordinal()
    except ValueError as error:
        raise ValueError('grant timestamp calendar') from error
    require(hour <= 23 and minute <= 59, 'grant timestamp clock')
    zone = match.group(8)
    offset = 0
    if zone != 'Z':
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        require(hours <= 23 and minutes <= 59, 'grant timestamp offset')
        offset = (hours * 60 + minutes) * (1 if zone[0] == '+' else -1)
    seconds = day_number * 86400 + hour * 3600 + minute * 60 + second - offset * 60
    fraction = int((match.group(7) or '').ljust(9, '0') or '0')
    return seconds * 1_000_000_000 + fraction


def causal_grant_semantic_check(body):
    issued = grant_timestamp_nanos(body['issued_at'])
    expires = grant_timestamp_nanos(body['expires_at'])
    require(0 < expires - issued <= 900_000_000_000, 'causal grant lease')


def date(value):
    require(isinstance(value, str), 'timestamp is not a string')
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'timestamp needs timezone')
    return result


def schema_check(value, schema, document, depth=0):
    require(depth < 150, 'schema recursion limit')
    allowed = {'$schema', '$id', 'title', '$defs', '$ref', 'type', 'properties',
               'required', 'additionalProperties', 'propertyNames', 'maxProperties',
               'minLength', 'maxLength', 'pattern', 'enum', 'const', 'minimum',
               'maximum', 'items', 'minItems', 'maxItems', 'uniqueItems', 'oneOf',
               'anyOf', 'format'}
    # The V2 document has one root annotation. Keep V1's accepted vocabulary
    # unchanged and do not admit annotations on arbitrary nested schemas.
    if depth == 0 and schema is document and document.get('$id') == 'https://apicontour.invalid/spec/v2/batch-v2.schema.json':
        allowed.add('description')
        require(isinstance(schema.get('description'), str), 'invalid V2 description')
    require(not set(schema) - allowed, 'unsupported schema keyword')
    if '$ref' in schema:
        ref = schema['$ref']
        require(ref.startswith('#/$defs/'), 'external reference forbidden')
        schema_check(value, document['$defs'][ref.split('/')[-1]], document, depth+1)
        return
    for union in ('oneOf', 'anyOf'):
        if union in schema:
            matches = 0
            for branch in schema[union]:
                try:
                    schema_check(value, branch, document, depth+1)
                    matches += 1
                except ValueError:
                    pass
            require(matches == 1 if union == 'oneOf' else matches >= 1, union+' mismatch')
    if 'const' in schema:
        require(type(value) is type(schema['const']) and value == schema['const'], 'const mismatch')
    if 'enum' in schema:
        require(value in schema['enum'], 'enum mismatch')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool, 'null': type(None)}
    if 'type' in schema:
        require(type(value) is types[schema['type']], 'type mismatch')
    if isinstance(value, dict):
        require(set(schema.get('required', [])) <= set(value), 'missing required property')
        require(len(value) <= schema.get('maxProperties', float('inf')), 'too many properties')
        properties = schema.get('properties', {})
        for key, item in value.items():
            if 'propertyNames' in schema:
                schema_check(key, schema['propertyNames'], document, depth+1)
            if key in properties:
                schema_check(item, properties[key], document, depth+1)
            else:
                extra = schema.get('additionalProperties', True)
                require(extra is not False, 'unknown property: '+key)
                if isinstance(extra, dict):
                    schema_check(item, extra, document, depth+1)
    if isinstance(value, list):
        require(schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', float('inf')), 'array bound')
        if schema.get('uniqueItems'):
            encoded = [json.dumps(x, sort_keys=True) for x in value]
            require(len(encoded) == len(set(encoded)), 'duplicate array item')
        if 'items' in schema:
            for item in value:
                schema_check(item, schema['items'], document, depth+1)
    if isinstance(value, str):
        require(schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', float('inf')), 'string bound')
        if 'pattern' in schema:
            require(re.search(schema['pattern'], value) is not None, 'pattern mismatch')
        if schema.get('format') == 'date-time':
            date(value)
    if type(value) is int:
        require(schema.get('minimum', -float('inf')) <= value <= schema.get('maximum', float('inf')), 'number bound')


def semantic_check(batch):
    require(len(json.dumps(batch, ensure_ascii=False).encode()) <= 1048576, 'batch bytes')
    ids = [r['record_id'] for r in batch['records']]
    require(len(ids) == len(set(ids)), 'duplicate record ID')
    for record in batch['records']:
        require(date(record['first_seen']) <= date(record['last_seen']), 'time order')
        lifetime = date(record['expires_at']) - date(record['queued_at'])
        require(datetime.timedelta(0) <= lifetime <= datetime.timedelta(hours=24), 'retention deadline')
        require(date(record['queued_at']) <= date(batch['created_at']) <= date(record['expires_at']), 'batch outside record lifetime')
        require(record['sample_numerator'] <= record['sample_denominator'], 'sampling ratio')
        if record['completeness'] == 'complete':
            require(not set(record['reasons']) & {'permission', 'encrypted', 'unsupported', 'limit', 'malformed', 'source_gap'}, 'complete evidence has limiting reason')
        else:
            require(record['reasons'], 'incomplete evidence needs reason')
        if record['visibility'] != 'structure':
            require(record['structure']['kind'] == 'unknown', 'metadata-only visibility has structure')
        require('?' not in record['route_template'] and '#' not in record['route_template'], 'unsafe route syntax')
        require(len(json.dumps(record['structure'], ensure_ascii=False).encode()) <= 65536, 'structure bytes')
        def walk(node, depth=1):
            require(depth <= 32, 'structure depth')
            kind = node['kind']
            if record['completeness'] == 'complete' and kind == 'unknown':
                require(node['reason'] == 'empty', 'complete evidence has incomplete node')
            if kind == 'object':
                for child in node['fields'].values(): walk(child, depth+1)
                if node['additional'] is not None: walk(node['additional'], depth+1)
            elif kind == 'array': walk(node['items'], depth+1)
            elif kind == 'union':
                require(all(x['kind'] != 'union' for x in node['alternatives']), 'nested union')
                for child in node['alternatives']: walk(child, depth+1)
        walk(record['structure'])


def semantic_check_v2(batch):
    """Validate V2 wrappers and then the unchanged V1 record semantics.

    A witness is untrusted data; these syntax checks confer no authority.
    The enclosing JSON loader must already reject duplicate raw keys.
    """
    require(type(batch) is dict and type(batch.get('wire_version')) is int and batch['wire_version'] == 2, 'invalid V2 envelope')
    require(len(json.dumps(batch, ensure_ascii=False).encode()) <= 1048576, 'batch bytes')
    require(type(batch.get('records')) is list and 1 <= len(batch['records']) <= 500, 'V2 record count')
    records = []
    for wrapper in batch['records']:
        require(type(wrapper) is dict and set(wrapper) == {'record','origin_witness'}, 'invalid V2 wrapper')
        witness = wrapper['origin_witness']
        require(type(witness) is dict, 'invalid origin witness')
        kind = witness.get('kind')
        if kind == 'unattributed':
            require(set(witness) == {'kind'}, 'invalid unattributed witness')
        elif kind == 'downstream_mtls_leaf_sha256_v1':
            require(set(witness) == {'kind','leaf_sha256'}, 'invalid leaf witness')
            digest = witness['leaf_sha256']
            require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None, 'invalid leaf digest')
        else:
            raise ValueError('invalid origin witness kind')
        records.append(wrapper['record'])
    semantic_check({'created_at':batch['created_at'], 'records':records})


def batch_v2_regressions(schema, fixtures, legacy_schema, legacy_fixtures):
    """Exercise wrapper rejection and inherited semantic rules on decoded fixtures."""
    valid = next(row['body'] for row in fixtures if row['id'] == 'valid_claim')
    legacy = next(row['body'] for row in legacy_fixtures if row['id'] == 'valid_structure')
    schema_check(legacy, legacy_schema, legacy_schema)
    semantic_check(legacy)

    def rejects(function, value):
        try:
            function(value)
        except ValueError:
            return True
        return False

    for change in ('invalid_digest', 'witness_extra', 'wrapper_extra', 'missing_witness'):
        candidate = copy.deepcopy(valid)
        wrapper = candidate['records'][0]
        if change == 'invalid_digest': wrapper['origin_witness']['leaf_sha256'] = 'g'*64
        elif change == 'witness_extra': wrapper['origin_witness']['verified'] = True
        elif change == 'wrapper_extra': wrapper['verified'] = True
        else: del wrapper['origin_witness']
        require(rejects(lambda value: schema_check(value, schema, schema), candidate), 'V2 schema regression: '+change)
        require(rejects(semantic_check_v2, candidate), 'V2 wrapper regression: '+change)

    v2_duplicate = copy.deepcopy(valid)
    v2_duplicate['records'].append(copy.deepcopy(v2_duplicate['records'][0]))
    schema_check(v2_duplicate, schema, schema)
    require(rejects(semantic_check_v2, v2_duplicate), 'V2 duplicate record ID regression')
    for source, check in ((valid, semantic_check_v2), (legacy, semantic_check)):
        candidate = copy.deepcopy(source)
        record = candidate['records'][0]['record'] if check is semantic_check_v2 else candidate['records'][0]
        record['sample_numerator'] = record['sample_denominator'] + 1
        require(rejects(check, candidate), 'inherited record semantics regression')
    v1_extra = copy.deepcopy(legacy)
    v1_extra['records'][0]['origin_witness'] = {'kind':'unattributed'}
    require(rejects(lambda value: schema_check(value, legacy_schema, legacy_schema), v1_extra), 'V1 witness rejection regression')
    remote = copy.deepcopy(schema)
    remote['$defs']['v2_record']['properties']['record']['$ref'] = 'https://example.invalid/record'
    require(rejects(lambda value: check_references(value, ROOT/'contracts/batch-v2.schema.json'), remote), 'remote reference regression')
    # Duplicate raw JSON keys are rejected by the loader, not JSON Schema.
    class DuplicateInput:
        def read_text(self): return '{"origin_witness":{"kind":"unattributed","kind":"unattributed"}}'
    require(rejects(load, DuplicateInput()), 'duplicate raw key regression')


def canonical(node):
    def string_encode(value):
        parts = ['"']
        for char in value:
            code = ord(char)
            require(not 0xd800 <= code <= 0xdfff, 'unpaired surrogate')
            if code < 32: parts.append('\\u%04x' % code)
            elif char in ('"', '\\'): parts.append('\\'+char)
            else: parts.append(char)
        return ''.join(parts)+'"'
    def write(value):
        if value is None: return 'null'
        if isinstance(value, str): return string_encode(value)
        return '['+','.join(write(x) for x in value)+']'
    def tree(n):
        kind = n['kind']
        if kind == 'object':
            return [kind, [[k, tree(n['fields'][k])] for k in sorted(n['fields'], key=lambda x:x.encode('utf-8'))], tree(n['additional']) if n['additional'] is not None else None]
        if kind == 'array': return [kind, tree(n['items'])]
        if kind == 'unknown': return [kind, n['reason']]
        if kind == 'union':
            alternatives = [tree(x) for x in n['alternatives']]
            return [kind, sorted(alternatives, key=lambda x:write(x).encode('utf-8'))]
        return [kind]
    return write(tree(node))


def check_references(document, path):
    count = 0
    def walk(value):
        nonlocal count
        if isinstance(value, dict):
            if '$ref' in value:
                reference = value['$ref']
                require('://' not in reference, 'remote contract reference')
                file_part, _, fragment = reference.partition('#')
                target = load(path.parent/file_part) if file_part else document
                for token in fragment.strip('/').split('/') if fragment else []:
                    target = target[token.replace('~1', '/').replace('~0', '~')]
                count += 1
            for child in value.values(): walk(child)
        elif isinstance(value, list):
            for child in value: walk(child)
    walk(document)
    return count


def main():
    paths = list(ROOT.rglob('*.json'))
    for path in paths: load(path)
    data = load_traceability()
    groups = {}
    for key in ('requirements', 'phases', 'tasks', 'capabilities', 'acceptance'):
        rows = data[key]
        groups[key] = {r['id']: r for r in rows}
        require(len(groups[key]) == len(rows), 'duplicate ID: '+key)
    requirements, phases, tasks, caps, tests = (groups[k] for k in ('requirements', 'phases', 'tasks', 'capabilities', 'acceptance'))
    require(set(phases) == {f'P{i:02d}' for i in range(16)}, 'missing phase')
    covered = set()
    for task in tasks.values():
        require(task['phase'] in phases, 'unknown phase')
        require(task['id'] in phases[task['phase']]['tasks'], 'task phase mismatch')
        require(task['status'] == 'PENDING', 'spec task claims execution')
        require(task['requirements'] and set(task['requirements']) <= set(requirements), 'invalid requirements')
        covered.update(task['requirements'])
        require(task['acceptance'] and set(task['acceptance']) <= set(tests), 'missing acceptance')
        require(set(task['depends_on']) <= set(tasks), 'unknown dependency')
        for aid in task['acceptance']: require(tests[aid]['task'] == task['id'], 'test ownership mismatch')
    require(covered == set(requirements), 'uncovered requirement')
    visited, active = set(), set()
    def visit(tid):
        require(tid not in active, 'task cycle')
        if tid in visited: return
        active.add(tid)
        for dep in tasks[tid]['depends_on']: visit(dep)
        active.remove(tid); visited.add(tid)
    for tid in tasks: visit(tid)
    for phase in phases.values():
        require(phase['release_required'] is True, 'optional phase')
        require(set(phase['depends_on']) <= set(phases), 'unknown phase dependency')
        for tid in phase['tasks']:
            require(tid in tasks and tasks[tid]['phase'] == phase['id'], 'phase task mismatch')
            for dep in phase['depends_on']:
                require(set(phases[dep]['tasks']) <= set(tasks[tid]['depends_on']), 'missing phase entry dependency')
    required_families = {'gateway','ebpf','browser','android','ios','aws','gcp','azure','messaging','protocols','runtime','serverless','kubernetes','docker','ci','external'}
    require({c['family'] for c in caps.values()} == required_families, 'missing family')
    for cap in caps.values():
        require(cap['required'] is True and cap['status'] == 'NOT_RUN', 'capability scope/status')
        require(cap['task'] in tasks and cap['acceptance'] in tasks[cap['task']]['acceptance'], 'capability test missing')
    for aid, case in tests.items():
        require(case['status'] == 'NOT_RUN', 'spec test claims execution')
        require(case['task'] in tasks and aid in tasks[case['task']]['acceptance'], 'orphan test')
        require(all(case[k].strip() for k in ('setup','action','expected','evidence')), 'empty acceptance criterion')
    links = 0
    for path in ROOT.glob('*.md'):
        text = path.read_text()
        require(text.count('```') % 2 == 0, 'unclosed code fence')
        for ref in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
            if '://' in ref or ref.startswith('#'): continue
            target = path.parent/ref.split('#')[0]
            require(target.exists(), f'broken link: {path.name}: {ref}')
            links += 1
    schema = load(ROOT/'contracts/batch.schema.json')
    fixtures = load(ROOT/'fixtures/batches.json')
    for fixture in fixtures:
        try:
            schema_check(fixture['body'], schema, schema)
            semantic_check(fixture['body'])
            actual = 'accept'
        except ValueError:
            actual = 'reject'
        require(actual == fixture['expected'], 'fixture outcome: '+fixture['id'])
    schema_v2 = load(ROOT/'contracts/batch-v2.schema.json')
    fixtures_v2 = load(ROOT/'fixtures/batches-v2.json')
    for fixture in fixtures_v2:
        try:
            schema_check(fixture['body'], schema_v2, schema_v2)
            semantic_check_v2(fixture['body'])
            actual = 'accept'
        except ValueError:
            actual = 'reject'
        require(actual == fixture['expected'], 'V2 fixture outcome: '+fixture['id'])
    batch_v2_regressions(schema_v2, fixtures_v2, schema, fixtures)
    causal_schema = load(ROOT/'contracts/causal-event-batch.schema.json')
    causal_fixtures = load(ROOT/'fixtures/causal-events.json')
    import hashlib
    for fixture in causal_fixtures:
        try:
            schema_check(fixture['body'], causal_schema, causal_schema)
            causal_semantic_check(fixture['body'])
            actual = 'accept'
        except ValueError:
            actual = 'reject'
        require(actual == fixture['expected'], 'causal fixture outcome: '+fixture['id'])
        if actual == 'accept':
            require(len(fixture['events']) == len(fixture['body']['events']), 'causal event golden count')
            for value, vector, domain in [(fixture['body'], fixture, 'apicontour/causal-events/1')] + [(e, v, 'apicontour/causal-event/1') for e, v in zip(fixture['body']['events'], fixture['events'])]:
                encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                require(encoded.decode() == vector['canonical'] and len(encoded) == vector['bytes'] and hashlib.sha256(domain.encode()+b'\n'+encoded).hexdigest() == vector['sha256'], 'causal golden mismatch')
    envelope_schema = load(ROOT/'contracts/causal-grant-envelope.schema.json')
    schema_check(load(ROOT/'fixtures/causal-grant-envelope.json'), envelope_schema, envelope_schema)
    grant_schema = load(ROOT/'contracts/causal-grant.schema.json')
    for fixture in load(ROOT/'fixtures/causal-grants.json'):
        try:
            schema_check(fixture['body'], grant_schema, grant_schema)
            causal_grant_semantic_check(fixture['body'])
            actual = 'accept'
        except ValueError:
            actual = 'reject'
        require(actual == fixture['expected'], 'causal grant fixture outcome: '+fixture['id'])
    goldens = load(ROOT/'fixtures/canonical.json')
    for fixture in goldens:
        schema_check(fixture['node'], {'$ref':'#/$defs/node'}, schema)
        require(canonical(fixture['node']) == fixture['canonical'], 'canonical vector: '+fixture['id'])
    reference_count = 0
    for path in (ROOT/'contracts').rglob('*.json'):
        reference_count += check_references(load(path), path)
    api = load(ROOT/'contracts/platform.openapi.json')
    operations = []
    for path, methods in api['paths'].items():
        if '$ref' in methods:
            methods = resolve_local(methods['$ref'], ROOT/'contracts/platform.openapi.json')
        for method, operation in methods.items():
            require(method in {'get','post','put','patch','delete'}, 'invalid API method')
            require(operation.get('security') and operation.get('responses'), 'missing API security/response')
            operations.append(operation['operationId'])
            if '{id}' in path:
                require(any(p['name'] == 'id' and p['in'] == 'path' and p['required'] for p in operation.get('parameters', [])), 'missing API path parameter')
    require(len(operations) == len(set(operations)), 'duplicate operation ID')
    # Regression checks for the dependencies found during independent review.
    for tid, prerequisites in {'P01-03':['P01-04'], 'P03-03':['P03-01','P03-02'], 'P06-03':['P06-01','P06-02'], 'P06-04':['P06-03'], 'P14-04':['P14-01','P14-02','P14-03']}.items():
        for prerequisite in prerequisites:
            completed = set(tasks) - {tid, prerequisite}
            require(not set(tasks[tid]['depends_on']) <= completed, 'premature task readiness: '+tid)
    print(json.dumps({'status':'PASS','scope':'Offline specification links, traceability, DAG and local schema-subset/semantic fixture checks only','json_files':len(paths),'local_links':links,'requirements':len(requirements),'phases':len(phases),'tasks':len(tasks),'capabilities':len(caps),'acceptance_cases':len(tests),'batch_fixtures':len(fixtures),'batch_v2_fixtures':len(fixtures_v2),'canonical_vectors':len(goldens),'local_contract_references':reference_count,'api_operations':len(operations),'product_acceptance':'NOT_RUN','full_schema_standard_validation':'NOT_RUN','full_openapi_standard_validation':'NOT_RUN'},indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print('FAIL: '+str(exc), file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Offline checks for this specification, not a product acceptance runner.

The schema interpreter supports only the vocabulary used in batch.schema.json.
It rejects unknown keywords. It is not a full JSON Schema conformance validator.
"""
import datetime
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
    print(json.dumps({'status':'PASS','scope':'Offline specification links, traceability, DAG and local schema-subset/semantic fixture checks only','json_files':len(paths),'local_links':links,'requirements':len(requirements),'phases':len(phases),'tasks':len(tasks),'capabilities':len(caps),'acceptance_cases':len(tests),'batch_fixtures':len(fixtures),'canonical_vectors':len(goldens),'local_contract_references':reference_count,'api_operations':len(operations),'product_acceptance':'NOT_RUN','full_schema_standard_validation':'NOT_RUN','full_openapi_standard_validation':'NOT_RUN'},indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print('FAIL: '+str(exc), file=sys.stderr)
        sys.exit(1)

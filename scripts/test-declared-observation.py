"""Actual accepted observation -> catalog reader -> checked declared comparison."""
import copy
import json
from pathlib import Path
import subprocess


def run_cases(execute, setup, submit, consume, read, items, target):
    def obj(fields=None, extra=None):
        return dict(kind='object', fields=fields or {}, additional=extra)

    def decl_obj(fields=None, additional='allowed'):
        return dict(kind='object', fields=fields or {}, additional=additional)

    string, integer = {'kind': 'string'}, {'kind': 'integer'}
    unknown = lambda reason: dict(kind='unknown', reason=reason)
    scenarios = {}

    def add(label, shape, **metadata):
        scenarios[label] = (shape, metadata)
        return label

    add('empty', obj())
    add('partial', obj(), completeness='partial', reasons=['limit'])
    add('sampled', obj(), sample_denominator=97, reasons=['sampled'])
    add('route', obj(), route_uncertain=True)
    for reason, completeness in [('encrypted', 'unavailable'), ('limit', 'partial'), ('unsupported', 'unavailable')]:
        add(reason, unknown(reason), completeness=completeness, reasons=[reason],
            visibility='connection' if completeness == 'unavailable' else 'structure')
    for kind in ['string', 'integer', 'number', 'null', 'boolean']:
        add(kind, dict(kind=kind))
    add('nullable', dict(kind='union', alternatives=[{'kind': 'null'}, string]))
    add('union', dict(kind='union', alternatives=[integer, string]))
    add('uncertain_union', dict(kind='union', alternatives=[string, unknown('encrypted')]), completeness='partial', reasons=['encrypted'])
    add('field', obj({'a': string}))
    add('extra', obj({'a': string, 'extra': integer}))
    add('unnamed', obj({}, integer))
    add('empty_array', dict(kind='array', items=unknown('empty')))
    add('extra_unknown', obj({'extra': dict(kind='array', items=unknown('empty'))}))
    add('nested', obj({'a': obj({'a': string})}))
    add('repeat', obj({'a': integer, 'b': integer}))
    tricky = ['雪', 'nul\x00name', '/', '~', '*', 'items', 'additional', '$']
    add('paths', obj({name: string for name in tricky}))

    def nested(levels, leaf, name):
        for _ in range(levels): leaf = obj({name: leaf})
        return leaf

    add('path_safe', nested(14, string, 'x' * 64))
    add('path_over', nested(15, string, 'x' * 64))
    prefix = '雪' * 64

    def aggregate(count, leaf):
        groups = {'g%d' % group: obj({'f%03d' % index: leaf for index in range(min(256, count-group*256))})
                  for group in range((count+255)//256)}
        return nested(12, obj(groups), prefix)

    add('aggregate_safe', aggregate(432, string))
    add('aggregate_over', aggregate(433, string))
    add('work_safe', obj({'n%03d' % i: string for i in range(126)}))
    add('work_over', obj({'n%03d' % i: string for i in range(127)}))
    add('differences', obj({'g%02d' % i: obj() for i in range(40)}))

    def names(shape):
        found = set(shape.get('fields', {}))
        for child in shape.get('fields', {}).values(): found.update(names(child))
        for key in ['items', 'additional']:
            if shape.get(key) is not None: found.update(names(shape[key]))
        for child in shape.get('alternatives', []): found.update(names(child))
        return found

    approved = sorted(set().union(*(names(shape) for shape, _ in scenarios.values())) | {'DELETE'})
    body, _, _ = setup('declared_observation', lambda p: p.update(approved_names=sorted(set(p['approved_names'] + approved))), current=1)
    original = body['records'][0]
    expected, labels, batches = {}, {}, {}
    # Small real accepted batches bound fixture preparation without altering runtime deadlines.
    records = []
    for index, (label, (shape, metadata)) in enumerate(scenarios.items()):
        record = copy.deepcopy(original)
        record.update(record_id='00000000-0000-4000-8000-%012x' % (0xd030000 + index),
                      structure=shape, operation='DELETE', direction='response', status_code=200,
                      route_uncertain=False, completeness='complete', visibility='structure',
                      reasons=[], sample_numerator=1, sample_denominator=1, count=1)
        record.update(metadata)
        records.append(record); labels[label] = record['record_id']; expected[record['record_id']] = record
    for offset in range(0, len(records), 16):
        batch = copy.deepcopy(body)
        batch.update(batch_id='00000000-0000-4000-8000-%012x' % (0xd040000 + offset), records=records[offset:offset+16])
        submit(batch, status='accepted', compact_utf8=True)
        consume(batch)
        for record in batch['records']: batches[record['record_id']] = batch['batch_id']
    operation_id = execute("SELECT operation_id::text FROM contour.observation_windows WHERE tenant_id='%s' AND collector_id='%s' LIMIT 1;" % (body['tenant_id'], body['collector_id']))
    scope = [body['tenant_id'], original['project_id'], original['service_id'], operation_id]
    loaded = [item for item in items(read(limit=200, selected=scope)) if item['collector_id'] == body['collector_id']]
    assert len(loaded) == len(expected)
    observations = {}
    for item in loaded:
        record = item['record']; key = record['record_id']
        assert record == expected[key] and item['batch_id'] == batches[key], 'persisted comparison evidence changed'
        observations[key] = dict(wire_version=1, tenant_id=body['tenant_id'], collector_id=body['collector_id'],
                                 batch_id=item['batch_id'], created_at=record['queued_at'], records=[record])
    operation = [body['tenant_id'], original['project_id'], original['service_id'], original['environment_id'], 'http', 'response', 'DELETE', original['route_template']]

    def model(schema, definitions=None):
        nodes = []

        def build(value):
            kind = value['kind']; node = dict(kind=kind, omissions=value.get('omissions', []))
            if kind == 'object':
                node['properties'] = [dict(name=name, required=required, target=build(child))
                                      for name, (required, child) in sorted(value.get('fields', {}).items())]
                additional = value.get('additional', 'allowed')
                node['additional'] = additional if isinstance(additional, str) else dict(schema=build(additional))
            elif kind == 'array': node['items'] = build(value['items'])
            elif kind == 'union': node['alternatives'] = [build(child) for child in value['alternatives']]
            elif kind == 'reference': node['reference'] = value['reference']
            elif kind == 'unknown': node['reason'] = value['reason']
            node['id'] = len(nodes); nodes.append(node)
            return node['id']
        root = build(schema)
        defs = [dict(name=name, target=build(value)) for name, value in sorted((definitions or {}).items())]
        return dict(version=1, operation=operation, root=root, nodes=nodes, definitions=defs,
                    omissions=sorted({omission for node in nodes for omission in node['omissions']}))

    def compare(declared, label):
        payload = dict(declared=declared, observed=observations[labels[label]])
        process = subprocess.run([str(Path(target) / 'debug/examples/declared_comparison_probe')],
                                 input=json.dumps(payload, ensure_ascii=False, separators=(',', ':')),
                                 capture_output=True, text=True, timeout=5)
        assert process.returncode == 0 and not process.stderr, 'declared comparison process rejected checked input'
        return json.loads(process.stdout)

    def differences(declared, label):
        result = compare(declared, label)
        assert result.get('compatibility') == 'Inconclusive', 'observed absence became a declared compatibility verdict'
        assert result == compare(declared, label), 'declared comparison result changed on replay'
        return result['differences']

    def pairs(result): return [(d['path'], d['kind']) for d in result]

    required = model(decl_obj({'a': (True, string), 'optional': (False, string)}))
    for label in ['empty', 'partial', 'sampled', 'route']:
        result = differences(required, label)
        assert ('#/fields/a', 'RequiredFieldNotObserved') in pairs(result)
        assert not any(d['path'].endswith('/optional') for d in result)
        assert not any(d['kind'] in ('RequirednessChanged', 'ContractRemoved') for d in result)
        assert (('#', 'InsufficientEvidence') in pairs(result)) == (label != 'empty')
    assert differences(required, 'field') == []
    for label in ['encrypted', 'limit', 'unsupported']:
        result = differences(required, label)
        assert any(d['observed_unknown'] == label.capitalize() for d in result)
        assert not any(d['kind'] == 'RequiredFieldNotObserved' for d in result)
    assert differences(model({'kind': 'number'}), 'integer') == []
    assert pairs(differences(model(integer), 'number')) == [('#', 'TypeMismatch')]
    assert pairs(differences(model(string), 'null')) == [('#', 'NullNotDeclared')]
    nullable = model(dict(kind='union', alternatives=[dict(kind='null'), string]))
    assert differences(nullable, 'null') == [] and differences(nullable, 'nullable') == []
    assert pairs(differences(model(string), 'nullable')) == [('#', 'NullNotDeclared')]
    nullable_unknown = model(dict(kind='union', alternatives=[dict(kind='null'), unknown('unspecified')]))
    result = differences(nullable_unknown, 'string')
    assert pairs(result) == [('#', 'InsufficientEvidence')]
    assert result[0]['declared_unknown'] == 'Unspecified'
    assert pairs(differences(model(dict(kind='null')), 'string')) == [('#', 'TypeMismatch')]
    for additional in ['allowed', 'forbidden', integer, string]:
        declared = model(decl_obj({'a': (True, string)}, additional))
        result = pairs(differences(declared, 'extra'))
        wanted = [] if additional in ['allowed', integer] else [('#/fields/extra', 'UndeclaredFieldObserved' if additional == 'forbidden' else 'TypeMismatch')]
        assert result == wanted
        unnamed = differences(declared, 'unnamed')
        assert ('#/additional', 'InsufficientEvidence') in pairs(unnamed)
        assert not any(d['kind'] == 'UndeclaredFieldObserved' for d in unnamed)
    result = differences(model(decl_obj(additional='allowed')), 'extra_unknown')
    assert pairs(result) == [('#/fields/extra/items', 'InsufficientEvidence')]
    assert result[0]['observed_unknown'] == 'Empty', 'allowed extra hid nested unknown evidence'
    result = differences(model(dict(kind='array', items=string)), 'empty_array')
    assert any(d['path'] == '#/items' and d['observed_unknown'] == 'Empty' for d in result)
    for reason in ['unspecified', 'omitted', 'unsupported']:
        omissions = [] if reason == 'unspecified' else ['removed_value' if reason == 'omitted' else 'unsupported_construct']
        result = differences(model(dict(kind='unknown', reason=reason, omissions=omissions)), 'field')
        assert any(d['declared_unknown'] == reason.capitalize() for d in result)
    general = model(dict(kind='union', alternatives=[integer, string]))
    assert ('#', 'UnsupportedConstruct') in pairs(differences(general, 'string'))
    result = differences(model(string), 'uncertain_union')
    assert any(d['kind'] == 'InsufficientEvidence' and d['observed_unknown'] == 'Encrypted' for d in result)
    assert not any(d['kind'] == 'NullNotDeclared' for d in result)
    ref = lambda name: dict(kind='reference', reference=name)
    recursive = model(ref('self'), {'self': decl_obj({'a': (False, ref('self'))})})
    assert ('#/fields/a/fields/a', 'TypeMismatch') in pairs(differences(recursive, 'nested'))
    mutual = model(ref('one'), {'one': decl_obj({'a': (False, ref('two'))}), 'two': decl_obj({'a': (False, ref('one'))})})
    assert ('#/fields/a/fields/a', 'TypeMismatch') in pairs(differences(mutual, 'nested'))
    cycle = model(ref('one'), {'one': ref('two'), 'two': ref('one')})
    assert ('#', 'InsufficientEvidence') in pairs(differences(cycle, 'string'))
    nullable_cycle = model(dict(kind='union', alternatives=[dict(kind='null'), ref('one')]),
                           {'one': ref('two'), 'two': ref('one')})
    assert pairs(differences(nullable_cycle, 'string')) == [('#', 'UnsupportedConstruct')]
    repeated = model(decl_obj({'a': (True, ref('s')), 'b': (True, ref('s'))}), {'s': string})
    assert pairs(differences(repeated, 'repeat')) == [('#/fields/a', 'TypeMismatch'), ('#/fields/b', 'TypeMismatch')]
    escaped = model(decl_obj({name: (False, integer) for name in tricky}))
    assert [d['path'] for d in differences(escaped, 'paths')] == ['#/fields/' + n.replace('~', '~0').replace('/', '~1') for n in sorted(tricky, key=lambda n: n.encode())]
    for index, value in [(0, '00000000-0000-4000-8000-000000000fff'), (1, '00000000-0000-4000-8000-000000000fff'),
                         (2, '00000000-0000-4000-8000-000000000fff'), (3, '00000000-0000-4000-8000-000000000fff'),
                         (4, 'graphql'), (5, 'request'), (6, 'PUT'), (7, '/other')]:
        other = copy.deepcopy(required); other['operation'][index] = value
        assert compare(other, 'field') == dict(error='OperationScope'), 'declared operation scope mismatch accepted'

    def as_declared(shape, leaf=integer):
        if shape['kind'] != 'object': return leaf
        return decl_obj({name: (False, as_declared(child, leaf)) for name, child in shape['fields'].items()})
    assert len(differences(model(as_declared(scenarios['path_safe'][0])), 'path_safe')) == 1
    assert compare(model(as_declared(scenarios['path_over'][0])), 'path_over') == dict(error='PathLimit')
    safe = differences(model(as_declared(scenarios['aggregate_safe'][0])), 'aggregate_safe')
    assert len(safe) == 432 and sum(len(d['path'].encode()) for d in safe) == 1046736
    assert compare(model(as_declared(scenarios['aggregate_over'][0])), 'aggregate_over') == dict(error='PathLimit')
    definitions = {'s%d' % i: ref('s%d' % (i+1)) for i in range(255)}
    definitions['s255'] = string
    for label, valid in [('work_safe', True), ('work_over', False)]:
        declared = model(decl_obj({name: (False, ref('s0')) for name in scenarios[label][0]['fields']}), definitions)
        if valid: assert differences(declared, label) == []
        else: assert compare(declared, label) == dict(error='WorkLimit')
    # Root costs2; each of127 fields costs259 with the full reference chain.
    # Shortening one chain by127 or126 visits reaches32768 or32769 exactly.
    for start, valid in [(127, True), (126, False)]:
        fields = {name: (False, ref('s%d' % start if name == 'n126' else 's0'))
                  for name in scenarios['work_over'][0]['fields']}
        declared = model(decl_obj(fields), definitions)
        if valid: assert differences(declared, 'work_over') == []
        else: assert compare(declared, 'work_over') == dict(error='WorkLimit')
    for count in [10000, 10001]:
        # Shared scalar target keeps node/edge/output limits independent of findings.
        graph = dict(version=1, operation=operation, root=0, definitions=[], omissions=[], nodes=[
            dict(id=0, kind='object', omissions=[], additional='allowed', properties=[
                dict(name='g%02d' % group, required=False, target=group+2) for group in range(40)]),
            dict(id=1, kind='string', omissions=[])])
        for group in range(40):
            amount = 250 + int(count == 10001 and group == 39)
            graph['nodes'].append(dict(id=group+2, kind='object', omissions=[], additional='allowed', properties=[
                dict(name='f%03d' % i, required=True, target=1) for i in range(amount)]))
        if count == 10000: assert len(differences(graph, 'differences')) == count
        else: assert compare(graph, 'differences') == dict(error='DifferenceLimit')
    assert [item for item in items(read(limit=200, selected=scope)) if item['collector_id'] == body['collector_id']] == loaded
    print('Persisted observation versus checked declared graph: inconclusive absence, types, nulls, omissions, cycles, scope and limits passed', flush=True)

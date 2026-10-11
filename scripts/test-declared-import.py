"""Executable selected import -> independent checked declared codec reload."""
import copy
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 5 * 1024 * 1024


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def document(schema, definitions=None):
    body = {'content': {'application/json': {'schema': schema}}}
    return {'openapi': '3.0.3', 'paths': {'/source': {'post': {
        'requestBody': body, 'responses': {'200': copy.deepcopy(body)}}}},
        'components': {'schemas': definitions or {}}}


def main():
    subprocess.run(['cargo', 'build', '-p', 'contour-core', '--example', 'import_probe',
                    '--example', 'declared_probe', '--locked', '--offline'],
                   cwd=ROOT, check=True, capture_output=True, timeout=180)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1',
                                                '--no-deps', '--offline'], cwd=ROOT, timeout=15))
    examples = Path(metadata['target_directory']) / 'debug/examples'
    count = 0

    def check(value, valid=True, names=('a', 'b', 'c', 'd'), direction='request',
              status='-', method='POST', path='/source', media='application/json', fmt='openapi_json', error=None):
        nonlocal count
        count += 1
        raw = value if isinstance(value, bytes) else compact(value)
        result = subprocess.run([str(examples / 'import_probe'), fmt, direction, method, path,
                                 media, status, ','.join(names)], input=raw, capture_output=True, timeout=5)
        if not valid:
            assert result.returncode == 1 and not result.stdout, 'import invalid case accepted (%d)' % count
            assert result.stderr.strip() in (b'Size', b'Invalid', b'UnsupportedFormat', b'Selection',
                                             b'Reference', b'Name', b'Graph'), 'unsafe import error'
            if error is not None: assert result.stderr.strip() == error, 'wrong import failure boundary'
            return None
        assert result.returncode == 0 and not result.stderr, 'import valid case rejected (%d)' % count
        reload = subprocess.run([str(examples / 'declared_probe')], input=result.stdout,
                                capture_output=True, timeout=5)
        assert reload.returncode == 0 and not reload.stderr and reload.stdout == result.stdout, 'import reload mismatch'
        output = json.loads(result.stdout)
        assert output['operation'][-4:] == ['http', direction, method, '/orders']
        return output, result.stdout

    def root(model):
        return next(n for n in model['nodes'] if n['id'] == model['root'])

    scalar = document({'type': 'string'})
    check(scalar)
    for fmt in ('asyncapi_json', 'graphql_sdl', 'protobuf_descriptor', 'unknown'):
        check(scalar, False, fmt=fmt)
    for override in ({'path': '/missing'}, {'media': 'text/plain'}, {'method': 'GET'},
                     {'direction': 'response'}, {'status': '200'}, {'direction': 'response', 'status': '404'}):
        check(scalar, False, **override)
    check(scalar, direction='response', status='200')
    for version in ('3.0.2', '3.1.0', 3):
        invalid = copy.deepcopy(scalar); invalid['openapi'] = version
        check(invalid, False)
    check(b'{"openapi":"3.0.3","openapi":"3.0.3"}', False)
    check(compact(scalar).replace(b'"type":"string"', b'"type":"string","type":"string"'), False)
    # Duplicate detection applies after JSON escape decoding, not only raw key bytes.
    check(compact(scalar).replace(b'"type":"string"',
                                 b'"type":"string","' + b'\\u0074ype":"integer"'), False, error=b'Invalid')
    check(compact(scalar) + b' {}', False, error=b'Invalid')
    schema = {'type': 'object', 'required': ['a', 'b'], 'properties': {
        'a': {'type': 'string'}, 'b': {'type': 'string', 'nullable': True},
        'c': {'type': 'string', 'default': 'VALUE_SENTINEL'}, 'd': {'type': 'string', 'nullable': True}}}
    model, _ = check(document(schema))
    props = {p['name']: p for p in root(model)['properties']}
    kinds = {n['id']: n['kind'] for n in model['nodes']}
    assert [props[n]['required'] for n in 'abcd'] == [True, True, False, False]
    assert [kinds[props[n]['target']] for n in 'abcd'] == ['string', 'union', 'string', 'union']
    for additional, expected in ((None, 'allowed'), (True, 'allowed'), (False, 'forbidden'), ({'type': 'integer'}, 'schema')):
        value = {'type': 'object'}
        if additional is not None: value['additionalProperties'] = additional
        model, _ = check(document(value))
        actual = root(model)['additional']
        assert actual == expected if expected != 'schema' else set(actual) == {'schema'}
    for read, write in ((True, False), (False, True), (False, False)):
        child = {'type': 'string', 'readOnly': read, 'writeOnly': write}
        schema = {'type': 'object', 'properties': {'a': child}, 'required': ['a']}
        for response in (False, True):
            model, _ = check(document(schema), direction='response' if response else 'request', status='200' if response else '-')
            assert root(model)['properties'][0]['required'] == (not (read and not response or write and response))
    check(document({'type': 'string', 'readOnly': True, 'writeOnly': True}), False)
    definitions = {'SOURCE_SENTINEL': {'type': 'object', 'properties': {'a': {'$ref': '#/components/schemas/SOURCE_SENTINEL'}}}}
    model, wire = check(document({'$ref': '#/components/schemas/SOURCE_SENTINEL'}, definitions))
    assert len(model['definitions']) == 1 and b'SOURCE_SENTINEL' not in wire
    definitions['SOURCE_SENTINEL']['properties']['a'] = {'$ref': '#/components/schemas/Other'}
    definitions['Other'] = {'$ref': '#/components/schemas/SOURCE_SENTINEL'}
    model, _ = check(document({'$ref': '#/components/schemas/Other'}, definitions))
    assert len(model['definitions']) == 2
    for pointer in ('https://example.invalid/schema', 'file:///tmp/schema', '#/missing', '#/components/schemas/missing', '#/components/schemas/bad~2'):
        check(document({'$ref': pointer}), False)
    # An external base must not be discarded even when its fragment resolves locally.
    check(document({'$ref': 'https://example.invalid/api#/components/schemas/Known'},
                   {'Known': {'type': 'string'}}), False, error=b'Reference')
    model, _ = check(document({'$ref': '#/components/schemas/a~1b~0c'}, {'a/b~c': {'type': 'integer'}}))
    assert any(n['kind'] == 'integer' for n in model['nodes'])
    schema = {'type': 'object', 'required': ['a'], 'properties': {'a': {'$ref': '#/components/schemas/Read', 'readOnly': False}}}
    model, _ = check(document(schema, {'Read': {'type': 'string', 'readOnly': True}}))
    assert not root(model)['properties'][0]['required']
    # Reach the external reference through each supported schema entry path.
    external = {'Bridge': {'$ref': 'https://REF_SENTINEL.invalid/schema'}}
    for body in (
            {'type': 'object', 'properties': {'a': {'$ref': '#/components/schemas/Bridge'}}},
            {'type': 'object', 'additionalProperties': {'$ref': '#/components/schemas/Bridge'}}):
        check(document(body, external), False, error=b'Reference')
    check(document(schema, {'Read': {'type': 'string', 'readOnly': True, 'writeOnly': True}}),
          False, error=b'Invalid')
    # Source definition labels may be long, but must never become output names.
    long_name = 'LONG_REF_SENTINEL_' + 'x' * 262144
    long_body = {'type': 'object', 'properties': {
        n: {'$ref': '#/components/schemas/' + long_name} for n in ('a', 'b')}}
    model, wire = check(document(long_body, {long_name: {'type': 'string'}}))
    assert len(model['definitions']) == 1 and b'LONG_REF_SENTINEL_' not in wire
    check(document(long_body, {long_name + 'missing': {'type': 'string'}}), False, error=b'Reference')
    for key in ('description', 'example', 'default', 'enum', 'pattern', 'x-private'):
        model, wire = check(document({'type': 'string', key: 'VALUE_SENTINEL'}))
        assert b'VALUE_SENTINEL' not in wire and 'removed_value' in model['omissions']
    for keyword in ('allOf', 'oneOf', 'anyOf', 'not'):
        model, _ = check(document({keyword: [{'type': 'string'}]}))
        assert root(model)['kind'] == 'unknown' and root(model)['reason'] == 'unsupported'
        assert 'unsupported_construct' in model['omissions']
    model, _ = check(document({'nullable': True}))
    assert root(model)['reason'] == 'unspecified'
    check(document({'type': 'array'}), False)
    check(document({'type': 'array', 'items': {'type': 'integer'}}))
    check(document({'type': 'object', 'properties': {'unsafe': {'type': 'string'}}}), False)
    for required in ([], ['a', 'a'], ['missing']):
        check(document({'type': 'object', 'properties': {'a': {'type': 'string'}}, 'required': required}), False)
    ordered = document({'type': 'object', 'properties': {'a': {'type': 'integer'}, 'b': {'type': 'string'}}})
    _, first = check(ordered)
    reordered = json.loads(json.dumps(ordered, sort_keys=True))
    assert check(reordered)[1] == first
    for length in (64, 65):
        name = 'n' * length
        check(document({'type': 'object', 'properties': {name: {'type': 'string'}}}), length == 64, names=(name,))
    for length in (256, 257):
        names = tuple('n%d' % n for n in range(length))
        check(document({'type': 'object', 'properties': {n: {'type': 'string'} for n in names}}), length == 256, names=names)
    # Byte bound includes ignored source data. Exact input limit succeeds.
    raw = compact(scalar)
    check(raw + b' ' * (LIMIT - len(raw)))
    check(raw + b' ' * (LIMIT + 1 - len(raw)), False)
    # Root=0, filler child=1; inner primitive depths64/65 form the exact pair.
    for depth in (63, 64):
        extra = copy.deepcopy(scalar)
        extra['x-depth'] = json.loads('[' * depth + 'null' + ']' * depth)
        check(extra, depth == 63)
    # Count includes map keys and values. The scalar document uses a measured formula.
    def values(v):
        if isinstance(v, dict): return 1 + sum(1 + values(x) for x in v.values())
        if isinstance(v, list): return 1 + sum(values(x) for x in v)
        return 1
    for limit in (65536, 65537):
        extra = copy.deepcopy(scalar); extra['x-count'] = []
        extra['x-count'] = [None] * (limit - values(extra))
        check(extra, limit == 65536)
    # Reference chain is memoized; definition257 fails without expansion.
    for count_defs in (256, 257):
        defs = {'s%d' % i: {'$ref': '#/components/schemas/s%d' % (i + 1)} for i in range(count_defs - 1)}
        defs['s%d' % (count_defs - 1)] = {'type': 'string'}
        check(document({'$ref': '#/components/schemas/s0'}, defs), count_defs == 256)
    # Repeated aliases must charge directional flag resolution to the visit budget.
    # 126 traversals of256 definitions, one plain property and scalar additional
    # schema require32768 visits. Wrapping that scalar in an array requires32769.
    defs = {'s%d' % i: {'$ref': '#/components/schemas/s%d' % (i + 1)} for i in range(255)}
    defs['s255'] = {'type': 'string'}
    names = tuple('n%d' % i for i in range(126)) + ('plain',)
    properties = {n: {'$ref': '#/components/schemas/s0'} for n in names[:-1]}
    properties['plain'] = {'type': 'string'}
    for extra, valid in (({'type': 'integer'}, True),
                         ({'type': 'array', 'items': {'type': 'integer'}}, False)):
        body = {'type': 'object', 'properties': properties, 'additionalProperties': extra}
        check(document(body, defs), valid, names=names, error=None if valid else b'Graph')
    # Unsupported composition is opaque: no fetch, source string or compatibility claim.
    model, wire = check(document({'allOf': [{'$ref': 'https://REFERENCE_SENTINEL.invalid'}]}))
    assert root(model)['reason'] == 'unsupported' and b'REFERENCE_SENTINEL' not in wire
    # Exactly4096/4097 emitted nodes, independent of parser element bounds.
    names = tuple('n%d' % i for i in range(255))
    for total in (4096, 4097):
        groups = {'n%d' % i: {'type': 'object', 'properties': {
            n: {'type': 'string'} for n in names}} for i in range(16)}
        if total == 4096: del groups['n0']['properties']['n0']
        model = check(document({'type': 'object', 'properties': groups}), total == 4096, names=names)
        if model: assert len(model[0]['nodes']) == total
    # Same graph and scalar-name limit; UTF-8 expansion crosses the output byte limit.
    for width, valid in ((24, True), (60, False)):
        names = tuple('😀' * width + ('%03d' % i) for i in range(200))
        child = {'type': 'object', 'properties': {n: {'type': 'string'} for n in names}}
        graph = {'type': 'object', 'properties': {n: child for n in names[:16]}}
        check(document(graph), valid, names=names)
    print('PASS declared importer: %d executable cases; independent model reload, selectors, cycles, omissions and bounds' % count)


if __name__ == '__main__':
    main()

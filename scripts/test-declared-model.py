"""Actual declared codec process: independent graph assertions, limits and cycles."""
import copy
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1048576
UUID = '00000000-0000-0000-0000-000000000001'
OPERATION = [UUID]*4 + ['http','request','GET','/orders']


def node(identifier, kind='string', **fields):
    return dict(id=identifier,kind=kind,omissions=[],**fields)


def document(nodes=None, **fields):
    return dict(version=1,operation=OPERATION,root=0,nodes=nodes or [node(0)],definitions=[],omissions=[],**fields)


def compact(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()


def main():
    subprocess.run(['cargo','build','-p','contour-core','--example','declared_probe','--locked','--offline'],cwd=ROOT,check=True,timeout=180,capture_output=True)
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],cwd=ROOT,timeout=15))
    probe=Path(metadata['target_directory'])/'debug/examples/declared_probe'
    count=0
    def check(value, valid=True, expected=None):
        nonlocal count
        raw=value if isinstance(value,bytes) else compact(value)
        result=subprocess.run([str(probe)],input=raw,capture_output=True,timeout=3)
        count+=1
        if valid:
            assert result.returncode==0 and not result.stderr, 'declared valid case rejected (%d)' % count
            assert len(result.stdout)<=LIMIT
            decoded=json.loads(result.stdout)
            if expected is not None: assert decoded==expected,'declared semantic evidence changed'
            again=subprocess.run([str(probe)],input=result.stdout,capture_output=True,timeout=3)
            assert again.returncode==0 and again.stdout==result.stdout,'declared bytes not idempotent'
            return decoded,result.stdout
        assert result.returncode==1 and not result.stdout,'declared invalid case accepted (%d)' % count
        assert result.stderr.strip() in [b'Size',b'Invalid',b'Duplicate',b'Reference',b'Edges',b'Cycle',b'Operation',b'Omissions'], 'unbounded diagnostic'
        return None

    # Four independent requiredness/nullability combinations retain exact intent.
    graph=document([node(0,'object',properties=[
        dict(name='required_plain',required=True,target=1),dict(name='optional_plain',required=False,target=1),
        dict(name='required_nullable',required=True,target=3),dict(name='optional_nullable',required=False,target=3)],additional='forbidden'),
        node(1),node(2,'null'),node(3,'union',alternatives=[2,1])])
    decoded,wire=check(graph)
    props={item['name']:item for item in decoded['nodes'][0]['properties']}
    assert props['required_plain']['required'] and not props['optional_plain']['required']
    assert props['required_nullable']['target']==3 and props['optional_nullable']['target']==3
    assert decoded['nodes'][3]['alternatives']==[1,2]
    shuffled=copy.deepcopy(graph);shuffled['nodes'].reverse();shuffled['nodes'][-1]['properties'].reverse()
    assert check(shuffled)[1]==wire,'graph order changes deterministic bytes'
    for policy in ['allowed','forbidden',{'schema':1}]:
        value=copy.deepcopy(graph);value['nodes'][0]['additional']=policy;check(value)
    value=copy.deepcopy(graph);value['nodes'].append(node(4,'array',items=3));value['root']=4;check(value)
    for direction in ['request','response','publish','consume','operation','connection']:
        value=document();value['operation']=OPERATION.copy();value['operation'][5]=direction;check(value)
    for direction in ['inbound','outbound','REQUEST','']:
        value=document();value['operation']=OPERATION.copy();value['operation'][5]=direction;check(value,False)
    for kind in ['boolean','integer','number','binary','null']:
        check(document([node(0,kind)]))

    recursive=document([node(0,'object',properties=[dict(name='next',required=False,target=1)],additional='forbidden'),node(1,'reference',reference='Root')])
    recursive['definitions']=[dict(name='Root',target=0)]
    assert check(recursive)[0]==recursive,'named recursion was expanded or changed'
    self_ref=document([node(0,'reference',reference='Self')]);self_ref['definitions']=[dict(name='Self',target=0)];check(self_ref)
    mutual=document([node(0,'reference',reference='Right'),node(1,'reference',reference='Left')])
    mutual['definitions']=[dict(name='Left',target=0),dict(name='Right',target=1)]
    assert check(mutual)[0]==mutual,'mutual named references expanded or changed'
    check(document([node(0,'array',items=0)]),False)
    check(document([node(0,'array',items=1),node(1,'array',items=0)]),False)
    for reason,omission in [('omitted','removed_value'),('unsupported','unsupported_construct')]:
        value=document([dict(node(0,'unknown',reason=reason),omissions=[omission])]);value['omissions']=[omission]
        check(value,expected=value)
        value['omissions']=[];check(value,False)
        value['nodes'][0]['omissions']=[];check(value,False)
    check(document([node(0,'unknown',reason='unspecified')]))
    warned=copy.deepcopy(graph);warned['nodes'][1]['omissions']=['removed_value'];warned['omissions']=['removed_value'];check(warned,expected={**warned,'nodes':decoded['nodes'][:1]+warned['nodes'][1:3]+[decoded['nodes'][3]]})
    for mutation in [lambda d:d.update(root=99),lambda d:d['nodes'].append(node(0)),lambda d:d['nodes'][0].update(kind='url'),lambda d:d['nodes'][0].update(example='SYNTHETIC_SECRET'),lambda d:d.update(url='SYNTHETIC_SECRET'),lambda d:d.update(omissions=['removed_value']),lambda d:d['nodes'][0].update(omissions=['removed_value','removed_value'])]:
        value=document();mutation(value);check(value,False)
    value=copy.deepcopy(recursive);value['definitions']=[];check(value,False)
    value=copy.deepcopy(recursive);value['definitions'][0]['target']=99;check(value,False)
    value=copy.deepcopy(recursive);value['definitions']*=2;check(value,False)
    for field in ['properties','additional','items','alternatives','reference','reason','nullable']:
        value=document();value['nodes'][0][field]=None;check(value,False)
    for raw in [b'{"version":1,"version":1}',b'{"id":0,"id":0}',b'\xff',b'[]',b'null',b'['*300+b']'*300]: check(raw,False)
    raw=compact(document());check(raw.replace(b'"kind":"string"',b'"kind":"string","kind":"string"'),False)
    raw=compact(recursive);check(raw.replace(b'"required":false',b'"required":false,"required":true'),False)

    for amount in [256,257]:
        value=document([node(0,'object',properties=[dict(name='p%03d'%i,required=False,target=1) for i in range(amount)],additional='allowed'),node(1)])
        check(value,amount==256)
    for amount in [2,64,65]:
        value=document([node(0,'union',alternatives=list(range(1,amount+1)))]+[node(i) for i in range(1,amount+1)])
        check(value,amount<=64)
    for alternatives in [[],[1],[1,1],[1,99]]:
        check(document([node(0,'union',alternatives=alternatives),node(1)]),False)
    for amount in [256,257]:
        value=document();value['definitions']=[dict(name='D%03d'%i,target=0) for i in range(amount)];check(value,amount==256)
    for amount in [4096,4097]: check(document([node(i) for i in range(amount)]),amount==4096)
    # Very deep logical graph is flat and traversed iteratively, never on the stack.
    deep=document([node(i,'array',items=i+1) for i in range(4095)]+[node(4095)]);check(deep)
    dense=document([node(i) for i in range(64)]+[node(i+64,'union',alternatives=list(range(64))) for i in range(511)]+[node(575,'union',alternatives=list(range(63)))])
    check(dense)  #32767 structural edges plus document root =32768.
    dense['nodes'][-1]['alternatives'].append(63);check(dense,False)
    for name,valid in [('',False),('x'*64,True),('x'*65,False),('😀'*64,True),('😀'*65,False),('\x00',True)]:
        value=document([node(0,'object',properties=[dict(name=name,required=False,target=1)],additional='allowed'),node(1)]);check(value,valid)
    value=copy.deepcopy(graph);value['nodes'][0]['properties']*=2;check(value,False)

    tiny=compact(document());check(tiny+b' '*(LIMIT-len(tiny)));check(tiny+b' '*(LIMIT+1-len(tiny)),False)
    # Exact serialized output bound, not just a whitespace-padded small graph.
    maximum=document([node(0)]+[node(i,'object',properties=[dict(name='p%03d'%j,required=False,target=0) for j in range(256)],additional='forbidden') for i in range(1,42)])
    remaining=LIMIT-len(compact(maximum))
    for item in maximum['nodes'][1:]:
        for prop in item['properties']:
            added=min(64-len(prop['name']),remaining);prop['name']+='q'*added;remaining-=added
    assert remaining==0 and len(compact(maximum))==LIMIT
    assert len(check(maximum)[1])==LIMIT
    maximum['nodes'][-1]['properties'][-1]['name']+='q';check(maximum,False)
    check(document())  # Valid recovery after adversarial cases.
    print('Declared graph executable codec: %d cases passed; no import, persistence or compatibility acceptance claimed'%count)


if __name__=='__main__': main()

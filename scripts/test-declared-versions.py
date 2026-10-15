"""Executable directional containment, checked wire reload, and bounded failure evidence."""
import copy
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
UUID = '00000000-0000-0000-0000-000000000001'
OP = [UUID]*4 + ['http', 'request', 'GET', '/orders']


def node(i, kind='string', **fields):
    return dict(id=i, kind=kind, omissions=[], **fields)


def graph(nodes=None, root=0, definitions=None):
    return dict(version=1, operation=OP.copy(), root=root, nodes=nodes or [node(0)],
                definitions=definitions or [], omissions=[])


def primitive(kind, nullable=False):
    nodes = [node(0, kind)]
    if nullable:
        nodes += [node(1, 'null'), node(2, 'union', alternatives=[0, 1])]
    return graph(nodes, root=2 if nullable else 0)


def obj(fields=(), additional='forbidden', kind='integer'):
    return graph([node(0, 'object', properties=[dict(name=n, required=r, target=1) for n,r in fields],
                       additional=additional), node(1, kind)])


def main():
    subprocess.run(['cargo','build','-p','contour-core','--example','declared_versions_probe','--locked','--offline'],
                   cwd=ROOT,check=True,timeout=180,capture_output=True)
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],cwd=ROOT,timeout=15))
    probe=Path(metadata['target_directory'])/'debug/examples/declared_versions_probe'
    count=0
    def check(a,b,expected='Compatible',error=None,direction='request'):
        nonlocal count
        a,b=copy.deepcopy(a),copy.deepcopy(b)
        a['operation'][5]=b['operation'][5]=direction
        raw=json.dumps([a,b],ensure_ascii=False,separators=(',',':')).encode()
        result=subprocess.run([str(probe)],input=raw,capture_output=True,timeout=5)
        count+=1
        if error:
            assert result.returncode==1 and not result.stdout and result.stderr.strip()==error.encode(), (count,'wrong bounded failure',result.stderr)
            return
        assert result.returncode==0 and not result.stderr, (count,'rejected',result.stderr)
        out=json.loads(result.stdout)
        assert out['compatibility']==expected, (count,direction,expected,out)
        assert len(out['differences'])<=10000
        assert [d['path'] for d in out['differences']]==sorted(d['path'] for d in out['differences'])
        return out
    def pair(a,b,request,response):
        check(a,b,request)
        check(a,b,response,direction='response')

    # Regression: compatible changes still produce typed structural findings.
    for direction in ['request','response']:
        cases=[(primitive('integer'),primitive('number'),'TypeChanged',direction=='request'),
               (obj([('x',True)]),obj([('x',False)]),'RequirednessChanged',direction=='request'),
               (primitive('integer'),primitive('integer',True),'NullMembershipChanged',direction=='request')]
        for a,b,change,compatible in cases:
            out=check(a,b,'Compatible' if compatible else 'Incompatible',direction=direction)
            finding=next((d for d in out['differences'] if d['kind']==change),None)
            assert finding, 'missing typed compatible change: '+change
            field,expected={'TypeChanged':('kind',('Integer','Number')),'RequirednessChanged':('required',(True,False)),
                            'NullMembershipChanged':('includes_null',(False,True))}[change]
            assert (finding['baseline_'+field],finding['candidate_'+field])==expected, 'reversed finding labels' 
            out=check(b,a,'Incompatible' if compatible else 'Compatible',direction=direction)
            assert any(d['kind']==change for d in out['differences']), 'missing typed reversed change: '+change
        assert check(primitive('integer'),primitive('integer'),direction=direction)['differences']==[]
        out=check(obj(),obj([('x',False)]),'Compatible' if direction=='request' else 'Incompatible',direction=direction)
        finding=next(d for d in out['differences'] if d['kind']=='FieldAdded')
        assert finding['baseline_kind'] is None and finding['candidate_kind']=='Integer'
        assert finding['baseline_required'] is None and finding['candidate_required'] is False
        out=check(obj([('x',False)]),obj(),'Incompatible' if direction=='request' else 'Compatible',direction=direction)
        assert any(d['kind']=='FieldRemoved' for d in out['differences'])
        out=check(obj(),obj(additional='allowed'),'Compatible' if direction=='request' else 'Incompatible',direction=direction)
        finding=next(d for d in out['differences'] if d['kind']=='AdditionalPolicyChanged')
        assert (finding['baseline_additional'],finding['candidate_additional'])==('Forbidden','Allowed')
    # Unsupported evidence must not discard independent known sibling changes.
    for mode in ['unknown','omission','union','recursion']:
        a=obj([('known',False),('uncertain',False)])
        a['nodes'][0]['properties'][1]['target']=2
        if mode=='unknown': a['nodes'].append(node(2,'unknown',reason='unspecified'))
        elif mode=='omission':
            a['nodes'].append(dict(node(2),omissions=['removed_value']));a['omissions']=['removed_value']
        elif mode=='union': a['nodes'] += [node(2,'union',alternatives=[3,4]),node(3,'string'),node(4,'integer')]
        else:
            a['nodes'].append(node(2,'reference',reference='Root'));a['definitions']=[dict(name='Root',target=0)]
        b=copy.deepcopy(a);b['nodes'][1]['kind']='number'
        for direction in ['request','response']:
            out=check(a,b,'Inconclusive',direction=direction)
            assert any(d['path']=='#/fields/known' and d['kind']=='TypeChanged' for d in out['differences']), 'known sibling change discarded: '+mode
    # All primitive pairs, both variances, with independently computed expectations.
    kinds=['null','boolean','integer','number','string','binary']
    for a in kinds:
        for b in kinds:
            subset=lambda x,y:x==y or (x,y)==('integer','number')
            pair(primitive(a),primitive(b),'Compatible' if subset(a,b) else 'Incompatible',
                 'Compatible' if subset(b,a) else 'Incompatible')
    for a in [False,True]:
        for b in [False,True]:
            pair(primitive('integer',a),primitive('integer',b),
                 'Incompatible' if a and not b else 'Compatible',
                 'Incompatible' if b and not a else 'Compatible')
    for kind in kinds:
        pair(primitive('null'),primitive(kind,True),'Compatible','Compatible' if kind=='null' else 'Incompatible')
    labelled=check(primitive('integer'),primitive('number'),'Incompatible',direction='response')['differences'][0]
    assert (labelled['baseline_kind'],labelled['candidate_kind'])==('Integer','Number')
    for a in [False,True]:
        for b in [False,True]:
            pair(obj([('x',a)]),obj([('x',b)]),'Incompatible' if b and not a else 'Compatible',
                 'Incompatible' if a and not b else 'Compatible')
    policies=['forbidden',{'schema':1},'allowed']
    # Allowed > integer schema > forbidden. All absent-name and explicit-name combinations.
    for ai,a in enumerate(policies):
        for bi,b in enumerate(policies):
            pair(obj(additional=a),obj(additional=b),'Compatible' if ai<=bi else 'Incompatible',
                 'Compatible' if bi<=ai else 'Incompatible')
            for required in [False,True]:
                left,right=obj(additional=a),obj([('x',required)],additional=b)
                # Named x is absent/typed/unrestricted on left; target explicitly integer.
                req_ok=not required and ai<=1 and ai<=bi
                resp_ok=ai>=1 and bi<=ai
                pair(left,right,'Compatible' if req_ok else 'Incompatible','Compatible' if resp_ok else 'Incompatible')
                pair(right,left,'Compatible' if resp_ok else 'Incompatible','Compatible' if req_ok else 'Incompatible')
    for ak in ['integer','number','string']:
        for bk in ['integer','number','string']:
            a=graph([node(0,'array',items=1),node(1,ak)])
            b=graph([node(0,'array',items=1),node(1,bk)])
            subset=lambda x,y:x==y or (x,y)==('integer','number')
            pair(a,b,'Compatible' if subset(ak,bk) else 'Incompatible','Compatible' if subset(bk,ak) else 'Incompatible')
            pair(obj(additional={'schema':1},kind=ak),obj(additional={'schema':1},kind=bk),
                 'Compatible' if subset(ak,bk) else 'Incompatible','Compatible' if subset(bk,ak) else 'Incompatible')
    # Unknown and omissions dominate, including equality and unreachable nodes.
    unknown=graph([node(0,'unknown',reason='unspecified')])
    check(unknown,unknown,'Inconclusive')
    warned=primitive('integer');warned['nodes'][0]['omissions']=['removed_value'];warned['omissions']=['removed_value']
    pair(warned,primitive('string'),'Inconclusive','Inconclusive')
    hidden=primitive('integer');hidden['nodes'].append(node(1,'unknown',reason='unspecified'))
    check(hidden,primitive('integer'),'Inconclusive')
    union=graph([node(0,'union',alternatives=[1,2]),node(1,'integer'),node(2,'string')])
    check(union,union,'Inconclusive')
    self_ref=graph([node(0,'reference',reference='Self')],definitions=[dict(name='Self',target=0)])
    mutual=graph([node(0,'reference',reference='B'),node(1,'reference',reference='A')],definitions=[dict(name='A',target=0),dict(name='B',target=1)])
    recursive=obj([('next',False)]);recursive['nodes'][1]=node(1,'reference',reference='Root');recursive['definitions']=[dict(name='Root',target=0)]
    for value in [self_ref,mutual,recursive]:
        pair(value,value,'Inconclusive','Inconclusive')
    # A cycle can close on a structural edge after entering through a reference.
    through_ref=graph([node(0,'reference',reference='Body'),node(1,'object',properties=[
        dict(name='known',required=False,target=2),dict(name='next',required=False,target=0)],additional='forbidden'),node(2,'integer')],definitions=[dict(name='Body',target=1)])
    through_candidate=copy.deepcopy(through_ref);through_candidate['nodes'][2]['kind']='number'
    for direction in ['request','response']:
        out=check(through_ref,through_candidate,'Inconclusive',direction=direction)
        assert any(d['path']=='#/fields/known' and d['kind']=='TypeChanged' for d in out['differences'])
    # Acyclic alias chain uses all definitions without consuming Python/Rust call stacks.
    chain=graph([node(i,'reference',reference='d%03d'%i) for i in range(256)]+[node(256,'integer')],
                definitions=[dict(name='d%03d'%i,target=i+1) for i in range(256)])
    pair(chain,primitive('number'),'Compatible','Incompatible')
    repeated=obj([('a',False),('b',False)]);repeated['nodes'][1]=node(1,'reference',reference='Leaf');repeated['nodes'].append(node(9,'integer'));repeated['definitions']=[dict(name='Leaf',target=9)]
    added=check(obj(),repeated)
    assert all(d['candidate_kind']=='Integer' for d in added['differences']), 'reference labels not resolved'
    other=obj([('a',False),('b',False)],kind='string')
    result=check(repeated,other,'Incompatible')
    assert [d['path'] for d in result['differences']]==['#/fields/a','#/fields/b']
    ids=graph([node(99,'integer')],root=99);check(primitive('integer'),ids)
    escaped=obj([('a/b~c',False),('😀',False)],kind='integer')
    changed=obj([('a/b~c',False),('😀',False)],kind='string')
    result=check(escaped,changed,'Incompatible')
    assert [d['path'] for d in result['differences']]==['#/fields/a~1b~0c','#/fields/😀']
    shuffled=copy.deepcopy(escaped);shuffled['nodes'].reverse();shuffled['nodes'][-1]['properties'].reverse()
    assert check(shuffled,changed,'Incompatible')==result
    for i in range(8):
        a,b=primitive('integer'),primitive('integer')
        b['operation'][i]=([UUID[:-1]+'2']*4+['grpc','response','POST','/other'])[i]
        # Preserve the intentionally mismatched direction outside check's direction assignment.
        raw=json.dumps([a,b]).encode();r=subprocess.run([str(probe)],input=raw,capture_output=True,timeout=5);count+=1
        assert r.returncode==1 and not r.stdout and r.stderr.strip()==b'OperationScope'
    for direction in ['publish','consume','operation','connection']:
        check(primitive('integer'),primitive('integer'),error='UnsupportedDirection',direction=direction)
    # Deep flat structural graph fails the path bound, never recursion/stack overflow.
    deep=graph([node(i,'array',items=i+1) for i in range(4095)]+[node(4095)])
    check(deep,deep,error='PathLimit')
    # Exact 1024 Unicode path scalars and one over (object child overhead is 8).
    def long_path(last):
        nodes=[node(i,'array',items=i+1) for i in range(159)]
        nodes += [node(159,'object',properties=[dict(name='x'*last,required=False,target=160)],additional='forbidden'),node(160,'integer')]
        return graph(nodes)
    check(long_path(61),long_path(61))
    check(long_path(62),long_path(62),error='PathLimit')
    # Work count = two normalized graphs (node + edge), plus pushed obligations
    # and merged property scans. Shared array suffixes retain per-path obligations.
    # 123 shared array levels yield 33010 visits before shortening two paths.
    def work_graph(extra):
        value=graph([node(0,'object',properties=[dict(name='p%03d'%i,required=False,target=1) for i in range(256)],additional='forbidden')]+
                    [node(i,'array',items=i+1) for i in range(1,124)]+[node(124)])
        value['nodes'][0]['properties'][-1]['target']=124
        value['nodes'][0]['properties'][-2]['target']=120-extra
        return value
    check(work_graph(0),work_graph(0))
    check(work_graph(1),work_graph(1),error='WorkLimit')
    # Exact 10000 findings, then one extra (well below the work bound).
    def many(extra=False, long=False, over=False, kind='integer'):
        root=[dict(name=('r%02d'%i).ljust(43 if long else 3,'x'),required=False,target=1 if i<39 else 2) for i in range(40)]
        def props(custom):
            return [dict(name=('p%03d'%i).ljust((44+(i<(35 if custom else 219))) if long else 4,'x'),required=False,target=9) for i in range(250)]
        common,custom=props(False),props(True)
        if over: custom[-1]['name']+='x'
        if extra: custom.append(dict(name='extra',required=False,target=9))
        return graph([node(0,'object',properties=root,additional='forbidden'),
                      node(1,'object',properties=common,additional='forbidden'),
                      node(2,'object',properties=custom,additional='forbidden'),node(9,kind)])
    out=check(many(),many(kind='string'),'Incompatible')
    assert len(out['differences'])==10000
    check(many(extra=True),many(extra=True,kind='string'),error='DifferenceLimit')
    out=check(many(long=True),many(long=True,kind='string'),'Incompatible')
    assert sum(len(d['path'].encode()) for d in out['differences'])==1048576
    check(many(long=True,over=True),many(long=True,over=True,kind='string'),error='PathLimit')
    # Compatible findings consume the same budgets as incompatible findings.
    out=check(many(),many(kind='number'))
    assert len(out['differences'])==10000
    check(many(extra=True),many(extra=True,kind='number'),error='DifferenceLimit')
    out=check(many(long=True),many(long=True,kind='number'))
    assert sum(len(d['path'].encode()) for d in out['differences'])==1048576
    check(many(long=True,over=True),many(long=True,over=True,kind='number'),error='PathLimit')
    # Null-only union, reference to nullable union and nested nullable wrapper.
    nulls=graph([node(0,'union',alternatives=[1,2]),node(1,'null'),node(2,'null')])
    pair(nulls,primitive('null'),'Compatible','Compatible')
    nullable=primitive('integer',True)
    nullable['nodes'].append(node(3,'reference',reference='Nullable'));nullable['root']=3
    nullable['definitions']=[dict(name='Nullable',target=2)]
    pair(nullable,primitive('integer'),'Incompatible','Compatible')
    nullable['nodes'] += [node(4,'union',alternatives=[3,5]),node(5,'null')];nullable['root']=4
    pair(nullable,primitive('integer',True),'Compatible','Compatible')
    check(primitive('integer'),primitive('integer'))
    print('Declared version containment executable: %d cases passed; internal evidence only'%count)


if __name__=='__main__':
    main()

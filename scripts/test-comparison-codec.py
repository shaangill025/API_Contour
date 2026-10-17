"""Checked internal result codec: actual comparisons and adversarial wire inputs."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
ROOT=Path(__file__).resolve().parents[1]

def main():
    subprocess.run(['cargo','build','-p','contour-core','--example','comparison_codec_probe','--locked','--offline'],cwd=ROOT,check=True,capture_output=True,timeout=180)
    target=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps','--offline'],cwd=ROOT,timeout=15))['target_directory']
    probe=Path(target)/'debug/examples/comparison_codec_probe'
    count=0
    def check(value,valid=True,mode='decode'):
        nonlocal count
        raw=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
        result=subprocess.run([str(probe),mode],input=raw,capture_output=True,timeout=5);count+=1
        if not valid:
            assert result.returncode==1 and not result.stdout and result.stderr.strip() in [b'Wire',b'Version',b'Size',b'Limit',b'Invariant'],(count,'invalid codec accepted',result.stderr)
            return
        assert result.returncode==0 and not result.stderr,(count,'valid codec rejected',result.stderr)
        wire=json.loads(result.stdout)
        again=subprocess.run([str(probe),'decode'],input=result.stdout,capture_output=True,timeout=5)
        assert again.returncode==0 and again.stdout==result.stdout and not again.stderr,'non-deterministic codec'
        return wire
    def finding(kind='type_changed',path='#',**kw):
        row=dict(path=path,kind=kind,baseline_kind=None,candidate_kind=None,baseline_required=None,candidate_required=None,baseline_includes_null=None,candidate_includes_null=None,baseline_additional=None,candidate_additional=None)
        row.update(kw);return row
    def doc(rows=(),compatibility='compatible'):
        return dict(version=1,compatibility=compatibility,differences=list(rows))
    type_change=finding(baseline_kind='integer',candidate_kind='number')
    samples=[type_change,
        finding('null_membership_changed',baseline_kind='string',candidate_kind='string',baseline_includes_null=False,candidate_includes_null=True),
        finding('requiredness_changed','#/fields/x',baseline_kind='integer',candidate_kind='number',baseline_required=True,candidate_required=False),
        finding('field_added','#/fields/x',candidate_kind='unknown',candidate_required=False),
        finding('field_removed','#/fields/x',baseline_kind='string',baseline_required=True),
        finding('additional_policy_changed','#/additional',baseline_additional='allowed',candidate_additional='schema',candidate_kind='integer'),
        finding('insufficient_evidence',baseline_kind='object',candidate_kind='unknown')]
    for sample in samples:
        compatible='inconclusive' if sample['kind']=='insufficient_evidence' else 'compatible'
        wire=doc([sample],compatible);assert check(wire)==wire
        for field in sample:
            broken=copy.deepcopy(wire);del broken['differences'][0][field];check(broken,False)
        for field in ['path','kind','baseline_kind','candidate_kind','baseline_required','candidate_required','baseline_includes_null','candidate_includes_null','baseline_additional','candidate_additional']:
            broken=copy.deepcopy(wire);broken['differences'][0][field]=[];check(broken,False)
        broken=copy.deepcopy(wire);broken['differences'][0]['extra']=None;check(broken,False)
    base=doc([type_change]);raw=json.dumps(base,separators=(',',':')).encode()
    check(raw.replace(b'"version":1',b'"version":1,"version":1'),False)
    check(raw.replace(b'"path":"#"',b'"path":"#","path":"#"'),False)
    check(raw.replace(b'"baseline_required":null',b'"baseline_required":null,"baseline_required":null'),False)
    check(raw+b'{}',False);check(raw+b' ',True);check(raw[:-1],False)
    for token in [b'-0',b'-1',b'true',b'null',b'"1"',b'2',b'9'*257]:check(raw.replace(b'"version":1',b'"version":'+token),False)
    for token in [b'1.0',b'1e0']:check(raw.replace(b'"version":1',b'"version":'+token))
    for field in base:
        broken=copy.deepcopy(base);del broken[field];check(broken,False)
    for field in ['compatibility','differences']:
        broken=copy.deepcopy(base);broken[field]=None;check(broken,False)
    broken=copy.deepcopy(base);broken['extra']=1;check(broken,False)
    for field in ['compatibility','kind','baseline_kind','baseline_additional']:
        broken=copy.deepcopy(base)
        (broken if field=='compatibility' else broken['differences'][0])[field]='not-an-enum';check(broken,False)
    # Review regressions: impossible normalized labels and repeated findings.
    for index,patch in [(0,dict(baseline_kind='unknown')),(0,dict(candidate_kind='unknown')),(1,dict(baseline_kind='null')),(1,dict(baseline_kind='unknown')),(1,dict(candidate_kind='unknown'))]:
        row=copy.deepcopy(samples[index]);row.update(patch);check(doc([row]),False)
    row=copy.deepcopy(samples[1]);row.update(candidate_kind='null',baseline_includes_null=True,candidate_includes_null=False);check(doc([row]),False)
    check(doc([type_change,type_change]),False)
    # Semantic guards: same type labels, extraneous metadata, absent required pairs.
    for patch in [dict(candidate_kind='integer'),dict(baseline_kind=None),dict(baseline_required=False),dict(candidate_includes_null=False),dict(baseline_additional='allowed'),dict(candidate_kind='union')]:
        row=copy.deepcopy(type_change);row.update(patch);check(doc([row]),False)
    for index,patch in [(1,dict(candidate_includes_null=False)),(1,dict(baseline_includes_null=None)),(2,dict(candidate_required=True)),(2,dict(candidate_required=None)),(3,dict(baseline_kind='string')),(3,dict(candidate_required=None)),(4,dict(candidate_kind='string')),(4,dict(baseline_required=None)),(5,dict(candidate_additional='allowed')),(5,dict(candidate_kind=None)),(5,dict(baseline_kind='string'))]:
        row=copy.deepcopy(samples[index]);row.update(patch);check(doc([row]),False)
    for bad in ['', '/', '#/', '#/else', '#/fields', '#/fields/', '#/fields/a~', '#/fields/a~2', '#/fields/a/b', '#/fields/'+'x'*65]:
        row=copy.deepcopy(type_change);row['path']=bad;check(doc([row]),False)
    for good in ['#', '#/items/additional', '#/fields/items', '#/fields/a~1b~0c\x00é😀', '#/fields/~01']:
        row=copy.deepcopy(type_change);row['path']=good;assert check(doc([row]))['differences'][0]['path']==good
    for index in [2,3,4,5,6]:
        row=copy.deepcopy(samples[index]);row['path']='#/items';check(doc([row],'inconclusive' if index==6 else 'compatible'),False)
    check(doc([samples[6]],'compatible'),False);check(doc([],'inconclusive'),False)
    check(doc([samples[6],samples[6]],'inconclusive'),False)
    check(doc([samples[6],type_change],'inconclusive'))
    check(doc([type_change,samples[6]],'inconclusive'))  # equal-path order is preserved
    check(doc([samples[2],type_change]),False)
    long_path='#'+'/items'*159+'/fields/'+'x'*61
    assert len(long_path)==1024
    row=copy.deepcopy(type_change);row['path']=long_path;check(doc([row]))
    row['path']+='x';check(doc([row]),False)
    check(b' '*(1048576-len(raw))+raw);check(b' '+b' '*(1048576-len(raw))+raw,False)
    # Escaping and metadata can exceed output bounds before structural limits.
    escaped=[finding(path='#/fields/'+'\x00'*60+f'{i:04}',baseline_kind='integer',candidate_kind='number') for i in range(2000)]
    check(doc(escaped),False)
    # Feed genuine checked comparator outputs through independent codec reload.
    helpers=runpy.run_path(str(ROOT/'scripts/test-declared-versions.py'))
    primitive,obj,graph,node=[helpers[n] for n in ['primitive','obj','graph','node']]
    pairs=[(primitive('integer'),primitive('number')),(primitive('string'),primitive('string',True)),
           (obj([('x',True)]),obj([('x',False)])),(obj(),obj([('x',False)])),
           (obj([('x',False)]),obj()),(obj(),obj(additional='allowed')),
           (graph([node(0,'unknown',reason='unspecified')]),primitive('string'))]
    kinds=set()
    for a,b in pairs:
        for direction in ['request','response']:
            a,b=copy.deepcopy(a),copy.deepcopy(b);a['operation'][5]=b['operation'][5]=direction
            wire=check([a,b],mode='compare');kinds.update(d['kind'] for d in wire['differences'])
    assert kinds=={s['kind'] for s in samples},'actual comparator kinds missing'
    print('Checked declared comparison codec: %d wire and actual comparison cases passed'%count)

if __name__=='__main__':main()

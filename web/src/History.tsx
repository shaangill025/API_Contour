import {useEffect, useRef, useState} from 'react';
import {api, ApiError} from './api.ts';
import type {Observation} from './domain.ts';
import {requestEpoch} from './domain.ts';

// A keyed instance is scoped to one operation. Sequence numbers also prevent
// overlapping requests within that instance from replacing newer results.
export function History({operationId}: {operationId: string}) {
  const [items,setItems]=useState<Observation[]>([]); const [cursor,setCursor]=useState<string|null>(null);
  const [loaded,setLoaded]=useState(false); const [loading,setLoading]=useState(false);
  const [detail,setDetail]=useState<Observation|null>(null); const [detailLoading,setDetailLoading]=useState(false);
  const [error,setError]=useState(''); const [detailError,setDetailError]=useState('');
  const listRequest=useRef(requestEpoch()); const detailRequest=useRef(requestEpoch());
  useEffect(()=>()=>{listRequest.current.invalidate(); detailRequest.current.invalidate();},[]);
  async function load(more=false) {
    const serial=listRequest.current.start(); setLoading(true); setError('');
    if (!more) { setDetail(null); detailRequest.current.invalidate(); setDetailLoading(false); setDetailError(''); }
    try {
      const page=await api.observations(operationId,more && cursor ? cursor : undefined);
      if (!listRequest.current.current(serial)) return;
      if (more && page.items.some(item=>items.some(old=>old.id===item.id))) throw new Error('Invalid response');
      setItems(more ? [...items,...page.items] : page.items); setCursor(page.next_cursor); setLoaded(true);
    } catch (e) { if (listRequest.current.current(serial)) setError(e instanceof ApiError ? e.message : 'Observation history could not be verified.'); }
    finally { if (listRequest.current.current(serial)) setLoading(false); }
  }
  async function open(id: string) {
    const serial=detailRequest.current.start(); setDetail(null); setDetailError(''); setDetailLoading(true);
    try { const item=await api.observation(operationId,id); if (detailRequest.current.current(serial)) setDetail(item); }
    catch (e) { if (detailRequest.current.current(serial)) setDetailError(e instanceof ApiError ? e.message : 'Observation detail could not be verified.'); }
    finally { if (detailRequest.current.current(serial)) setDetailLoading(false); }
  }
  return <section className="panel" aria-labelledby="history-title"><p className="step">OBSERVED EVIDENCE</p><h2 id="history-title">Observation history</h2>
    <p>Immutable observations for operation <code>{operationId}</code>. Historical origin evidence is unavailable.</p>
    <div className="actions"><button className="secondary" disabled={loading} onClick={()=>void load()}> {loaded ? 'Reload history' : 'Load history'}</button>{cursor && items.length<500 && <button className="secondary" disabled={loading} onClick={()=>void load(true)}>Load more observations</button>}</div>
    {loading && <p role="status">Loading observations…</p>}{error && <p className="error" role="alert">{error}</p>}
    {loaded && !items.length && !loading && <p className="empty">No stored observations for this operation.</p>}
    {items.length>0 && <div className="table-scroll"><table><caption>Stored observations</caption><thead><tr><th scope="col">Observation</th><th scope="col">Last seen</th><th scope="col">Visibility / completeness</th><th scope="col">Sampling</th><th scope="col">Detail</th></tr></thead><tbody>{items.map(item=><tr key={item.id}><td><code>{item.id}</code></td><td>{item.last_seen}</td><td>{item.visibility} / {item.completeness}</td><td>{item.sample_numerator} / {item.sample_denominator}</td><td><button className="secondary" onClick={()=>void open(item.id)}>Inspect</button></td></tr>)}</tbody></table></div>}
    {cursor && items.length>=500 && <p>Display limit reached. Reload history to start again.</p>}
    {detailLoading && <p role="status">Loading observation detail…</p>}{detailError && <p className="error" role="alert">{detailError}</p>}
    {detail && <div className="result"><h3>Observation detail</h3><dl>
      <dt>Observation ID</dt><dd><code>{detail.id}</code></dd><dt>Historical origin evidence</dt><dd>Unavailable</dd>
      <dt>Operation and direction</dt><dd>{detail.protocol} · {detail.direction} · {detail.operation} {detail.route_template}{detail.route_uncertain ? ' · route uncertain' : ''}</dd>
      <dt>Visibility / completeness</dt><dd>{detail.visibility} / {detail.completeness}</dd><dt>Reasons</dt><dd>{detail.reasons.length ? detail.reasons.join(', ') : 'None reported'}</dd>
      <dt>Observed count / sampling</dt><dd>{detail.count} · {detail.sample_numerator} / {detail.sample_denominator}{detail.sample_numerator!==detail.sample_denominator ? ' (sampled)' : ''}</dd>
      <dt>First / last seen</dt><dd>{detail.first_seen} / {detail.last_seen}</dd><dt>Queued / expires</dt><dd>{detail.queued_at} / {detail.expires_at}</dd>
      <dt>Policy revision / parser</dt><dd>{detail.policy_revision} / {detail.parser_profile}</dd><dt>Status code</dt><dd>{detail.status_code ?? 'Unavailable'}</dd>
      <dt>Structure fingerprint</dt><dd><code>{detail.structure_fingerprint}</code> · canonicalization {detail.canonicalization_version}</dd></dl>
      <h4>Sanitized structure</h4><p>Unknown nodes and their reasons are shown as returned.</p><pre className="history-structure">{JSON.stringify(detail.structure,null,2)}</pre>
    </div>}
  </section>;
}

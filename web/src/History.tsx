import {useEffect, useRef, useState} from 'react';
import {api, ApiError, SessionChanged, SessionViewFailure, sessionFenced, onSessionInvalidated} from './api.ts';
import type {HistoricalConnection, HistoricalOrigin, Observation} from './domain.ts';
import {acceptConnectionPage, requestEpoch} from './domain.ts';
import {historyRead} from './history-read.ts';

// A keyed instance is scoped to one operation. Sequence numbers also prevent
// overlapping requests within that instance from replacing newer results.
export function History({operationId}: {operationId: string}) {
  const [items,setItems]=useState<Observation[]>([]); const [cursor,setCursor]=useState<string|null>(null);
  const [loaded,setLoaded]=useState(false); const [loading,setLoading]=useState(false);
  const [detail,setDetail]=useState<Observation|null>(null); const [detailLoading,setDetailLoading]=useState(false);
  const [origin,setOrigin]=useState<HistoricalOrigin|null>(null); const [originLoading,setOriginLoading]=useState(false);
  const [originError,setOriginError]=useState('');
  const [connections,setConnections]=useState<HistoricalConnection[]>([]); const [connectionCursor,setConnectionCursor]=useState<string|null>(null);
  const [connectionLoading,setConnectionLoading]=useState(false); const [connectionLoaded,setConnectionLoaded]=useState(false); const [connectionError,setConnectionError]=useState('');
  const connectionCursors=useRef(new Set<string>());
  function clearConnections() { setConnections([]); setConnectionCursor(null); setConnectionLoading(false); setConnectionLoaded(false); setConnectionError(''); connectionCursors.current.clear(); }

  const [error,setError]=useState(''); const [detailError,setDetailError]=useState('');
  const generation=useRef(requestEpoch()); const pending=useRef<AbortController|null>(null); const activeView=useRef<string|null>(null);
  function clearHistory() {
    generation.current.invalidate(); pending.current?.abort(); pending.current=null; activeView.current=null;
    setItems([]); setCursor(null); setLoaded(false); setLoading(false);
    setDetail(null); setDetailLoading(false); setDetailError('');
    setOrigin(null); setOriginLoading(false); setOriginError(''); clearConnections(); setError('');
  }
  useEffect(()=>{
    clearHistory();
    const clear=()=>clearHistory();
    const unsubscribe=onSessionInvalidated(clear);
    window.addEventListener('focus',clear); document.addEventListener('visibilitychange',clear);
    return ()=>{ unsubscribe(); window.removeEventListener('focus',clear); document.removeEventListener('visibilitychange',clear); generation.current.invalidate(); pending.current?.abort(); };
  },[operationId]);
  function begin() {
    pending.current?.abort(); const controller=new AbortController(); pending.current=controller;
    return {controller,serial:generation.current.start()};
  }
  function failed(e: unknown, serial: number, setMessage: (message:string)=>void, fallback='Observation history could not be verified.') {
    if (!generation.current.current(serial)) return;
    if (e instanceof SessionChanged || e instanceof SessionViewFailure || (e instanceof ApiError && e.status===401)) { clearHistory(); setError('Session changed or expired. Reload history.'); return; }
    setMessage(e instanceof ApiError ? e.message : fallback);
  }
  function captureView(serial:number, view:string) {
    if (!generation.current.current(serial)) throw new SessionChanged();
    if (activeView.current!==null && activeView.current!==view) throw new SessionChanged();
    activeView.current=view;
  }
  async function load(more=false) {
    const {controller,serial}=begin(); setLoading(true); setDetailLoading(false); setOriginLoading(false); setError('');
    setDetail(null); setOrigin(null); setOriginError(''); setDetailError(''); clearConnections();
    try {
      const page=await sessionFenced((signal,view)=>api.observations(operationId,more && cursor ? cursor : undefined,signal,view),controller.signal,view=>captureView(serial,view));
      if (!generation.current.current(serial)) return;
      if (more && page.items.some(item=>items.some(old=>old.id===item.id))) throw new Error('Invalid response');
      setItems(more ? [...items,...page.items] : page.items); setCursor(page.next_cursor); setLoaded(true);
    } catch (e) { failed(e,serial,setError); }
    finally { if (generation.current.current(serial)) setLoading(false); }
  }
  async function open(id: string) {
    const {controller,serial}=begin(); setLoading(false);
    setDetail(null); setDetailError(''); setDetailLoading(true);
    setOrigin(null); setOriginError(''); setOriginLoading(true); clearConnections(); setConnectionLoading(true);
    const onView=(view:string)=>captureView(serial,view);
    const current=()=>generation.current.current(serial);
    void historyRead((signal,view)=>api.observation(operationId,id,signal,view),controller.signal,onView,current,
      setDetail,e=>failed(e,serial,setDetailError),()=>setDetailLoading(false));
    void historyRead((signal,view)=>api.observationOrigin(operationId,id,signal,view),controller.signal,onView,current,
      setOrigin,e=>failed(e,serial,setOriginError,'Historical origin could not be verified.'),()=>setOriginLoading(false));
    void historyRead((signal,view)=>api.observationConnections(operationId,id,undefined,signal,view),controller.signal,onView,current,
      page=>{ setConnections(page.items); setConnectionCursor(page.next_cursor); setConnectionLoaded(true); if (page.next_cursor) connectionCursors.current.add(page.next_cursor); },
      e=>failed(e,serial,setConnectionError,'Historical connections could not be verified.'),()=>setConnectionLoading(false));
  }
  async function moreConnections() {
    if (!detail || !connectionCursor || connectionLoading || connections.length>=500) return;
    const requested=connectionCursor; const {controller,serial}=begin(); setOriginLoading(false); setConnectionLoading(true); setConnectionError('');
    try {
      const page=await sessionFenced((signal,view)=>api.observationConnections(operationId,detail.id,requested,signal,view),controller.signal,view=>captureView(serial,view));
      if (!generation.current.current(serial)) return;
      acceptConnectionPage(page.next_cursor,connectionCursors.current,connections.length,page.items.length);
      setConnections([...connections,...page.items]); setConnectionCursor(page.next_cursor);
    } catch (e) { failed(e,serial,setConnectionError); }
    finally { if (generation.current.current(serial)) setConnectionLoading(false); }
  }
  return <section className="panel" aria-labelledby="history-title"><p className="step">OBSERVED EVIDENCE</p><h2 id="history-title">Observation history</h2>
    <p>Immutable observations for operation <code>{operationId}</code>.</p>
    <div className="actions"><button className="secondary" disabled={loading} onClick={()=>void load()}> {loaded ? 'Reload history' : 'Load history'}</button>{cursor && items.length<500 && <button className="secondary" disabled={loading} onClick={()=>void load(true)}>Load more observations</button>}</div>
    {loading && <p role="status">Loading observations…</p>}{error && <p className="error" role="alert">{error}</p>}
    {loaded && !items.length && !loading && <p className="empty">No stored observations for this operation.</p>}
    {items.length>0 && <div className="table-scroll"><table><caption>Stored observations</caption><thead><tr><th scope="col">Observation</th><th scope="col">Last seen</th><th scope="col">Visibility / completeness</th><th scope="col">Sampling</th><th scope="col">Detail</th></tr></thead><tbody>{items.map(item=><tr key={item.id}><td><code>{item.id}</code></td><td>{item.last_seen}</td><td>{item.visibility} / {item.completeness}</td><td>{item.sample_numerator} / {item.sample_denominator}</td><td><button className="secondary" onClick={()=>void open(item.id)}>Inspect</button></td></tr>)}</tbody></table></div>}
    {cursor && items.length>=500 && <p>Display limit reached. Reload history to start again.</p>}
    {detailLoading && <p role="status">Loading observation detail…</p>}{detailError && <p className="error" role="alert">{detailError}</p>}
    {detail && <div className="result"><h3>Observation detail</h3><dl>
      <dt>Observation ID</dt><dd><code>{detail.id}</code></dd><dt>Historical origin evidence</dt><dd>
        {originLoading ? 'Loading historical origin…' : originError ? <span className="error" role="alert">{originError}</span> : origin?.status==='verified' ? 'Verified' : 'Unavailable'}</dd>
      {origin?.status==='verified' && <>{([['Instance',origin.origin.instance_id],['Deployment',origin.origin.deployment_id],['Lifecycle',origin.origin.lifecycle_id],['Project',origin.origin.project_id],['Service',origin.origin.service_id],['Environment',origin.origin.environment_id],['Credential',origin.origin.credential_id],['Grant',origin.origin.grant_id]] as const).map(([label,value])=><div key={label}><dt>Origin {label.toLowerCase()} ID</dt><dd><code>{value}</code></dd></div>)}</>}
      <dt>Operation and direction</dt><dd>{detail.protocol} · {detail.direction} · {detail.operation} {detail.route_template}{detail.route_uncertain ? ' · route uncertain' : ''}</dd>
      <dt>Visibility / completeness</dt><dd>{detail.visibility} / {detail.completeness}</dd><dt>Reasons</dt><dd>{detail.reasons.length ? detail.reasons.join(', ') : 'None reported'}</dd>
      <dt>Observed count / sampling</dt><dd>{detail.count} · {detail.sample_numerator} / {detail.sample_denominator}{detail.sample_numerator!==detail.sample_denominator ? ' (sampled)' : ''}</dd>
      <dt>First / last seen</dt><dd>{detail.first_seen} / {detail.last_seen}</dd><dt>Queued / expires</dt><dd>{detail.queued_at} / {detail.expires_at}</dd>
      <dt>Policy revision / parser</dt><dd>{detail.policy_revision} / {detail.parser_profile}</dd><dt>Status code</dt><dd>{detail.status_code ?? 'Unavailable'}</dd>
      <dt>Structure fingerprint</dt><dd><code>{detail.structure_fingerprint}</code> · canonicalization {detail.canonicalization_version}</dd></dl>
      <h4>Historical connections</h4><p>Resolved historical evidence for this observation. It does not establish current connectivity or complete coverage.</p>
      {connectionLoading && <p role="status">Loading historical connections…</p>}{connectionError && <p className="error" role="alert">Historical connections unavailable. {connectionError}</p>}
      {connectionLoaded && !connections.length && !connectionLoading && !connectionError && <p className="empty">No historical connections returned.</p>}
      {connections.map((connection,index)=><div className="result" key={`${connection.producer.event_id}-${connection.receiver.event_id}-${index}`}><h5>Producer → receiver</h5><p>Resolved {connection.resolved_at} · Expires {connection.expires_at}</p>{(['producer','receiver'] as const).map(side=><div key={side}><strong>{side==='producer' ? 'Producer' : 'Receiver'}</strong><dl>{(['project_id','service_id','environment_id','deployment_id','instance_id','batch_id','event_id','receipt_id'] as const).map(key=><div key={key}><dt>{key.replace('_',' ')}</dt><dd><code>{connection[side][key]}</code></dd></div>)}</dl></div>)}</div>)}
      {connectionCursor && connections.length<500 && <button className="secondary" disabled={connectionLoading} onClick={()=>void moreConnections()}>Load more connections</button>}
      {connectionCursor && connections.length>=500 && <p>Connection display limit reached. Inspect the observation again to restart.</p>}
      <h4>Sanitized structure</h4><p>Unknown nodes and their reasons are shown as returned.</p><pre className="history-structure">{JSON.stringify(detail.structure,null,2)}</pre>
    </div>}
  </section>;
}

import React, {useEffect, useRef, useState} from 'react';
import {api, ApiError} from './api.ts';
import {comparisonMatches, reviewMatches, reviewEligibility, failureStale, uuidPattern, validUuid} from './domain.ts';
import type {Comparison, Contract, ImportFormat, Kind, Operation, Review} from './domain.ts';

export function App() {
  const [operations, setOperations] = useState<Operation[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [operation, setOperation] = useState<Operation | null>(null);
  const [left, setLeft] = useState('');
  const [leftKind, setLeftKind] = useState<Kind>('declared');
  const [right, setRight] = useState('');
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [review, setReview] = useState<Review | null>(null);
  const [reloadId, setReloadId] = useState('');
  const [imported, setImported] = useState<Contract | null>(null);
  const [project, setProject] = useState('');
  const [service, setService] = useState('');
  const [format, setFormat] = useState<ImportFormat>('openapi_json');
  const [file, setFile] = useState<File | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState('');
  const [status, setStatus] = useState('Choose an operation to begin, or reload an existing review.');
  const [error, setError] = useState('');
  const [stale, setStale] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);

  async function run(label: string, action: () => Promise<void>, scope: 'catalog' | 'mutation' = 'mutation') {
    setBusy(label); setError(''); setStatus(label);
    try { await action(); }
    catch (e) {
      setError(e instanceof ApiError ? e.message : 'The response could not be verified. Reload explicitly before continuing.');
      setStale(current => failureStale(current, scope)); setStatus('Action stopped. No automatic retry was made.');
    } finally { setBusy(''); }
  }
  async function loadCatalog(more = false) {
    await run('Loading authorized operations…', async () => {
      const page = await api.operations(more && cursor ? cursor : undefined);
      if (!Array.isArray(page.items)) throw new Error('Invalid catalog');
      setOperations(old => more ? [...old, ...page.items] : page.items);
      setCursor(page.next_cursor); setLoaded(true);
      setStatus('Authorized operations loaded. Select the exact operation and direction.');
    }, 'catalog');
  }
  useEffect(() => { void loadCatalog(); }, []);
  useEffect(() => { if (comparison) heading.current?.focus(); }, [comparison?.id]);
  function resetComparison() { setComparison(null); setReview(null); setStale(false); }
  function selectOperation(id: string) {
    const selected = operations.find(o => o.id === id) ?? null;
    setOperation(selected); resetComparison(); setImported(null);
    setLeft(''); setRight(''); setLeftKind('declared');
    if (selected) { setProject(selected.project_id); setService(selected.service_id); }
  }
  async function importContract(event: React.FormEvent) {
    event.preventDefault();
    if (!file) return;
    await run('Importing and sanitizing contract…', async () => {
      if (file.size > 5 * 1024 * 1024) throw new ApiError(413);
      const content = await file.text();
      const result = await api.import({project_id: project, service_id: service, format, content});
      if (!validUuid(result.id) || result.project_id !== project || result.service_id !== service || result.kind !== 'declared') throw new Error('Invalid import');
      setImported(result); setFile(null);
      if (fileInput.current) fileInput.current.value = '';
      setStatus('Declared contract imported. Choose explicitly how to use its exact ID below.');
    });
  }
  async function compare(event: React.FormEvent) {
    event.preventDefault(); if (!operation) return;
    await run('Comparing exact versions…', async () => {
      const body = {operation_id: operation.id, left_id: left, left_kind: leftKind, right_id: right, right_kind: 'declared' as const};
      const result = await api.compare(body);
      if (!comparisonMatches(result, body) || !validUuid(result.id) || !Array.isArray(result.differences)) throw new Error('Mismatched comparison');
      setComparison(result); setReview(null); setStale(false);
      setStatus(`Comparison is ${result.result}. Review the differences before creating a review.`);
    });
  }
  async function createReview() {
    if (!comparison || !operation || reviewEligibility(comparison, operation.approved_contract_id) !== null) return;
    await run('Creating pending review…', async () => {
      const result = await api.createReview({operation_id: operation.id, comparison_id: comparison.id,
        candidate_contract_id: comparison.right_id, expected_baseline_id: operation.approved_contract_id});
      if (!reviewMatches(result, comparison, operation.approved_contract_id) || result.status !== 'pending') throw new Error('Mismatched review');
      setReview(result); setReloadId(result.id);
      setStatus('Pending review created. Approval is a separate, explicit decision.');
    });
  }
  async function reloadReview(event?: React.FormEvent) {
    event?.preventDefault();
    const id = review?.id ?? reloadId;
    if (!validUuid(id)) return;
    await run('Reloading exact review and current baseline…', async () => {
      const fresh = await api.review(id);
      const exact = await api.comparison(fresh.comparison_id);
      const selected = await api.operation(fresh.operation_id);
      if (fresh.id !== id || selected.id !== fresh.operation_id || !reviewMatches(fresh, exact, fresh.expected_baseline_id)) throw new Error('Mismatched review');
      setReview(fresh); setComparison(exact); setOperation(selected);
      setLeft(exact.left_id); setRight(exact.right_id); setLeftKind(exact.left_kind); setReloadId(id);
      const changed = fresh.status === 'pending' && selected.approved_contract_id !== fresh.expected_baseline_id;
      setStale(changed);
      const newObservation = operation?.id === selected.id && operation.last_seen !== selected.last_seen;
      setStatus(changed ? 'The approved baseline changed. This review cannot replace it. Start a new comparison.' : newObservation ? 'New observations arrived. This review still refers to its exact immutable versions; inspect the updated last observation before deciding.' : 'Exact review reloaded. Check the current revision before deciding.');
    });
  }
  async function decide(decision: 'approve' | 'reject') {
    if (!review || !comparison) return;
    await run(decision === 'approve' ? 'Approving exact candidate…' : 'Rejecting review…', async () => {
      const result = await api.decide(review, decision);
      if (result.id !== review.id || !reviewMatches(result, comparison, review.expected_baseline_id) ||
        result.revision <= review.revision || result.status !== (decision === 'approve' ? 'approved' : 'rejected')) throw new Error('Mismatched decision');
      setReview(result); setStatus(`Review ${result.status}. Decision recorded by the authenticated server principal.`);
    });
  }
  const reviewBlock = comparison && operation ? reviewEligibility(comparison, operation.approved_contract_id) : 'Select an operation and compare exact versions first.';
  const locked = !!busy;
  const canCompare = !!operation && validUuid(left) && validUuid(right) && left !== right;
  return <div className="shell">
    <a className="skip" href="#workspace">Skip to review workspace</a>
    <header><a href="/" className="brand" aria-label="APIContour home"><span className="mark" aria-hidden="true">◈</span> APIContour</a><span className="connection">Same-origin authenticated workspace</span></header>
    <main id="workspace">
      <div className="intro"><p className="eyebrow">CONTRACT GOVERNANCE / REVIEW WORKSPACE</p><h1>Make the change explicit.</h1><p>Compare immutable versions, inspect the evidence, and record an exact decision.</p></div>
      <div className="notice"><strong>Declared structure is not observed coverage.</strong> Compatibility does not imply approval. Inconclusive results require investigation; no collector health is inferred here.</div>
      <div className="status" role="status" aria-live="polite" aria-atomic="true">{status}</div>
      {error && <div className="error" role="alert">{error}</div>}
      {stale && <div className="warning"><strong>Context needs review.</strong> Previous results remain visible. Reload this review, or explicitly start a new comparison. Mutations are paused.</div>}
      <div className="grid">
        <section className="panel" aria-labelledby="scope-title"><p className="step">01 / SCOPE</p><h2 id="scope-title">Select an operation</h2><p>Choose the operation and direction explicitly. IDs are assigned by the server.</p>
          <label htmlFor="operation">Authorized operation</label>
          <select id="operation" value={operation?.id ?? ''} disabled={locked} onChange={e => selectOperation(e.target.value)}>
            <option value="">Select an operation…</option>
            {operations.map(o => <option key={o.id} value={o.id}>{o.operation} {o.route_template} · {o.direction} · {o.id}</option>)}
          </select>
          {loaded && operations.length === 0 && <p className="empty">No authorized operations in this scope yet.</p>}
          <div className="actions"><button className="secondary" disabled={locked} onClick={() => void loadCatalog()}>Reload catalog</button>{cursor && <button className="secondary" disabled={locked} onClick={() => void loadCatalog(true)}>Load more</button>}</div>
          {operation && <dl><dt>Operation ID</dt><dd><code>{operation.id}</code></dd><dt>Direction</dt><dd>{operation.direction}</dd><dt>Visibility / completeness</dt><dd>{operation.visibility} / {operation.completeness}</dd><dt>Last observation</dt><dd>{operation.last_seen}</dd><dt>Current approved baseline</dt><dd><code>{operation.approved_contract_id ?? 'None'}</code></dd></dl>}
        </section>
        <section className="panel" aria-labelledby="import-title"><p className="step">02 / DECLARED INPUT</p><h2 id="import-title">Import a contract</h2><p>Upload baseline and candidate separately. The platform sanitizes each artifact before storage.</p>
          <form onSubmit={e => void importContract(e)}><fieldset disabled={locked}><label htmlFor="project">Project UUID</label><input id="project" required pattern={uuidPattern} value={project} onChange={e => setProject(e.target.value)} />
            <label htmlFor="service">Service UUID</label><input id="service" required pattern={uuidPattern} value={service} onChange={e => setService(e.target.value)} />
            <label htmlFor="format">Declared format</label><select id="format" value={format} onChange={e => setFormat(e.target.value as ImportFormat)}><option value="openapi_json">OpenAPI JSON</option><option value="asyncapi_json">AsyncAPI JSON</option><option value="graphql_sdl">GraphQL SDL</option><option value="protobuf_descriptor">Protobuf descriptor</option></select>
            <label htmlFor="artifact">Artifact · maximum 5 MiB</label><input ref={fileInput} id="artifact" type="file" required onChange={e => {setFile(e.target.files?.[0] ?? null); setImported(null);}} />
            <button type="submit" disabled={!file || stale}>Import declared contract</button></fieldset></form>
          {imported && <div className="import-result"><p><strong>Declared contract</strong> · revision {imported.revision}</p><code>{imported.id}</code><p>Warnings: {imported.warnings.length ? imported.warnings.join(', ') : 'None reported'}</p><div className="actions"><button className="secondary" disabled={locked || !!review} onClick={() => {setLeft(imported.id); setLeftKind('declared'); resetComparison();}}>Use as left baseline</button><button className="secondary" disabled={locked || !!review} onClick={() => {setRight(imported.id); resetComparison();}}>Use as right candidate</button></div></div>}
        </section>
      </div>
      <section className="panel" aria-labelledby="compare-title"><p className="step">03 / EXACT COMPARISON</p><h2 id="compare-title">Compare baseline → candidate</h2><p>Enter exact public contract IDs. A declared baseline does not become approved by importing it.</p>
        <form onSubmit={e => void compare(e)}><fieldset disabled={locked || !!review}><div className="grid inputs"><div><label htmlFor="left-kind">Left baseline kind</label><select id="left-kind" value={leftKind} onChange={e => {setLeftKind(e.target.value as Kind); resetComparison();}}><option value="declared">Declared</option><option value="approved">Approved</option><option value="observed">Observed</option></select><label htmlFor="left">Left immutable version UUID</label><input id="left" required pattern={uuidPattern} value={left} onChange={e => {setLeft(e.target.value); resetComparison();}} /></div><div><label htmlFor="right">Right declared candidate UUID</label><input id="right" required pattern={uuidPattern} value={right} onChange={e => {setRight(e.target.value); resetComparison();}} /><p className="hint">The right version is the candidate submitted for approval.</p></div></div><button disabled={!canCompare || stale}>Compare exact versions</button></fieldset></form>
        {comparison && <div className="result"><h3 ref={heading} tabIndex={-1}>Result: <span className={`badge ${comparison.result}`}>{comparison.result}</span></h3><p>Direction: <strong>{comparison.direction}</strong> · comparison <code>{comparison.id}</code></p><p><strong>{comparison.left_kind}</strong> <code>{comparison.left_id}</code> → <strong>{comparison.right_kind}</strong> <code>{comparison.right_id}</code></p>
          {comparison.result === 'inconclusive' && <p className="warning">Evidence is insufficient or includes unsupported constructs. This is not a compatibility pass.</p>}
          {comparison.differences.length === 0 ? <p className="empty">No differences returned. This does not establish observed coverage.</p> : <div className="table-scroll"><table><caption>Exact structural differences</caption><thead><tr><th scope="col">Path</th><th scope="col">Change</th><th scope="col">Assessment</th><th scope="col">Evidence reason</th></tr></thead><tbody>{comparison.differences.map((d, i) => <tr key={i}><td><code>{d.path}</code></td><td>{d.kind}</td><td>{d.assessment}</td><td>{d.reason}</td></tr>)}</tbody></table></div>}
          {!review && <><button aria-describedby={reviewBlock ? 'review-eligibility' : undefined} disabled={locked || stale || reviewBlock !== null} onClick={() => void createReview()}>Create pending review</button>{reviewBlock && <p id="review-eligibility" className="hint">{reviewBlock}</p>}</>}
        </div>}
      </section>
      <section className="panel" aria-labelledby="review-title"><p className="step">04 / RECORDED DECISION</p><h2 id="review-title">Review the exact candidate</h2>
        {!review && <form onSubmit={e => void reloadReview(e)}><label htmlFor="review-id">Existing review UUID</label><div className="actions"><input id="review-id" required pattern={uuidPattern} value={reloadId} disabled={locked} onChange={e => setReloadId(e.target.value)} /><button className="secondary" disabled={locked || !validUuid(reloadId)}>Load review</button></div></form>}
        {review ? <><dl><dt>Review / revision</dt><dd><code>{review.id}</code> / {review.revision}</dd><dt>Status</dt><dd><strong>{review.status}</strong></dd><dt>Exact candidate</dt><dd><code>{review.candidate_contract_id}</code></dd><dt>Expected approved baseline</dt><dd><code>{review.expected_baseline_id ?? 'None — first approval'}</code></dd>{review.deciding_actor_id && <><dt>Deciding actor</dt><dd><code>{review.deciding_actor_id}</code></dd><dt>Decided at</dt><dd>{review.decided_at}</dd></>}</dl>
          {review.status === 'pending' && <><p>Approval replaces the expected approved baseline with this exact candidate. The server records your verified identity and checks revision {review.revision} atomically.</p><div className="actions"><button disabled={locked || stale} onClick={() => void decide('approve')}>Approve exact candidate</button><button className="danger" disabled={locked || stale} onClick={() => void decide('reject')}>Reject review</button></div></>}
          <div className="actions"><button className="secondary" disabled={locked} onClick={() => void reloadReview()}>Reload exact review</button><button className="secondary" disabled={locked} onClick={() => {setReview(null); setComparison(null); setStale(false); setStatus('Start a new exact comparison. Reload the catalog to refresh the approved baseline.'); setOperation(null);}}>Start new comparison</button></div>
        </> : <p className="empty">Create a pending review from a comparison, or load one by its exact ID.</p>}
      </section>
      <footer>APIContour · Immutable evidence. Explicit decisions. <span>Review workspace slice</span></footer>
    </main>
  </div>;
}

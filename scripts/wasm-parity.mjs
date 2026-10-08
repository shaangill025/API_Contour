import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const [modulePath, casesPath] = process.argv.slice(2);
const bytes = readFileSync(modulePath);
const module = new WebAssembly.Module(bytes);
assert.deepEqual(WebAssembly.Module.imports(module), [], 'unexpected WASM imports');
const e = new WebAssembly.Instance(module).exports;
const names = ['memory', '__data_end', '__heap_base',
  'contour_wasm_input_v1', 'contour_wasm_canonical_v1', 'contour_wasm_fingerprint_v1',
  'contour_wasm_capacity_v1', 'contour_wasm_canonical_length_v1',
  'contour_wasm_fingerprint_length_v1', 'contour_wasm_process_v1'];
assert.ok(Object.keys(e).every(name => names.includes(name)), 'unexpected WASM export');
assert.ok(e.memory instanceof WebAssembly.Memory, 'missing linear memory');
assert.ok(!(e.memory.buffer instanceof SharedArrayBuffer), 'shared memory forbidden');
assert.equal(e.contour_wasm_capacity_v1(), 65536);
const offsets = [e.contour_wasm_input_v1(), e.contour_wasm_canonical_v1(), e.contour_wasm_fingerprint_v1()];
const sizes = [65536, 65536, 64];
for (let i = 0; i < 3; i++) {
  assert.ok(offsets[i] >= 0 && offsets[i] + sizes[i] <= e.memory.buffer.byteLength);
  for (let j = i + 1; j < 3; j++)
    assert.ok(offsets[i] + sizes[i] <= offsets[j] || offsets[j] + sizes[j] <= offsets[i], 'overlapping regions');
}
const region = i => new Uint8Array(e.memory.buffer, offsets[i], sizes[i]);
const cases = JSON.parse(readFileSync(casesPath, 'utf8'));
const results = [];
for (let round = 0; round < 3; round++) {
  for (const item of cases) {
    const input = Buffer.from(item.input, 'base64');
    region(0).set(input.subarray(0, 65536));
    const status = e.contour_wasm_process_v1(input.length);
    assert.ok(region(0).every(value => value === 0), 'input was not cleared');
    let output;
    if (item.canonical === null) {
      assert.equal(status, 2, 'invalid structure accepted');
      assert.equal(e.contour_wasm_canonical_length_v1(), 0, 'stale canonical length');
      assert.equal(e.contour_wasm_fingerprint_length_v1(), 0, 'stale fingerprint length');
      assert.ok(region(1).every(value => value === 0) && region(2).every(value => value === 0), 'stale output bytes');
      output = '2\n';
    } else {
      assert.equal(status, 0, 'valid structure rejected');
      const expected = Buffer.from(item.canonical, 'utf8');
      assert.equal(e.contour_wasm_canonical_length_v1(), expected.length);
      assert.equal(e.contour_wasm_fingerprint_length_v1(), 64);
      const canonical = Buffer.from(region(1).subarray(0, expected.length));
      assert.ok(canonical.equals(expected), 'canonical mismatch');
      const fingerprint = Buffer.from(region(2)).toString('ascii');
      const hash = createHash('sha256').update('apicontour/structure/1\n').update(expected).digest('hex');
      assert.equal(fingerprint, hash, 'fingerprint mismatch');
      assert.ok(region(1).subarray(expected.length).every(value => value === 0), 'stale output suffix');
      output = '0\n' + hash + '\n' + item.canonical;
    }
    if (round === 0) results.push(Buffer.from(output).toString('base64'));
  }
  assert.equal(e.contour_wasm_process_v1(-1), 2, 'wrapped unsigned length accepted');
  assert.equal(e.contour_wasm_canonical_length_v1(), 0);
  assert.equal(e.contour_wasm_fingerprint_length_v1(), 0);
  // A legal growth detaches prior host views; the same offsets must still work.
  if (round === 0) e.memory.grow(1);
}
assert.throws(() => e.memory.grow(257), RangeError, 'module memory ceiling missing');
process.stdout.write(JSON.stringify({ results, node: process.version,
  memory_bytes: e.memory.buffer.byteLength, imports: [], rounds: 3 }));

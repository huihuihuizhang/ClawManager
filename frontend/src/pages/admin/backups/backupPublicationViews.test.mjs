import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
import React from 'react';
import * as jsx from 'react/jsx-runtime';
import { renderToStaticMarkup } from 'react-dom/server';

const compile = name => ts.transpileModule(readFileSync(new URL(name, import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;
const decoder = {}; runInNewContext(compile('./backupPublicationRead.ts'), { exports: decoder, AbortController });
const messages = {}; runInNewContext(compile('./messages.ts'), { exports: messages });
function component(name, service, hooks = React) {
  const exports = {};
  runInNewContext(compile(name), { exports, require: id => {
    if (id === 'react') return hooks;
    if (id === 'react/jsx-runtime') return jsx;
    if (id.endsWith('systemBackupReadService')) return { systemBackupPublicationReadService: service };
    if (id === './backupPublicationRead') return decoder;
    if (id === './messages') return messages;
    if (id === './useBackupText') return { useBackupText: () => ({ locale: 'en-US' }) };
    throw new Error(id);
  } });
  return exports.default;
}

test('live publication views are on demand and initial rendering never claims a successful read', () => {
  let calls = 0;
  const service = { catalog() { calls++; }, record() { calls++; }, manifest() { calls++; } };
  const catalog = renderToStaticMarkup(React.createElement(component('./BackupLiveCatalog.tsx', service), { installation: 'installation_original' }));
  assert.match(catalog, /Read catalog/); assert.match(catalog, /eventually consistent/); assert.doesNotMatch(catalog, /Original bytes match/);
  const detail = { task: { status: 'succeeded', origin_installation_id: 'installation_original', public_id: 'sbk_original', row_version: 2 }, artifact_state: 'committed', artifact_registration_id: 'scr_original', artifact_registration_hash: 'a'.repeat(64), checksums: { manifest: 'b'.repeat(64) } };
  const manifest = renderToStaticMarkup(React.createElement(component('./BackupLiveManifest.tsx', service), { detail }));
  assert.match(manifest, /Read manifest/); assert.match(manifest, /does not independently verify signatures/); assert.doesNotMatch(manifest, /Original bytes match/);
  const pending = renderToStaticMarkup(React.createElement(component('./BackupLiveManifest.tsx', service), { detail: { ...detail, task: { ...detail.task, status: 'validating' } } }));
  assert.match(pending, /does not yet contain complete references/); assert.doesNotMatch(pending, /<button/); assert.equal(calls, 0);
});

// Execute the actual compiled component and its event handlers with explicit
// hook state/effect lifetimes. This is a component-logic test, not browser QA.
function view(name) {
  let slots = [], work = [], pendingEffects = [], cursor = 0, props, tree, writes = 0;
  const effect = (body, deps) => {
    const n = cursor++, previous = slots[n];
    if (!previous || deps.some((d, i) => !Object.is(d, previous.deps[i]))) pendingEffects.push(() => { previous?.cleanup?.(); work[n] = { deps, cleanup: body() }; });
  };
  const hooks = {
    useState(initial) {
      const n = cursor++, box = work[n] ?? { value: typeof initial === 'function' ? initial() : initial }; work[n] = box;
      return [box.value, value => { writes++; box.value = typeof value === 'function' ? value(box.value) : value; }];
    },
    useMemo(factory, deps) {
      const n = cursor++, previous = slots[n];
      if (!previous || deps.some((d, i) => !Object.is(d, previous.deps[i]))) work[n] = { deps, value: factory() };
      return work[n].value;
    },
    useEffect: effect,
    useLayoutEffect: effect,
  };
  const Component = component(name, {}, hooks);
  function nodes(value) {
    if (Array.isArray(value)) return value.flatMap(nodes);
    if (value && typeof value === 'object' && 'props' in value) return [value, ...nodes(value.props.children)];
    return [];
  }
  const content = value => Array.isArray(value) ? value.map(content).join(' ') : value && typeof value === 'object' && 'props' in value ? content(value.props.children) : typeof value === 'string' || typeof value === 'number' ? String(value) : '';
  return {
    render(next = props) { cursor = 0; work = slots.slice(); pendingEffects = []; const nextTree = Component(next); while (pendingEffects.length) pendingEffects.shift()(); slots = work; props = next; tree = nextTree; return content(tree); },
    speculate(next) { cursor = 0; work = slots.slice(); pendingEffects = []; const result = content(Component(next)); pendingEffects = []; work = []; return result; },
    click(label) { const button = nodes(tree).find(n => n.type === 'button' && content(n.props.children) === label); assert.ok(button, label); button.props.onClick(); },
    unmount() { slots.forEach(s => s.cleanup?.()); },
    get writes() { return writes; },
  };
}
const settle = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('catalog ready content disappears on reader change and a late old-reader promise cannot write state', async () => {
  const item = { id: 'scr_original', backup: 'sbk_original', record_sha256: 'a'.repeat(64), manifestSHA256: 'b'.repeat(64), raw: 'ORIGINAL_SIGNED_CONTENT' };
  const page = { items: [item], next_cursor: null, consistency: 'eventual' };
  const later = deferred(); let reads = 0, oldSignal;
  const first = { catalog: async () => page, record: async (_installation, _id, signal) => { oldSignal = signal; return ++reads === 1 ? item : later.promise; } };
  const second = { catalog: async () => page, record: async () => item };
  const h = view('./BackupLiveCatalog.tsx');
  h.render({ installation: 'installation_original', reader: first }); h.click('Read catalog'); await settle(); h.render();
  h.click('Read original record'); await settle(); assert.match(h.render(), /ORIGINAL_SIGNED_CONTENT/);
  assert.doesNotMatch(h.render({ installation: 'installation_original', reader: second }), /ORIGINAL_SIGNED_CONTENT|scr_original/);
  h.render({ installation: 'installation_original', reader: first }); h.click('Read catalog'); await settle(); h.render(); h.click('Read original record'); h.render();
  h.render({ installation: 'installation_original', reader: second }); const writes = h.writes;
  assert.equal(oldSignal.aborted, true); later.resolve(item); await settle(); assert.equal(h.writes, writes);
  assert.doesNotMatch(h.render(), /ORIGINAL_SIGNED_CONTENT/); h.unmount();
});

test('an abandoned speculative reader render cannot withdraw the committed request or leak its result', async () => {
  const detail = { task: { status: 'succeeded', origin_installation_id: 'installation_original', public_id: 'sbk_original', row_version: 2 }, artifact_state: 'committed', artifact_registration_id: 'scr_original', artifact_registration_hash: 'a'.repeat(64), checksums: { manifest: 'b'.repeat(64) } };
  const later = deferred(); let signal;
  const committed = { manifest: async (_detail, s) => { signal = s; return later.promise; } };
  const speculative = { manifest: async () => { throw new Error('must not run'); } };
  const h = view('./BackupLiveManifest.tsx');
  h.render({ detail, reader: committed }); h.click('Read manifest'); h.render();
  assert.doesNotMatch(h.speculate({ detail, reader: speculative }), /Original bytes match/);
  assert.equal(signal.aborted, false);
  const writes = h.writes; later.resolve({ raw: 'COMMITTED_READER_RESULT', sha256: 'b'.repeat(64) }); await settle();
  assert.equal(h.writes, writes + 1); assert.match(h.render(), /COMMITTED_READER_RESULT/);
  assert.doesNotMatch(h.render({ detail, reader: speculative }), /COMMITTED_READER_RESULT/); h.unmount();
});

test('manifest ready content is reader-bound; task switch and unmount reject late results', async () => {
  const detail = { task: { status: 'succeeded', origin_installation_id: 'installation_original', public_id: 'sbk_original', row_version: 2 }, artifact_state: 'committed', artifact_registration_id: 'scr_original', artifact_registration_hash: 'a'.repeat(64), checksums: { manifest: 'b'.repeat(64) } };
  const later = deferred(); let reads = 0, lastSignal;
  const first = { manifest: async (_detail, signal) => { lastSignal = signal; return ++reads === 1 ? { raw: 'ORIGINAL_MANIFEST', sha256: 'b'.repeat(64) } : later.promise; } };
  const second = { manifest: async () => { throw new Error('permission_denied'); } };
  const h = view('./BackupLiveManifest.tsx');
  h.render({ detail, reader: first }); h.click('Read manifest'); await settle(); assert.match(h.render(), /ORIGINAL_MANIFEST/);
  assert.doesNotMatch(h.render({ detail, reader: second }), /ORIGINAL_MANIFEST|Original bytes match/);
  h.click('Read manifest'); await settle(); assert.match(h.render(), /Read failed/); assert.doesNotMatch(h.render(), /Original bytes match/);
  h.render({ detail, reader: first }); h.click('Read manifest'); h.render();
  const next = { ...detail, task: { ...detail.task, public_id: 'sbk_next' } };
  assert.doesNotMatch(h.render({ detail: next, reader: first }), /ORIGINAL_MANIFEST/);
  const writes = h.writes; assert.equal(lastSignal.aborted, true); later.resolve({ raw: 'LATE_OLD_TASK', sha256: 'b'.repeat(64) }); await settle();
  assert.equal(h.writes, writes); assert.doesNotMatch(h.render(), /LATE_OLD_TASK/);
  h.click('Read manifest'); h.unmount(); assert.equal(lastSignal.aborted, true);
});

test('new selection, refresh and unmount invalidate even late transport resolutions', async () => {
  const gate = decoder.createPublicationRequestGate(), shown = [];
  let complete;
  const old = gate.start();
  const result = new Promise(resolve => { complete = resolve; }).then(value => { if (old.active()) shown.push(value); });
  const current = gate.start(); assert.equal(old.signal.aborted, true); assert.equal(current.active(), true);
  complete('old task result'); await result; assert.deepEqual(shown, []);
  gate.cancel(); assert.equal(current.signal.aborted, true); assert.equal(current.active(), false);
  const refreshed = gate.start(); assert.equal(refreshed.active(), true); gate.cancel(); assert.equal(refreshed.active(), false);
});

test('client and live copy distinguish digest checking from signature trust and recovery eligibility', () => {
  for (const locale of ['en-US', 'zh-CN']) {
    const text = messages.publicationMessages(locale);
    assert.ok(text.trust.length > 20); assert.ok(text.catalogNote.length > 20);
  }
  assert.match(messages.publicationMessages('en-US').trust, /does not independently verify signatures/);
  assert.match(messages.publicationMessages('zh-CN').trust, /未执行独立客户端验签/);
});

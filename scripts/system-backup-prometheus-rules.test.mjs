import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { renderPrometheusRules } from './system-backup-prometheus-rules.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = readFileSync(join(root, 'contracts/system-backup/v12/metrics-alert-registry.json'), 'utf8');
const registry = JSON.parse(source);
const sourceHash = createHash('sha256').update(source).digest('hex');

test('candidate Prometheus rules preserve every PromQL alert without claiming controller-state execution', () => {
  const rendered = renderPrometheusRules(registry, sourceHash);
  const checkedIn = readFileSync(join(root, 'contracts/system-backup/v12/prometheus-alert-rules.yaml'), 'utf8');
  assert.equal(checkedIn, rendered);
  assert.match(rendered, /DO NOT LOAD: no rule loader, missing-series execution, or PromQL fixture validation exists yet/);
  const compiled = registry.alerts.filter((alert) => alert.expression_language === 'promql');
  const controllerState = registry.alerts.filter((alert) => alert.expression_language === 'controller_state');
  assert.equal(compiled.length, 95);
  assert.equal(controllerState.length, 4);
  assert.equal((rendered.match(/^      - alert: /gm) ?? []).length, compiled.length);
  for (const alert of compiled) {
    assert.ok(rendered.includes(`contract_rule_id: ${JSON.stringify(alert.id)}`), `${alert.id} was omitted`);
    assert.ok(rendered.includes(`expr: ${JSON.stringify(alert.expression)}`), `${alert.id} expression drifted`);
  }
  for (const alert of controllerState) {
    assert.ok(!rendered.includes(`contract_rule_id: ${JSON.stringify(alert.id)}`), `${alert.id} must use the controller evaluator`);
  }
});

test('candidate generator rejects duplicate or unassigned rules', () => {
  const duplicate = structuredClone(registry);
  duplicate.alerts[1].id = duplicate.alerts[0].id;
  assert.throws(() => renderPrometheusRules(duplicate, sourceHash), /duplicate alert ID/);
  const unknown = structuredClone(registry);
  unknown.alerts[0].expression_language = 'unknown';
  assert.throws(() => renderPrometheusRules(unknown, sourceHash), /unknown evaluator/);
  const missing = structuredClone(registry);
  missing.alerts.pop();
  assert.throws(() => renderPrometheusRules(missing, sourceHash), /inventory is incomplete/);
});

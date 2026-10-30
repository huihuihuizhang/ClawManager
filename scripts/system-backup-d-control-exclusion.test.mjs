import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const read=p=>readFileSync(join(root,p),'utf8'),json=p=>JSON.parse(read(p));
const registry=json('contracts/system-backup/v12/schema-registry.json');
const schema=json('contracts/system-backup/v12/verifier-contract.schema.json');
const runtime=read('backend/internal/systembackupresources/control_exclusion.go');
const four=['system_backup_v2_admin_revocations','system_backup_v2_admin_sessions','system_backup_v2_metadata_reservations','system_backup_v2_totp_credentials'];
const controls=registry.objects.filter(o=>o.category==='system_backup'&&o.name!=='schema_migrations');
const map=runtime.match(/var controlExclusionTables = map\[string\]struct\{\}\{([\s\S]*?)\n\}/);
assert.ok(map,'closed runtime control map missing');
const runtimeNames=[...map[1].matchAll(/"([a-z0-9_]+)"\s*:/g)].map(m=>m[1]).sort();
const migrationMap=json('docs/backup-team-integration/sql-map.json').files;
const currentMigration=file=>{
 const name=file.split('/').at(-1);
 return migrationMap[name] ? 'backend/internal/db/migrations/'+migrationMap[name] : file;
};
const contractIDs=schema.$defs.ControlExclusionCheck.allOf[1].properties.id.enum;
test('D control exclusion covers the implemented 35-table capability and exposes pending integration',()=>{
 assert.equal(controls.length,35);assert.equal(new Set(runtimeNames).size,35);assert.equal(contractIDs.length,35);assert.equal(new Set(contractIDs).size,35);
 const pending=registry.objects.find(o=>o.name==='system_backup_v2_execution_records');
 assert.ok(pending);assert.equal(pending.decision_status,'pending_owner_review');assert.deepEqual(pending.approved_cross_reviewers,[]);
 assert.equal(pending.backup_strategy,null);assert.equal(pending.restore_strategy,null);
 assert.ok(!runtimeNames.includes(pending.name));
 assert.equal(registry.contract_status,'draft');
 assert.deepEqual(runtimeNames,controls.map(o=>o.name).sort());
 assert.deepEqual([...contractIDs].sort(),runtimeNames.map(n=>'control_plane.empty.'+n));
 assert.ok(!runtimeNames.includes('schema_migrations'));
});
test('D runtime control exclusions retain metadata-only reference-only owner policies',()=>{
 for(const name of four){const o=controls.find(o=>o.name===name);assert.ok(o,name);assert.equal(o.object_type,'table');assert.equal(o.owner,'D');assert.equal(o.backup_strategy,'metadata_only');assert.equal(o.restore_strategy,'reference_only');assert.ok(contractIDs.includes('control_plane.empty.'+name));assert.ok(o.sources.migration.length>0);for(const file of o.sources.migration)assert.ok(read(currentMigration(file)).includes(name),file);}
});
test('D control exclusion keeps redacted count payloads and generic wire DTOs',()=>{
 const defs=schema.$defs;assert.equal(defs.ControlExclusionCheck.allOf[1].properties.expected.$ref,'#/$defs/ResourcesCountValue');assert.equal(defs.ControlExclusionCheck.allOf[1].properties.actual.$ref,'#/$defs/ResourcesCountValue');
 const parity=json('contracts/system-backup/v12/dto-parity.json');assert.ok(!parity.schema_sources.includes('contracts/system-backup/v12/verifier-contract.schema.json'));assert.equal(parity.status,'draft');
});

test('D implemented control exclusion count agrees with schema IDs and runtime',()=>{
 const declaration=schema['x-owner-check-registries'].D.control_plane_restore_validate;
 assert.equal(declaration.check_schema,'#/$defs/ControlExclusionCheck');
 assert.equal(declaration.required_check_count,contractIDs.length);
 assert.equal(declaration.required_check_count,controls.length);
 assert.equal(declaration.required_check_count,runtimeNames.length);
});

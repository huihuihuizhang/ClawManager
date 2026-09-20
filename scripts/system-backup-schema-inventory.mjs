#!/usr/bin/env node
// P0-0a ownership inventory. This is deliberately not the frozen schema registry:
// classification, strategies, normalization and verifiers require owner review.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const planPath = join(root, 'docs/system-backup-restore-division-plan.md');
const migrationDir = join(root, 'backend/internal/db/migrations');
const repositoryDir = join(root, 'backend/internal/repository');
const reportPath = join(root, 'docs/system-backup-restore-schema-inventory.json');
const args = process.argv.slice(2);
const has = (flag) => args.includes(flag);
const valueAfter = (flag) => {
  const index = args.indexOf(flag);
  if (index < 0) return undefined;
  if (!args[index + 1] || args[index + 1].startsWith('--')) throw new Error(`${flag} needs a file path`);
  return resolve(args[index + 1]);
};
const sourcePath = (path) => relative(root, path).replaceAll('\\', '/');
const sorted = (items) => [...items].sort((a, b) => a.localeCompare(b, 'en'));

function readOwnership() {
  const plan = readFileSync(planPath, 'utf8');
  const version = plan.match(/system-backup-plan\.v\d+/)?.[0];
  const section = plan.split('### 5.1 当前对象归属')[1]?.split('### 5.2 覆盖规则')[0];
  if (!version || !section) throw new Error('Cannot locate plan version or section 5.1');
  const owners = new Map();
  for (const match of section.matchAll(/^\|\s*([a-z_]+)\s*\|\s*([ABCD])\s*\|\s*(.*?)\s*\|\s*$/gm)) {
    const [, category, owner, names] = match;
    for (const nameMatch of names.matchAll(/`([a-z][a-z0-9_]*)`/g)) {
      const name = nameMatch[1];
      if (owners.has(name)) throw new Error(`Duplicate owner for ${name}`);
      owners.set(name, { owner, category });
    }
  }
  if (owners.size === 0) throw new Error('No owned objects found in plan section 5.1');
  return { version, owners };
}

function readPlannedControlTables() {
  const plan = readFileSync(planPath, 'utf8');
  const section = plan.split('### 6.2 逐表附加字段')[1]?.split('### 6.3 ')[0];
  if (!section) throw new Error('Cannot locate plan section 6.2');
  const names = [...section.matchAll(/^\|\s*`([a-z][a-z0-9_]*)`\s*\|/gm)].map((match) => match[1]);
  if (names.length === 0 || new Set(names).size !== names.length) {
    throw new Error('Plan section 6.2 has no unique control-table list');
  }
  return sorted(names);
}

function scanCreateStatements(directory, extension) {
  const objects = new Map();
  const create = /^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT)\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-z][a-z0-9_]*)`?\b/gim;
  for (const filename of sorted(readdirSync(directory).filter((name) => name.endsWith(extension)))) {
    const fullPath = join(directory, filename);
    const raw = readFileSync(fullPath, 'utf8');
    // Comments are stripped only for discovery; this is not a SQL parser.
    const text = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*--[^\r\n]*$/gm, '');
    for (const match of text.matchAll(create)) {
      const type = match[1].toLowerCase();
      const objectType = type === 'event' ? 'mysql_event' : ['procedure', 'function'].includes(type) ? 'routine' : type;
      const key = `${objectType}:${match[2].toLowerCase()}`;
      if (!objects.has(key)) objects.set(key, new Set());
      objects.get(key).add(sourcePath(fullPath));
    }
  }
  return objects;
}

function scanDeploymentCreates() {
  const objects = new Map();
  for (const flavor of ['k8s', 'k3s']) {
    for (const profile of ['cluster', 'single-node']) {
      const fullPath = join(root, 'deployments', flavor, profile, 'clawmanager.yaml');
      const raw = readFileSync(fullPath, 'utf8');
      for (const match of raw.matchAll(/^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-z][a-z0-9_]*)`?\b/gim)) {
        const key = `table:${match[1].toLowerCase()}`;
        if (!objects.has(key)) objects.set(key, new Set());
        objects.get(key).add(sourcePath(fullPath));
      }
    }
  }
  return objects;
}

function scanRepositoryAlters() {
  const alters = new Map();
  for (const filename of sorted(readdirSync(repositoryDir).filter((name) => name.endsWith('.go')))) {
    const fullPath = join(repositoryDir, filename);
    const raw = readFileSync(fullPath, 'utf8');
    for (const match of raw.matchAll(/\bALTER\s+TABLE\s+`?([a-z][a-z0-9_]*)`?\b/gim)) {
      const name = match[1].toLowerCase();
      if (!alters.has(name)) alters.set(name, new Set());
      alters.get(name).add(sourcePath(fullPath));
    }
  }
  return alters;
}

function readLines(path) {
  return new Set(readFileSync(path, 'utf8').split(/\r?\n/).map((line) => line.trim()).filter(Boolean));
}

function readDbObjects(path) {
  const objects = new Set();
  for (const [index, line] of readFileSync(path, 'utf8').split(/\r?\n/).entries()) {
    if (!line.trim() || line.startsWith('object_type\t')) continue;
    const [type, name, ...extra] = line.trim().split('\t');
    if (extra.length || !/^(table|view|trigger|routine|mysql_event)$/.test(type) || !/^[a-z][a-z0-9_]*$/.test(name)) {
      throw new Error(`Invalid database object TSV line ${index + 1}`);
    }
    objects.add(`${type}:${name}`);
  }
  return objects;
}

function buildReport() {
  const { version, owners } = readOwnership();
  const plannedControlTables = readPlannedControlTables();
  const migrationObjects = scanCreateStatements(migrationDir, '.sql');
  const repositoryObjects = scanCreateStatements(repositoryDir, '.go');
  const repositoryAlters = scanRepositoryAlters();
  const deploymentObjects = scanDeploymentCreates();
  const bookkeeping = readFileSync(join(root, 'backend/internal/db/migrations.go'), 'utf8');
  if (!/schemaMigrationsTable\s*=\s*"schema_migrations"/.test(bookkeeping)) {
    throw new Error('Migration bookkeeping table source changed');
  }
  const allKeys = new Set([...migrationObjects.keys(), ...repositoryObjects.keys(), ...deploymentObjects.keys(), ...[...repositoryAlters.keys()].map((name) => `table:${name}`), ...[...owners.keys()].map((name) => `table:${name}`)]);
  allKeys.add('table:schema_migrations');
  const plannedControlWithoutInventory = plannedControlTables.filter((name) => !allKeys.has(`table:${name}`));
  const objects = sorted(allKeys).map((key) => {
    const [object_type, name] = key.split(':');
    const assignment = key === 'table:schema_migrations'
      ? { owner: 'D', category: 'system_backup' }
      : object_type === 'table' ? owners.get(name) ?? null : null;
    return {
      object_type,
      name,
      owner: assignment?.owner ?? null,
      category: assignment?.category ?? null,
      migration_sources: sorted(migrationObjects.get(key) ?? []),
      repository_create_sources: sorted(repositoryObjects.get(key) ?? []),
      repository_alter_sources: sorted(repositoryAlters.get(name) ?? []),
      deployment_bootstrap_create_sources: sorted(deploymentObjects.get(key) ?? []),
      source_exception: key === 'table:schema_migrations' ? 'migration_runner_bookkeeping' : null,
    };
  });
  const withoutMigration = objects.filter((item) => !item.migration_sources.length && !item.source_exception).map((item) => item.name);
  const unassigned = objects.filter((item) => !item.owner).map((item) => `${item.object_type}:${item.name}`);
  const runtimeDDL = objects.filter((item) => item.repository_create_sources.length).map((item) => item.name);
  const runtimeAlter = objects.filter((item) => item.repository_alter_sources.length).map((item) => item.name);
  const deploymentCreate = objects.filter((item) => item.deployment_bootstrap_create_sources.length).map((item) => item.name);
  const report = {
    kind: 'ownership_inventory_only',
    plan_version: version,
    plan_source: sourcePath(planPath),
    summary: {
      plan_business_tables: owners.size,
      plan_control_tables: plannedControlTables.length,
      plan_control_without_inventory: plannedControlWithoutInventory.length,
      inventoried_objects: objects.length,
      migration_objects: migrationObjects.size,
      without_migration: withoutMigration.length,
      unassigned: unassigned.length,
      repository_runtime_create: runtimeDDL.length,
      repository_runtime_alter: runtimeAlter.length,
      deployment_bootstrap_create: deploymentCreate.length,
    },
    gaps: {
      plan_control_without_inventory: plannedControlWithoutInventory,
      without_migration: sorted(withoutMigration),
      unassigned: sorted(unassigned),
      repository_runtime_create: sorted(runtimeDDL),
      repository_runtime_alter: sorted(runtimeAlter),
      deployment_bootstrap_create: sorted(deploymentCreate),
    },
    objects,
  };
  return report;
}

try {
  const report = buildReport();
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (has('--write')) writeFileSync(reportPath, output);
  if (has('--check') && (!existsSync(reportPath) || readFileSync(reportPath, 'utf8') !== output)) {
    throw new Error(`${sourcePath(reportPath)} is missing or stale; run with --write`);
  }
  const dbPath = valueAfter('--db-objects');
  const appliedPath = valueAfter('--applied');
  if (Boolean(dbPath) !== Boolean(appliedPath)) throw new Error('--db-objects and --applied must be used together');
  if (dbPath) {
    const observed = readDbObjects(dbPath);
    const applied = readLines(appliedPath);
    const expected = new Set(report.objects.filter((item) => item.source_exception || item.migration_sources.some((path) => applied.has(path.split('/').at(-1)))).map((item) => `${item.object_type}:${item.name}`));
    const outsideMigrations = [...observed].filter((key) => !expected.has(key));
    const knownRuntimeOnly = new Set(report.objects.filter((item) => item.repository_create_sources.length && !item.migration_sources.length).map((item) => `${item.object_type}:${item.name}`));
    report.database_comparison = {
      missing_from_database: sorted([...expected].filter((key) => !observed.has(key))),
      runtime_only_in_database: sorted(outsideMigrations.filter((key) => knownRuntimeOnly.has(key))),
      unexpected_in_database: sorted(outsideMigrations.filter((key) => !knownRuntimeOnly.has(key))),
      unknown_applied_migrations: sorted([...applied].filter((name) => !existsSync(join(migrationDir, name)))),
    };
  }
  process.stdout.write(`${JSON.stringify({ summary: report.summary, gaps: report.gaps, database_comparison: report.database_comparison ?? null }, null, 2)}\n`);
  if (has('--strict') && (report.summary.plan_control_without_inventory || report.summary.without_migration || report.summary.unassigned || report.summary.repository_runtime_create || report.summary.repository_runtime_alter || report.summary.deployment_bootstrap_create || report.database_comparison?.missing_from_database.length || report.database_comparison?.runtime_only_in_database.length || report.database_comparison?.unexpected_in_database.length || report.database_comparison?.unknown_applied_migrations.length)) {
    process.exitCode = 1;
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}

#!/usr/bin/env python3
"""Reauthor source DATA after the observed Redis certificate renewal, no grant."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
BIN = Path('/root/sbk/p2-jwt-api-c888315f/system-backup-first-install-materials')
BIN_SHA = '55c279a67b84c88c21eef9615cc29d31ac7457e58ac4c997f19b72a4b0357de9'
CA_SHA = 'f22c2e994100cb0abb52b8d059f055f19f6e86cb2c61ee9b71f6268701f79636'


def need(ok, why):
    if not ok: raise ValueError(why)


def replace_ca(value, old, new):
    if isinstance(value, dict):
        return {k: replace_ca(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [replace_ca(v, old, new) for v in value]
    if value == old['File']: return new['File']
    if value == old['SHA256']: return new['SHA256']
    return value


def successor(original, keeper, new_ca, old_out, out):
    value = copy.deepcopy(original)
    need(value['Version'] == 'original-initial-source-author-inputs.v1', 'original author definition required')
    core = value['Deployment']
    need(core['redis_read_keepers'] == [keeper], 'original Redis keeper binding differs')
    connections = [c for c in value['Connections'] if c['Purpose'] == 'source_redis']
    need(len(connections) == 1 and connections[0]['CA'] == keeper['CA'] and
         connections[0]['Credential'] == keeper['ReaderCredential'], 'original reader binding differs')
    need(value['Materials']['DeploymentConfigSHA256'] == '' and value['Materials']['CaptureGrantSHA256'] == '', 'unissued source template required')
    core['redis_read_keepers'] = replace_ca(core['redis_read_keepers'], keeper['CA'], new_ca)
    connections[0]['CA'] = copy.deepcopy(new_ca)
    value['Materials']['Redis'] = replace_ca(value['Materials']['Redis'], keeper['CA'], new_ca)
    need(core['profile_file'] == str(old_out/'execution-profile.json') and
         core['capture_modules']['path'] == str(old_out/'capture-materials.json'), 'original output paths changed')
    core['profile_file'] = str(out/'execution-profile.json')
    core['capture_modules']['path'] = str(out/'capture-materials.json')
    # Catch an unhandled CA reference rather than silently leaving mixed trust.
    encoded = json.dumps(value)
    need(keeper['CA']['File'] not in encoded and keeper['CA']['SHA256'] not in encoded, 'unhandled Redis CA reference')
    return value


def main():
    os.umask(0o077)
    need(os.name == 'posix', 'Linux operator required')
    spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
    r = ROOT/'source-preparation-redis-renew7d'
    r.mkdir(mode=0o700, exist_ok=True)
    need(r.resolve(strict=True) == r and r.stat().st_mode & 0o077 == 0, 'private canonical journal required')
    need(not (r/'author.sent.private.json').exists(), 'native author already sent; preserve original outcome')
    parent = json.loads((ROOT/'source-preparation-renew8h/completed.json').read_bytes())
    need(parent['SourceSelection']['SHA256'] == 'f42db72c7774a9a5fe50e1d5df837c1a2ffb954995ea8e5d09b44ae0e2a073b2', 'exact parent source required')
    receipt = A.obj(parent['Receipt']); selected = A.obj(parent['SourceSelection'])
    need(receipt['SourceSelection'] == parent['SourceSelection'], 'parent receipt differs')
    intent = json.loads((ROOT/'source-preparation-renew8h/author.sent.private.json').read_bytes())
    original = A.obj(intent['Definition'])
    renewal_file = ROOT/'redis-tls-renew7d/completed.json'
    renewal_raw = renewal_file.read_bytes(); renewed = json.loads(renewal_raw)
    need(renewed['Version'] == 'p2-redis-tls-renewed.v1' and renewed['CA']['SHA256'] == CA_SHA and
         renewed['RunID'] == '8eac27c6eac666ac053c2933c9cfe9f9836711e0' and
         renewed['ACL'] == '04d2c5882fff17d6051ca76105d564cf7514f98c25ed4c35f6ffb84e0bb6b36e' and
         renewed['PreviousFragment'] == A.KNOWN['Redis'] and renewed['BackupReady'] is False, 'observed Redis renewal differs')
    A.read(renewed['CA']); A.read(renewed['Certificate']); A.read(parent['VaultWriterSelection'])
    fragment = A.obj(A.KNOWN['Redis']); keeper = A.obj(fragment['KeeperSelection'])
    for key in ('CA', 'KeeperCredential', 'ReaderCredential', 'CustodyKey'): A.read(keeper[key])
    need(renewed['PodUID'] == keeper['Native']['PodUID'], 'renewed Redis Pod differs')
    now = dt.datetime.now(dt.timezone.utc)
    until = dt.datetime.fromisoformat(original['Until'].replace('Z', '+00:00'))
    need(now < until-dt.timedelta(minutes=5), 'source API/preparation window expired; renew through original flow')
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts exist; reconcile first')
    old_out = Path(parent['SourceSelection']['File']).parent
    out = old_out.parent/'initial-source-redis-renew7d'
    out.mkdir(mode=0o700, exist_ok=True)
    need(out.resolve(strict=True) == out and out.stat().st_mode & 0o077 == 0 and not list(out.iterdir()), 'new empty native output required')
    definition = successor(original, keeper, renewed['CA'], old_out, out)
    pin = A.retain(r/'definition.private.json', definition)
    # These successor selections are DATA, not a rewritten native receipt.
    writer = A.obj(fragment['WriterSelection'])
    need(writer['RedisReadKeepers'] == [keeper], 'original writer keeper differs')
    writer['RedisReadKeepers'] = definition['Deployment']['redis_read_keepers']
    writer_pin = A.retain(r/'redis-writer-selection.json', writer)
    keeper_pin = A.retain(r/'redis-keeper-selection.json', writer['RedisReadKeepers'][0])
    A.read({'File':str(BIN), 'SHA256':BIN_SHA}, 128<<20)
    old = intent['Argv']; need(old[1] == 'author-initial-source-inputs', 'original owner invocation required')
    argv = [str(BIN), old[1], *old[2:old.index('--definition-file')], '--definition-file', pin['File'],
            '--definition-sha256', pin['SHA256'], '--output-directory', str(out)]
    A.retain(r/'author.sent.private.json', {'Argv':argv, 'Definition':pin, 'ParentReceipt':parent['Receipt'],
        'RedisRenewal':{'File':str(renewal_file), 'SHA256':A.sha(renewal_raw)}, 'RedisWriterSelection':writer_pin})
    with (r/'author.stdout.private').open('xb') as stdout, (r/'author.stderr.private').open('xb') as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=180)
    A.retain(r/'author.exit.json', {'ExitCode':result.returncode})
    need(result.returncode == 0, 'native source author refused; retain partial outputs')
    raw = (r/'author.stdout.private').read_bytes(); value = json.loads(raw)
    need(value['Version'] == 'original-initial-source-inputs-authored.v1' and
         value['GrantsIssued'] is False and value['BackupReady'] is False, 'native unissued DATA receipt required')
    for key in ('Deployment', 'MaterialsTemplate', 'ExecutionProfile', 'SourceSelection'): A.read(value[key])
    authored = A.obj(value['SourceSelection'])
    need(authored['Connections'] == definition['Connections'] and authored['Until'] == selected['Until'], 'native source connections/window differ')
    done = {'Version':'p2-redis-source-reauthored.v1', 'Receipt':A.retain(r/'author.receipt.private.json', raw),
        'SourceSelection':value['SourceSelection'], 'RedisWriterSelection':writer_pin, 'RedisKeeperSelection':keeper_pin,
        'SourceAPI':parent['SourceAPI'], 'VaultWriterSelection':parent['VaultWriterSelection'],
        'Until':parent['Until'], 'GrantsIssued':False, 'BackupReady':False}
    A.retain(r/'completed.json', done)
    print('P2_REDIS_SOURCE_REAUTHORED_NO_HOLD', json.dumps(done), flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('P2_REDIS_SOURCE_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))

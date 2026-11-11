#!/usr/bin/env python3
"""Settle this already-sent Redis TLS rollout, then restore its original strategy."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

BIN = Path('/root/sbk/p2-redis-8bbf4c61')
RECORDS = Path('/root/sbk/p2-redis-connection.b5dQ12Lt')
UID = 'dd724dc4-ad59-4a78-b5bb-50aba907e036'


def need(ok, text):
    if not ok:
        raise RuntimeError(text)


def selected_recreate(spec, expected):
    need(spec == expected and spec.get('replicas') == 1 and spec.get('strategy', {}).get('type') == 'RollingUpdate',
         'current Redis spec is not the original native desired single-replica rollout')
    result = copy.deepcopy(spec)
    result['strategy'] = {'type': 'Recreate'}
    return result


def main():
    os.umask(0o077)
    raw = (BIN / 'continue-p2-minio-connection.py').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == '13da446e37fd45fd1344a04fe433e6e2306740cc5ede4fffa29745393d1a1b25', 'field helper changed')
    spec = importlib.util.spec_from_file_location('original_minio_field', BIN / 'continue-p2-minio-connection.py')
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    m = c.module(BIN, 'system-backup-minio-first-hop-tls.py')
    source = m.Source(c.source_arguments())
    prepared = json.loads(c.private(RECORDS / 'prepare.receipt.json'))
    need(prepared['Version'] == 'original-redis-native-materials.v1'
         and prepared['State'] == 'native_prepared_loopback_isolated_requires_apply', 'original Redis prepare receipt required')
    intent_pin = prepared['Intent']
    intent = json.loads(c.private(Path(intent_pin['File']), intent_pin['SHA256']))
    need(intent['Version'] == 'original-redis-native-intent.v1' and intent['Operation'] == prepared['Operation']
         and intent['DeploymentUID'] == UID, 'original native rollout identity changed')
    need(c.private(RECORDS / 'native/apply.sent').decode() == intent['Operation'], 'original native apply intent absent')
    location = RECORDS / 'rwo-rollout-settle'
    if not location.exists():
        location.mkdir(mode=0o700)
    need(not location.is_symlink() and location.stat().st_mode & 0o077 == 0, 'private rollout settlement directory required')
    name = 'clawmanager-team-redis'
    def current():
        value = source.get('deployment', name)
        need(value['metadata']['uid'] == UID and not value['metadata'].get('deletionTimestamp'), 'Redis Deployment replaced')
        return value
    def ready():
        value = current()
        pods = json.loads(source.kube('get', 'pods', '-l', ','.join(k+'='+v for k,v in sorted(value['spec']['selector']['matchLabels'].items())), '-o', 'json'))['items']
        return value, pods, (value.get('status', {}).get('observedGeneration', 0) >= value['metadata'].get('generation', 1)
            and value.get('status', {}).get('replicas', 0) == 1 and value.get('status', {}).get('readyReplicas', 0) == 1
            and len(pods) == 1 and not pods[0]['metadata'].get('deletionTimestamp')
            and pods[0]['metadata']['uid'] != intent['BeforePodUID'] and len(pods[0].get('status', {}).get('containerStatuses', [])) == 1
            and pods[0]['status']['containerStatuses'][0].get('ready') is True)
    final = intent['DesiredDeployment']
    temporary = selected_recreate(final, final)
    c.retain(location / 'plan.json', c.encode({'Version': 'validation-p2-original-redis-rwo-rollout-settle.v1',
        'OriginalIntent': intent_pin, 'Operation': intent['Operation'], 'UID': UID, 'FinalSpec': final, 'TemporarySpec': temporary}))
    # Recheck the original persistent source, never force-detach/delete it.
    claim = source.get('persistentvolumeclaim', intent['DataClaim'])
    volume = source.get('persistentvolume', intent['DataPV'])
    need(claim['metadata']['uid'] == intent['DataClaimUID'] and claim['spec']['volumeName'] == intent['DataPV']
         and volume['metadata']['uid'] == intent['DataPVUID'] and volume['spec']['claimRef']['uid'] == intent['DataClaimUID']
         and c.digest(m.raw(claim['spec'])) == intent['DataClaimSpecSHA256']
         and c.digest(m.raw(volume['spec'])) == intent['DataPVSpecSHA256']
         and claim.get('status', {}).get('phase') == 'Bound' and claim['spec'].get('accessModes') == ['ReadWriteOnce'],
         'original RWO source volume identity changed')
    def observe(target):
        value = current()
        if value['spec'] == target:
            return {'uid': UID, 'spec_sha256': m.sha(m.raw(target))}
        return None
    value = current()
    if (location / 'restore-strategy.sent.json').exists():
        need(value['spec'] in (temporary, final), 'foreign change during original strategy recovery')
    else:
        need(value['spec'] in (final, temporary), 'foreign Redis spec; no rollout compensation sent')
        if not (location / 'recreate.sent.json').exists():
            _, pods, settled = ready()
            need(not settled and any(p['metadata']['uid'] == intent['BeforePodUID'] for p in pods),
                 'original blocked rollout is no longer the observed RWO handover')
        source.authority()
        m.step(location, 'recreate', {'uid': UID, 'spec_sha256': m.sha(m.raw(temporary))},
            lambda: m.source_patch(source, value, temporary), lambda: observe(temporary))
        print('REDIS_RWO_RECREATE_SENT', flush=True)
        for _ in range(120):
            value, pods, settled = ready()
            need(value['spec'] == temporary, 'foreign Redis change during RWO rollout')
            if settled:
                break
            time.sleep(2)
        else:
            raise RuntimeError('RWO handover not settled; retain plan and original recovery obligations')
    value = current()
    source.authority()
    m.step(location, 'restore-strategy', {'uid': UID, 'spec_sha256': m.sha(m.raw(final))},
        lambda: m.source_patch(source, value, final), lambda: observe(final))
    for _ in range(45):
        value, _, settled = ready()
        need(value['spec'] == final, 'original desired Redis spec changed after strategy recovery')
        if settled:
            source.authority()
            print('REDIS_RWO_ROLLOUT_SETTLED_ORIGINAL_STRATEGY_RESTORED', flush=True)
            return
        time.sleep(2)
    raise RuntimeError('original strategy restored; final readiness requires query')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('REDIS_RWO_SETTLE_UNCONFIRMED ' + (str(error) if type(error) is RuntimeError or type(error).__name__ == 'Refused' else type(error).__name__))

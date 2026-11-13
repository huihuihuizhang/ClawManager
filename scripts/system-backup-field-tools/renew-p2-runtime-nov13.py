#!/usr/bin/env python3
"""Issue uniquely named runtime TLS Secrets, then use the guarded rotation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')


def main():
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location('rotation', Path(__file__).with_name('rotate-p2-runtime-certificates.py'))
    R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
    R.need(os.name == 'posix', 'Linux operator required')
    root = ROOT/'renewal-20261113/runtime-unique'
    root.mkdir(mode=0o700, exist_ok=True)
    R.need(root.resolve() == root and root.stat().st_mode & 0o077 == 0, 'private canonical journal required')
    R.OLD_RECEIPT = ROOT/'runtime-agent.receipt.private.json'
    old = json.loads(R.OLD_RECEIPT.read_bytes())
    R.OLD_CA = '4d6ffb92650f28a7148a536b60cfab6a0b025856a4b30dba3b6059905c128478'
    R.need(old['CA']['SHA256'] == R.OLD_CA, 'previous loaded CA differs')
    R.pinned(old['CA'])
    R.APP_IMAGE = '10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780'
    receipt_file = root/'runtime-agent.receipt.private.json'
    if not receipt_file.exists():
        R.need(not (root/'issuance.sent.private.json').exists(), 'issuance outcome unknown; preserve journal')
        intent = json.loads((ROOT/'runtime-agent.sent.private.json').read_bytes())
        argv = list(intent['Argv'])
        definition = json.loads(R.pinned({'File':argv[argv.index('--definition-file')+1],
            'SHA256':'4dcb51a587466f779f8f7eac1d29b99c928535086512156fb0067e86614271b3'}))
        definition['SecretPrefix'] = 'sbk-renew-20261113'
        definition['ValiditySeconds'] = 86400
        path = root/'definition.private.json'; R.retain(path, definition)
        executable = Path(argv[0])
        sums = dict(line.split(maxsplit=1) for line in (executable.parent/'SHA256SUMS').read_text().splitlines())
        R.need(any(name.strip().lstrip('*') == executable.name and R.sha(executable.read_bytes()) == digest
                   for digest,name in sums.items()), 'original executable checksum differs')
        output = root/'materials'; output.mkdir(mode=0o700, exist_ok=True)
        R.need(output.resolve() == output and not list(output.iterdir()), 'new empty material directory required')
        argv[argv.index('--definition-file')+1] = str(path)
        argv[argv.index('--definition-sha256')+1] = R.sha(path.read_bytes())
        argv[argv.index('--output-directory')+1] = str(output)
        R.retain(root/'issuance.sent.private.json', {'Argv':argv})
        with (root/'stdout.private').open('xb') as stdout, (root/'stderr.private').open('xb') as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=180)
        R.retain(root/'exit.json', {'ExitCode':result.returncode})
        R.need(result.returncode == 0, 'native issuance refused; retain partial outputs')
        raw = (root/'stdout.private').read_bytes(); receipt = json.loads(raw)
        R.need(receipt['Version'] == 'original-shared-agent-tls-materials.v1', 'native receipt required')
        R.need(not ({t['SecretName'] for t in receipt['Targets']} & {t['SecretName'] for t in old['Targets']}), 'Secret name collision')
        R.retain(receipt_file, raw)
    receipt = json.loads(receipt_file.read_bytes())
    R.NEW_CA = receipt['CA']['SHA256']; R.pinned(receipt['CA'])
    print('NOV13_RUNTIME_CERTIFICATE_MATERIALS', json.dumps({'Receipt':{'File':str(receipt_file),
        'SHA256':R.sha(receipt_file.read_bytes())},'CA':receipt['CA'],'NotAfter':receipt['NotAfter']}), flush=True)
    R.main(root)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('NOV13_RUNTIME_RENEWAL_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))

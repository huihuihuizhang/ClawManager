#!/usr/bin/env python3
"""Re-observe the existing Vault after the finite installer-profile repair."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
OLD_AUTHOR = '/root/sbk/p2-redis-8bbf4c61/system-backup-original-maintenance'
OLD_SHA = 'a947551a16fae050a00975ada5421b453baefd3340bcd1dffd8fa24bd861d20e'
HELPER = Path('/root/sbk/p2-runtime-cert-rotation-fcc26a0a/rotate-p2-runtime-certificates.py')
HELPER_SHA = 'ab1539c5e06c8c237e8516d9985b162fbec3216570abb5ebec1902df47f7052c'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def require(ok, message):
    if not ok:
        raise ValueError(message)


def refused_observation(argv, exit_value, stdout, stderr, output_names):
    """A failed bounded observation with no material output has no send to replay."""
    require(isinstance(argv, list) and len(argv) > 3 and argv[0] == OLD_AUTHOR and
            argv[1:3] == ['--mode', 'provider-materials'] and
            len(argv[1::2]) == len(set(argv[1::2])) and len(argv) % 2 == 1,
            'exact original provider observation required')
    require(type(exit_value.get('ExitCode')) is int and exit_value['ExitCode'] != 0 and
            stdout == stderr == b'' and not output_names,
            'original failed observation must have no partial outputs; retain and inspect it')
    return dict(zip(argv[1::2], argv[2::2]))


def main(directory):
    os.umask(0o077)
    require(os.name == 'posix', 'Linux operator required')
    A = load('vault_resume_assembly', directory / 'assemble-p2-installation-candidate.py')
    old = ROOT / 'vault-dependency'
    sent = json.loads((old / 'apply.sent.private.json').read_bytes())
    argv = sent['Argv']
    out = Path(argv[argv.index('--output-directory') + 1])
    require(out == Path('/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-vault-provider-apply') and
            out.is_dir() and not out.is_symlink(), 'exact retained original output directory required')
    flags = refused_observation(argv, json.loads((old / 'apply.exit.json').read_bytes()),
                               (old / 'apply.stdout.private').read_bytes(),
                               (old / 'apply.stderr.private').read_bytes(), list(out.iterdir()))
    require(not any((old / name).exists() for name in
                    ['apply.receipt.private.json', 'query.sent.private.json', 'finalize.sent.private.json', 'completed.json']),
            'later original observation exists; retain original records')
    require(hashlib.sha256(Path(OLD_AUTHOR).read_bytes()).hexdigest() == OLD_SHA and
            hashlib.sha256(HELPER.read_bytes()).hexdigest() == HELPER_SHA,
            'original native tool or API helper changed')
    writer = sent['WriterSelection']
    A.read(writer)
    require(flags['--selection-file'] == writer['File'] and flags['--selection-sha256'] == writer['SHA256'],
            'original selection changed')
    build = json.loads((directory / 'BUILD_RECEIPT.json').read_bytes())
    require(build['Version'] == 'p2-vault-installer-profile-build.v1' and build['Platform'] == 'linux/amd64' and
            build['SourceRevision'] == (directory / 'SOURCE_REVISION').read_text().strip(),
            'matching fixed-source build receipt required')
    binary = directory / 'system-backup-original-maintenance'
    tool = build['Binaries'][binary.name]
    raw = A.read({'File': str(binary), 'SHA256': tool['SHA256']}, 128 << 20)
    require(len(raw) == tool['Bytes'] and raw[:6] == b'\x7fELF\x02\x01' and raw[18:20] == b'\x3e\x00',
            'actual Linux amd64 native executable required')
    r = old / 'installer-profile-readback'
    r.mkdir(mode=0o700, exist_ok=True)
    require(r.resolve(strict=True) == r and r.stat().st_mode & 0o077 == 0, 'private readback directory required')
    A.retain(r / 'original-refusal.json', {'Version': 'p2-retained-empty-provider-observation.v1',
                                         'OriginalIntent': {'File': str(old / 'apply.sent.private.json'),
                                                            'SHA256': hashlib.sha256((old / 'apply.sent.private.json').read_bytes()).hexdigest()},
                                         'OriginalOutputsEmpty': True, 'OldIntentReplayed': False})
    print('P2_VAULT_EXISTING_INSTALLATION_PROFILE_READBACK', r, flush=True)
    m = load('vault_resume_transport', HELPER)
    site = m.Site(r)
    controller = json.loads((ROOT / 'controller-relay/controller-current.private.json').read_bytes())
    pod = site.get('pod', controller['metadata']['name'])
    require(pod['metadata']['uid'] == controller['metadata']['uid'], 'prepared controller changed')
    report = json.loads((ROOT / 'vault-owner/public-report.json').read_bytes())
    require(report['status'] == 'completed' and report['jwt_smoke_passed'] is True and
            report['persistence_restart_verified'] is True, 'completed original Vault owner required')
    D = load('vault_resume_dns', directory / 'p2-source-dns.py')
    dns = D.SourceDNS(site, r, pod, [('vault', report['endpoint'])], A.retain)
    dns.probe()
    receipt = r / 'provider.receipt.private.json'
    if receipt.exists():
        value = json.loads(receipt.read_bytes())
    else:
        require(not (r / 'provider.sent.private.json').exists(), 'readback already sent; retain and inspect its outcome')
        target = out.parent / 'initial-vault-provider-installer-profile'
        target.mkdir(mode=0o700, exist_ok=True)
        require(not list(target.iterdir()), 'partial new provider outputs retained')
        selected = list(argv)
        selected[0] = str(binary)
        selected[selected.index('--output-directory') + 1] = str(target)
        A.retain(r / 'provider.sent.private.json', {'Argv': selected, 'SourceRevision': build['SourceRevision'],
                                                 'OriginalIntentRetained': str(old / 'apply.sent.private.json')})
        with (r / 'provider.stdout.private').open('xb') as stdout, (r / 'provider.stderr.private').open('xb') as stderr:
            result = dns.run(selected, stdout=stdout, stderr=stderr, timeout=180)
        A.retain(r / 'provider.exit.json', {'ExitCode': result.returncode})
        if result.returncode:
            try:
                failure = json.loads((r / 'provider.stdout.private').read_bytes())
                if failure.get('Version') == 'original-vault-dependency-material-failure.v1':
                    print('P2_VAULT_NATIVE_REFUSAL_PHASE', failure['Phase'], flush=True)
            except (ValueError, KeyError):
                pass
            raise ValueError('native readback refused; retain this directory and its original outputs')
        value = json.loads((r / 'provider.stdout.private').read_bytes())
        A.retain(receipt, (r / 'provider.stdout.private').read_bytes())
    require(value['Version'] == 'pre-adoption-vault-materials.v1' and
            value['State'] == 'actual_installed_dependency_inputs_only_no_adoption_or_task_authority',
            'actual original native observation required')
    for key in ['InstalledObserver', 'WriterSelection']:
        A.read(value[key])
    record = {'Version': 'p2-vault-dependency-observed.v1',
              'Receipt': {'File': str(receipt), 'SHA256': hashlib.sha256(receipt.read_bytes()).hexdigest()},
              'WriterSelection': value['WriterSelection'], 'InstalledObserver': value['InstalledObserver'],
              'IAMMutated': False, 'NativeHoldClaim': False, 'BackupReady': False}
    A.retain(r / 'completed.json', record)
    A.retain(old / 'completed.json', record)
    print('P2_VAULT_PROVIDER_DEPENDENCY_READY_NO_HOLD', json.dumps(record), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool-directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        main(args.tool_directory)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit('P2_VAULT_DEPENDENCY_UNCONFIRMED ' + (str(error) if type(error) is ValueError else type(error).__name__))

#!/usr/bin/env python3
"""Package two reviewed Linux test binaries; never contacts a remote service."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def sums(directory, name):
    paths = sorted(directory.rglob('*'))
    assert not any(path.is_symlink() for path in paths)
    (directory / name).write_text(''.join(
        sha(path) + '  ' + path.relative_to(directory).as_posix() + '\n'
        for path in paths if path.is_file() and path.name != name), encoding='utf-8')


def main():
    assert len(sys.argv) == 5
    root, repo, pins_file, out = map(lambda value: Path(value).resolve(), sys.argv[1:])
    assert (root / '.owner').read_text().strip() == 'supervisor-effective-native-review-20261103'
    assert out.parent == repo and not out.exists()
    source = root / 'source'
    base = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    assert base == 'f4d73c79b509bc8d647c685887f729110632bb2b'
    pins = json.loads(pins_file.read_text(encoding='utf-8-sig'))
    assert len(pins) == 6
    for name, expected in pins.items():
        path = source / name
        assert path.resolve().is_relative_to(source) and not path.is_symlink()
        assert sha(path) == expected == sha(repo / name), name
    changed = subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=all'], text=True)
    assert set(line[3:] for line in changed.splitlines()) == set(pins), changed
    binaries = {}
    for name in ('owner.test', 'execution.test'):
        binary = root / 'bin' / name
        with binary.open('rb') as stream:
            header = stream.read(20)
        assert header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == 62
        binaries[name] = sha(binary)
    fixture = source / 'scripts/system-backup-d-kube-mysql-fixture.py'
    fixture_bytes = fixture.read_bytes().replace(b'\r\n', b'\n')
    fixture_sha = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha == 'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873'
    paths = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z', '--', 'backend', 'contracts']).decode().split('\0')
    paths = sorted(set(filter(None, paths)) | set(pins))
    receipt = ''.join(sha(source / path) + '  ' + path + '\n' for path in paths)
    overlay_id = hashlib.sha256(json.dumps(pins, sort_keys=True).encode()).hexdigest()[:12]
    label = 'owner-source-' + overlay_id
    package = root / ('clawmanager-native-' + label)
    assert not package.exists()
    bundle = package / 'bundle'
    (bundle / 'bin').mkdir(parents=True)
    for name in binaries:
        shutil.copyfile(root / 'bin' / name, bundle / 'bin' / name)
    for directory in (source / 'backend').rglob('testdata'):
        if directory.is_dir():
            assert not any(path.is_symlink() for path in directory.rglob('*'))
            shutil.copytree(directory, bundle / directory.relative_to(source), dirs_exist_ok=True)
    contracts = source / 'contracts/system-backup/v12'
    assert not any(path.is_symlink() for path in contracts.rglob('*'))
    shutil.copytree(contracts, bundle / 'contracts/system-backup/v12')
    migration = Path('backend/internal/db/migrations/134_backup_v2_installation_owner_authority.sql')
    (bundle / migration).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / migration, bundle / migration)
    runner = repo / 'scripts/system-backup-supervisor-owner-source-native-run.sh'
    (bundle / 'run-diagnostic.sh').write_bytes(runner.read_bytes().replace(b'\r\n', b'\n'))
    review = {'schema_version': 'supervisor-owner-source-native-packet.v1',
              'source_base_commit': base, 'source_overlay': pins,
              'source_is_clean_commit': False, 'overlay_id': overlay_id,
              'binary_sha256': binaries, 'platform': 'linux/amd64', 'cgo': False,
              'source_receipt_sha256': hashlib.sha256(receipt.encode()).hexdigest(),
              'native_executed': False, 'full_page_acceptance': False,
              'production_minio_verified': False, 'disaster_recovery_qualified': False,
              'scope': 'owned disposable MySQL plus controlled API/Redis/S3/Vault fixtures; not field integration',
              'original_window_timing_tests_included': False,
              'owner_timeout_minutes': 5, 'execution_timeout_minutes': 10,
              'fixture_runner_timeout_minutes': 18}
    (bundle / 'SOURCE_REVIEW.json').write_text(json.dumps(review, indent=2) + '\n')
    (bundle / 'SOURCE_FILES.sha256').write_text(receipt, encoding='utf-8')
    sums(bundle, 'SHA256SUMS')
    sums(package, 'DELIVERY_SHA256SUMS')
    out.mkdir()
    (out / '.owner').write_text('supervisor-owner-source-delivery-20261103\n')
    archive = out / (package.name + '.tar.gz')
    with tarfile.open(archive, 'w:gz') as stream:
        stream.add(package, arcname=package.name)
    (out / fixture.name).write_bytes(fixture_bytes)
    entry = (repo / 'scripts/system-backup-supervisor-native-1c350462.sh').read_text()
    old_commit = '1c3504620e3b456daf95f53adc647f8dd8d002b0'
    old_archive = '27f426891de91f6a1f7f702e7cee8ad01efdbbca2d17a5c5b51fa3aea2e8d847'
    assert old_commit in entry and old_archive in entry
    entry = entry.replace(old_commit, base).replace(old_archive, sha(archive)).replace('1c350462', label)
    entry = entry.replace('# Reviewed new Linux candidate; original 30-second policy remains unchanged.',
                          '# Supplemental owner/source fixture checks; original timing tests remain in R8.')
    entry = entry.replace('# Native candidate is pinned to ' + label + ' (backend b98 A4+B6); fixture is pinned to 875e3960.',
                          '# Explicit source overlay and ELF hashes are recorded in bundle/SOURCE_REVIEW.json.')
    entry = entry.replace('native test timeout is 15 minutes', 'selected test timeouts total 15 minutes')
    entry = entry.replace("elif re.search(r'^--- (PASS|FAIL): TestAPermit|stage=database-|retained failed original SQL namespace', line):",
                          "elif re.search(r'^--- (PASS|FAIL|SKIP): Test|Supplemental owner/source', line):")
    needle = '[[ -f $archive && ! -L $archive ]]'
    assert needle in entry
    guard = ("site_uid=$(kubectl --context 'kubernetes-admin@kubernetes' get namespace 'clawmanager-zhanghui08-system' -o 'jsonpath={.metadata.uid}')\n"
             "[[ $site_uid = '337cfe30-2c17-4b8e-b32a-760778b8098e' ]] || { echo 'Target namespace identity changed; no fixture resources created.' >&2; exit 64; }\n")
    entry = entry.replace(needle, guard + needle, 1)
    entry_path = out / ('run-' + label + '.sh')
    entry_path.write_text(entry, encoding='utf-8', newline='\n')
    review.update({'delivery_directory': str(out), 'archive': archive.name,
                   'archive_sha256': sha(archive), 'archive_bytes': archive.stat().st_size,
                   'entry': entry_path.name, 'entry_sha256': sha(entry_path),
                   'fixture': fixture.name, 'fixture_sha256': fixture_sha,
                   'runner_sha256': sha(bundle / 'run-diagnostic.sh')})
    (out / 'DELIVERY.json').write_text(json.dumps(review, indent=2) + '\n')
    print(json.dumps(review))


if __name__ == '__main__':
    main()

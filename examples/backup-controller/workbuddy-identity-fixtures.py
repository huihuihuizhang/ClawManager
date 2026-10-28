"""Only fixed synthetic lab mounts; never connect to a server or start an Agent."""
import hashlib
import base64
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile


def inventory(root):
    result = {}
    for p in [root] + sorted(root.rglob('*')):
        s = p.lstat()
        item = [stat.S_IFMT(s.st_mode), stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid]
        item.append({k: base64.b64encode(os.getxattr(p,k,follow_symlinks=False)).decode() for k in os.listxattr(p,follow_symlinks=False)})
        if p.is_symlink():
            item.append(os.readlink(p))
        elif p.is_file():
            item.append(hashlib.sha256(p.read_bytes()).hexdigest())
        result[str(p.relative_to(root))] = item
    return result


if sys.argv[1:] == ['seed']:
    expected = {}
    for i, name in enumerate(('workbuddy-a', 'workbuddy-b')):
        root = Path('/source') / name
        home = root / 'home'
        assert home.is_dir() and not (root / '.workbuddy-identity.json').exists()
        uid = 21000 + i
        marker = dict(schema=1, instanceId=7+i, userId=4+i, uid=uid, gid=uid)
        (root / '.workbuddy-identity.json').write_text(json.dumps(marker))
        fixtures = home / '.identity-lab'
        fixtures.mkdir()
        (fixtures / 'credential.json').write_text(json.dumps({'fake_only': True, 'owner': uid}))
        wine = home / '.local/share/workbuddy-editor-sdk-wine'
        if not wine.exists():
            (wine / 'dosdevices').mkdir(parents=True)
            (wine / 'drive_c/Documents').mkdir(parents=True)
            for registry in ('system.reg','user.reg','userdef.reg'):
                (wine / registry).write_text('synthetic Wine registry fixture\n')
            os.symlink('../drive_c',wine / 'dosdevices/c:')
            os.symlink('/',wine / 'dosdevices/z:')
        document = wine / 'drive_c/identity-lab-document.txt'
        document.write_text('synthetic document owner '+str(uid))
        os.setxattr(document,'user.DOSATTRIB',b'0x20')
        # Leave committed pages in WAL, as with a stopped native history store.
        code = """import os,sqlite3,sys
db=sqlite3.connect(sys.argv[1]);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, owner INTEGER, instance INTEGER, body TEXT)')
db.executemany('INSERT INTO messages VALUES(?,?,?,?)',[(n,int(sys.argv[2]),int(sys.argv[3]),'synthetic history '+str(n)) for n in range(300)])
db.commit();os._exit(0)
"""
        subprocess.run([sys.executable, '-c', code, str(fixtures / 'history.sqlite'), str(uid), str(7+i)], check=True)
        assert (fixtures / 'history.sqlite-wal').stat().st_size > 0
        os.chmod(root, 0o755)
        os.chmod(home, 0o700)
        for p in [home] + list(home.rglob('*')):
            os.chown(p, uid, uid, follow_symlinks=False)
        expected[str(7+i)] = inventory(root)
    Path('/lab/identity-inventory.json').write_text(json.dumps(expected, indent=2))
elif sys.argv[1:] == ['verify']:
    expected = json.loads(Path('/lab/identity-inventory.json').read_text())
    native, wal_rows, entries = 0, 0, 0
    for i in range(2):
        root = Path('/restored') / f'instance-{7+i}'
        uid = 21000 + i
        actual = inventory(root)
        assert actual == expected[str(7+i)], 'byte/link/mode/UID/GID inventory mismatch'
        entries += len(actual)
        marker = json.loads((root / '.workbuddy-identity.json').read_text())
        assert marker == dict(schema=1, instanceId=7+i, userId=4+i, uid=uid, gid=uid)
        wine = root / 'home/.local/share/workbuddy-editor-sdk-wine'
        assert os.readlink(wine / 'dosdevices/z:') == '/'
        assert os.getxattr(wine / 'drive_c/identity-lab-document.txt','user.DOSATTRIB') == b'0x20'
        own = root / 'home/.identity-lab/credential.json'
        other = Path('/restored') / f'instance-{8-i}/home/.identity-lab/credential.json'
        code = "from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()\ntry:Path(sys.argv[2]).read_bytes()\nexcept PermissionError:pass\nelse:raise RuntimeError('cross-user access allowed')"
        subprocess.run([sys.executable,'-c',code,str(own),str(other)],user=uid,group=uid,extra_groups=[],check=True)
        for p in (root / 'home').rglob('*'):
            if p.is_symlink() or not p.is_file():
                continue
            with p.open('rb') as f:
                if f.read(16) != b'SQLite format 3\0':
                    continue
            # Recovery/integrity checking operates on disposable copies only.
            with tempfile.TemporaryDirectory() as td:
                dst = Path(td) / 'db'
                shutil.copyfile(p,dst)
                for suffix in ('-wal','-shm'):
                    if Path(str(p)+suffix).exists():
                        shutil.copyfile(str(p)+suffix,str(dst)+suffix)
                with sqlite3.connect(dst) as db:
                    assert db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
                    if p == root / 'home/.identity-lab/history.sqlite':
                        n = db.execute('SELECT COUNT(*) FROM messages WHERE owner=? AND instance=?',(uid,7+i)).fetchone()[0]
                        assert n == 300
                        wal_rows += n
                    elif '.backup-lab-fixtures' not in p.parts:
                        native += 1
    assert wal_rows == 600 and native >= 2
    report = dict(native_sqlite_checked=native,synthetic_wal_messages_recovered=wal_rows,metadata_entries_verified=entries,cross_user_uid_isolation_verified=2,identity_markers_verified=2,instance_root_wine_mapping_and_dos_attributes_verified=True,agents_started=False)
    Path('/lab/mixed-linux-result.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
else:
    raise RuntimeError('Expected seed or verify')

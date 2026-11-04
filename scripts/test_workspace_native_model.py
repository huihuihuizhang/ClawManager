"""Transport/filesystem regression models, NOT NFS/native field qualification.

Run with Python -B. Temporary files and the one owned model child are removed
in finally blocks. The Linux root transport case explicitly skips elsewhere.
"""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("workspace_native_model_target", Path(__file__).with_name("system-backup-workspace-native.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
controller_spec=importlib.util.spec_from_file_location("workspace_controller_model_target",Path(__file__).with_name("system-backup-workspace-localization.py"))
controller=importlib.util.module_from_spec(controller_spec)
controller_spec.loader.exec_module(controller)


class ExportAndControlModels(unittest.TestCase):

    def test_real_state_file_parser_preserves_non_ascii_filename_bytes(self):
        # Actual os.open/read/EOF parser; filesystem identity is explicitly a
        # MODEL here. This does not qualify a live NFSD server or writer fence.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            clients=root/"clients"
            client=clients/"7"
            client.mkdir(parents=True)
            (client/"info").write_bytes(b'clientid: 0x123\naddress: "10.42.0.1:883"\nminor version: 2\n')
            (root/"versions").write_bytes(b'-2 -3 +4 +4.1 +4.2\n')
            clients_fd=os.open(clients,os.O_RDONLY|os.O_DIRECTORY)
            versions_fd=os.open(root/"versions",os.O_RDONLY)
            actor=native.Actor.__new__(native.Actor)
            actor.server={"pid":native.process(os.getpid()),"clients_fd":clients_fd,"versions_fd":versions_fd,"item":{"pod_uid":"model-source-server"}}
            actor.server_closed=False
            actor.definition={"node":{"name":"model-source-node"}}
            actor.event=lambda *args:None
            try:
                for filename in (b'/exports/workspaces/\xe4\xb8\xad\xe6\x96\x87',b'/exports/workspaces/\xff-name'):
                    with self.subTest(filename=filename.hex()):
                        state=b'- 0x1234: { type: open, filename: "'+filename+b'" }\n'
                        (client/"states").write_bytes(state)
                        with patch.object(native,"fs_magic",return_value=0x6E667364):
                            result=actor.source_nfs_client_census()
                        self.assertEqual(result["clients"][0]["state_kinds"],["open"])
                        self.assertEqual(result["clients"][0]["states_bytes_hex"],state.hex())
                        self.assertEqual(result["clients"][0]["states_sha256"],native.sha(state))
                        self.assertFalse(result["backup_ready"])
                (client/"states").write_bytes(state+b'unknown record\n')
                with patch.object(native,"fs_magic",return_value=0x6E667364),self.assertRaisesRegex(native.Refused,"unknown_actual_nfsd_state_record_format"):
                    actor.source_nfs_client_census()
            finally:
                os.close(versions_fd)
                os.close(clients_fd)
    def test_unknown_client_delegation_owner_and_unknown_state_refuse(self):
        owner=controller.WorkspaceLocalization.__new__(controller.WorkspaceLocalization)
        owner.m=types.SimpleNamespace(need=native.need,digest=native.sha,encoded=native.encoded)
        owner.stages=types.SimpleNamespace(operation="a"*32,retain=lambda *args:None)
        server={"pod_uid":"source-server","node":"master"}
        inventory={"clients":[{"node":"master"},{"node":"node1"}],"server":server}
        clients=[{"address":"10.42.0.1","state_kinds":["open","deleg"]}]
        class Session:
            def __init__(self,name,address):
                self.definition={"node":{"name":name},"session":name}
                self.address=address
            def rpc(self,action):
                if action == "source-node-network":
                    return {"node":self.definition["node"],"ipv4_interfaces":[{"address":self.address}]}
                return {"server":server,"node":self.definition["node"],"clients":clients}
        sessions={"master":Session("master","10.42.0.1"),"node1":Session("node1","10.42.1.1")}
        result=owner.nfs_client_boundary(sessions,inventory,"model-only")
        self.assertFalse(result["delegation_flush_proved"])
        self.assertFalse(result["network_admission_fence_proved"])
        clients[0]["address"]="192.0.2.55"
        with self.assertRaisesRegex(native.Refused,"unknown_or_ambiguous_original_nfs_v4_client_or_delegation_owner"):
            owner.nfs_client_boundary(sessions,inventory,"model-only")
        clients[0]["address"]="10.42.0.1"
        clients[0]["state_kinds"]=["unknown_delegation"]
        with self.assertRaisesRegex(native.Refused,"unknown_original_nfs_v4_state_or_delegation_kind"):
            owner.nfs_client_boundary(sessions,inventory,"model-only")
        clients[0]["state_kinds"]=["deleg"]
        sessions["node1"].address="10.42.0.1"
        with self.assertRaisesRegex(native.Refused,"unknown_or_ambiguous_original_nfs_v4_client_or_delegation_owner"):
            owner.nfs_client_boundary(sessions,inventory,"model-only")
    def test_server_supervisor_freeze_is_exact_owned_scope_and_reversible(self):
        actor=native.Actor.__new__(native.Actor)
        identity={"pid":12,"start":"1","pidns":"pid:[1]","mntns":"mnt:[1]","netns":"net:[1]","cgroup":"0::/original-cid"}
        record={"pid":identity,"user_freeze_fd":7,"user_events_fd":8,"user_freeze_owned":False}
        actor.server=record
        actor.event=lambda *args:None
        state=[False]
        writes=[]
        def read(fd):
            return (b"1\n" if state[0] else b"0\n") if fd == 7 else b"populated 1\nfrozen "+(b"1" if state[0] else b"0")+b"\n"
        def write(fd,value):
            writes.append(value)
            state[0]=value == b"1\n"
            return len(value)
        with patch.object(native,"process",return_value=identity),patch.object(native.Actor,"read_fd",side_effect=read),patch.object(native.os,"open",return_value=101),patch.object(native.os,"write",side_effect=write),patch.object(native.os,"close"),patch.object(native,"fs_magic",return_value=0x63677270):
            actor.server_user_freeze(True)
            self.assertTrue(state[0])
            actor.server_user_freeze(False)
            self.assertFalse(state[0])
            record["user_freeze_owned"]=False
            state[0]=True
            with self.assertRaisesRegex(native.Refused,"cannot_thaw_another_server_scope_owner"):
                actor.server_user_freeze(False)
        self.assertEqual(writes,[b"1\n",b"0\n"])
    def test_restored_observer_cannot_stop_clients_or_change_exports(self):
        actor=native.Actor.__new__(native.Actor)
        actor.definition={"direction":"observe-restored-server"}
        for action in ("stop-original-clients","stop-original-server","restore-original-server","isolate-server","sync-clients","sync-clients-for-recovery","source-mount-census"):
            with self.subTest(action=action),self.assertRaisesRegex(native.Refused,"restored_server_observer_cannot_mutate_source_or_exports"):
                actor.call(action)
    def test_partial_transport_writes_keep_complete_original_response(self):
        class ShortWriter:
            def __init__(self):
                self.raw=bytearray()
            def write(self,pending):
                self.raw.extend(pending[:2])
                return min(len(pending),2)
        writer=ShortWriter()
        native.stream_write(writer,b"original response\n")
        self.assertEqual(writer.raw,b"original response\n")
    def test_complete_export_profile_refuses_aliases_and_second_export(self):
        valid = b"/exports/workspaces *(rw,sync,fsid=0,no_root_squash)\n"
        self.assertEqual(native.parse_exports(valid)[0]["path"], native.EXPORT)
        for bad in (valid + b"/another *(rw,fsid=1)\n", valid.replace(b"fsid=0", b"fsid=1"), valid.replace(b"rw,", b"ro,"), valid.replace(b"sync,", b"crossmnt,"), b"malformed\n"):
            with self.subTest(export=bad), self.assertRaises(native.Refused):
                native.parse_exports(bad)

    def test_namespace_control_rejects_host_namespace_before_any_fork(self):
        record = {"pid": {"pid": 123, "netns": "net:[1]"}}
        with patch.object(native.os, "readlink", return_value="net:[1]"), patch.object(native.os, "open") as opened:
            with self.assertRaisesRegex(native.Refused, "dedicated_server_network_namespace_required"):
                native.nfsd_controls(record, Path("unused"))
            opened.assert_not_called()

    def test_nfsd_transaction_reopens_each_inode_and_reads_complete_eof(self):
        # Model Linux transaction_ops: the pinned descriptor has cached 8,
        # while each new open sees actual live state. A read-used open cannot
        # subsequently accept another transaction write (EBUSY).
        live = [b"0\n"]
        handles, opens, writes = {7: [b"8\n", 0, True]}, [], []
        def opened(path, flags):
            self.assertEqual(path, "/proc/self/fd/7")
            fd = 100 + len(opens)
            handles[fd] = [live[0], 0, False]
            opens.append(fd)
            return fd
        def read(fd, limit):
            value = handles[fd]
            value[2] = True
            # Deliberately short reads are not EOF.
            raw = value[0][value[1]:value[1] + min(1, limit)]
            value[1] += len(raw)
            return raw
        def write(fd, raw):
            if handles[fd][2]:
                raise OSError("EBUSY cached transaction")
            live[0] = raw
            writes.append(fd)
            return len(raw)
        with patch.object(native.os, "open", side_effect=opened), patch.object(native.os, "read", side_effect=read), patch.object(native.os, "write", side_effect=write), patch.object(native.os, "close"), patch.object(native, "fs_magic", return_value=0x6E667364):
            self.assertEqual(native.Actor.read_fd(7), b"0\n")
            live[0] = b"16\n"
            self.assertEqual(native.Actor.read_fd(7), b"16\n")
            native.Actor.write_control(7, b"0\n")
            self.assertEqual(native.Actor.read_fd(7), b"0\n")
        self.assertEqual(len(set(opens)), 4)
        self.assertNotIn(7, writes)

    def test_actual_cri_image_must_equal_kubernetes_observed_digest(self):
        actor = native.Actor.__new__(native.Actor)
        actor.definition = {"node": {"name": "node1"}}
        item = {"namespace":native.NS,"node":"node1","pod":"original","pod_uid":"uid","container_id":"containerd://"+"a"*64,"image_digest":"sha256:"+"b"*64}
        status = {"id":"a"*64,"labels":{"io.kubernetes.pod.uid":"uid","io.kubernetes.pod.namespace":native.NS,"io.kubernetes.pod.name":"original"},"imageRef":"registry/repository@sha256:"+"b"*64}
        actor.cri = lambda args: native.encoded({"status":status})
        self.assertEqual(actor.inspect(item)["status"]["id"], "a"*64)
        status["imageRef"] = "registry/repository@sha256:"+"c"*64
        with self.assertRaisesRegex(native.Refused, "actual_cri_and_kubernetes_image_digest_mismatch"):
            actor.inspect(item)


@unittest.skipUnless(sys.platform.startswith("linux"), "requires actual Linux directory/proc FD semantics")
class LinuxFilesystemModels(unittest.TestCase):
    def test_actual_nfs_client_files_are_read_to_eof_without_dropping_delegations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            client=root/"clients"/"42"
            client.mkdir(parents=True)
            (root/"versions").write_bytes(b"-2 -3 +4 +4.1 +4.2\n")
            info=b'clientid: 0x1234\naddress: "10.42.0.1:789"\nstatus: confirmed\nminor version: 1\n'
            states=b'- 0x1234: { type: open, access: rw, filename: "original" }\n- 0x5678: { type: deleg, access: r, filename: "original" }\n'
            (client/"info").write_bytes(info)
            (client/"states").write_bytes(states)
            directory=os.open(root/"clients",os.O_RDONLY|os.O_DIRECTORY)
            versions=os.open(root/"versions",os.O_RDONLY)
            try:
                actor=native.Actor.__new__(native.Actor)
                actor.definition={"node":{"name":"model-node"}}
                actor.server={"item":{"pod_uid":"actual-model-uid"},"pid":native.process(os.getpid()),"clients_fd":directory,"versions_fd":versions}
                actor.server_closed=False
                events=[]
                actor.event=lambda action,data:events.append((action,data))
                with patch.object(native,"fs_magic",return_value=0x6E667364):
                    result=actor.source_nfs_client_census()
                    self.assertEqual(result["clients"][0]["address"],"10.42.0.1")
                    self.assertEqual(result["clients"][0]["state_kinds"],["open","deleg"])
                    self.assertEqual(bytes.fromhex(result["clients"][0]["states_bytes_hex"]),states)
                    self.assertFalse(result["delegation_flush_proved"])
                    self.assertFalse(result["network_admission_fence_proved"])
                    self.assertFalse(result["backup_ready"])
                    self.assertTrue(events)
                    (client/"info").write_bytes(info.replace(b"10.42.0.1:789",b"[fd00::1]:789"))
                    with self.assertRaisesRegex(native.Refused,"unknown_actual_nfsd_client_identity_or_address_format"):
                        actor.source_nfs_client_census()
                    (root/"versions").write_bytes(b"-2 +3 +4\n")
                    with self.assertRaisesRegex(native.Refused,"stateless_nfs_protocol_client_ownership_not_provable"):
                        actor.source_nfs_client_census()
            finally:
                os.close(directory)
                os.close(versions)

    def test_mount_census_finds_dns_source_alias_and_rejects_unmapped_mount(self):
        # Filesystem model only: all mountinfo rows are supplied fixture data,
        # never represented as a real node/native qualification observation.
        with tempfile.TemporaryDirectory() as tmp:
            proc=Path(tmp)/"proc"
            task=proc/"11"/"task"/"11"
            (task/"ns").mkdir(parents=True)
            os.symlink("mnt:[1]",task/"ns"/"mnt")
            info=task/"mountinfo"
            prefix="17 1 0:44 / "
            suffix=" rw - nfs4 workspace-store.system.svc:/ rw,vers=4.1,addr=10.1.2.3\n"
            info.write_text(prefix+"/workspaces"+suffix,encoding="ascii")
            actor=native.Actor.__new__(native.Actor)
            actor.definition={"node":{"name":"model-node"}}
            actor.clients=[{"item":{"pod_uid":"original-uid","container_id":"containerd://"+"a"*64,"nfs_server":"10.1.2.3"},"pid":{"mntns":"mnt:[1]"}}]
            actor.server=None
            real_path=Path
            def paths(value):
                return proc if str(value) == "/proc" else real_path(value)
            with patch.object(native,"Path",side_effect=paths):
                actual=actor.source_mount_census()
                self.assertEqual(len(actual["source_nfs_mounts"]),1)
                self.assertTrue(actual["only_mount_mapping_observed"])
                self.assertFalse(actual["backup_ready"])
                info.write_text(prefix+"/unmapped-alias"+suffix,encoding="ascii")
                with self.assertRaisesRegex(native.Refused,"unmapped_actual_source_node_nfs_mount_alias"):
                    actor.source_mount_census()

    def test_symlinks_nonutf8_names_and_permissions_do_not_follow_external_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"root"
            root.mkdir(mode=0o700)
            (root/"private").mkdir(mode=0o700)
            (root/"private"/"data").write_bytes(b"original")
            os.chmod(root/"private"/"data",0o640)
            outside=Path(tmp)/"outside"
            outside.write_bytes(b"external bytes must never be followed")
            os.symlink(outside,root/"link")
            fd=os.open(os.fsencode(root)+b"/\xff",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            os.write(fd,b"raw-name")
            os.close(fd)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                first=native.tree(fd,fsync_files=True)
                self.assertEqual(first["bytes"],len(b"originalraw-name"))
                self.assertEqual(first["entries"],4)
                self.assertEqual(native.tree(fd),first)
                outside.write_bytes(b"changed outside")
                self.assertEqual(native.tree(fd),first)
                os.chmod(root/"private"/"data",0o600)
                self.assertNotEqual(native.tree(fd)["tree_sha256"],first["tree_sha256"])
            finally:
                os.close(fd)

    def test_special_file_refuses_before_first_source_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkfifo(Path(tmp)/"live-socket-like-fifo",0o600)
            fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(native.Refused,"unknown_native_source_file_type"):
                    native.tree(fd)
            finally:
                os.close(fd)


@unittest.skipUnless(sys.platform.startswith("linux") and getattr(os,"geteuid",lambda:1)() == 0,"requires Linux root SO_PEERCRED transport; model only")
class PersistentTransportModel(unittest.TestCase):
    def test_lost_ssh_response_reconnects_same_owner_nonce_without_second_mutation(self):
        definition={"version":native.VERSION,"operation":"a"*32,"session":"b"*32,"node":{"name":"model"}}
        address=b"\0workspace-model-"+secrets.token_hex(16).encode()
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind(address)
        listener.listen(1)
        with tempfile.TemporaryDirectory() as tmp:
            counter=Path(tmp)/"counter"
            class ModelOwner:
                def __init__(self,original):
                    self.previous="0"*64
                    self.definition=original
                    self.clients_closed=self.server_closed=False
                    self.fd=os.open(counter,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
                    self.count=0
                def event(self,*args):
                    pass
                def call(self,action):
                    if action == "one-mutation":
                        self.count+=1
                        os.write(self.fd,str(self.count).encode())
                        os.fsync(self.fd)
                    elif action == "release-model":
                        os.close(self.fd)
                        self.clients_closed=self.server_closed=True
                    return {"count":self.count,"model_only":True}
            child=os.fork()
            if child == 0:
                try:
                    native.Actor=ModelOwner
                    native.serve(listener,definition)
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            listener.close()
            try:
                def connect():
                    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    connection.settimeout(5)
                    connection.connect(address)
                    stream=connection.makefile("rwb",buffering=0)
                    stream.write(native.encoded(definition)+b"\n")
                    hello=native.decode(stream.readline())
                    self.assertEqual(hello["definition_sha256"],native.sha(native.encoded(definition)))
                    return connection,stream
                connection,stream=connect()
                request={"operation":definition["operation"],"action":"one-mutation","nonce":"c"*64}
                stream.write(native.encoded(request)+b"\n")
                # Lose the transport after sending, without reading a reply.
                stream.close();connection.close()
                connection,stream=connect()
                stream.write(native.encoded(request)+b"\n")
                reply=native.decode(stream.readline())
                self.assertEqual(reply["data"]["count"],1)
                self.assertEqual(counter.read_bytes(),b"1")
                for action,nonce in (("release-model","d"*64),("retire-owner","e"*64)):
                    stream.write(native.encoded({"operation":definition["operation"],"action":action,"nonce":nonce})+b"\n")
                    self.assertNotIn("error",native.decode(stream.readline()))
                stream.close();connection.close()
                deadline=time.monotonic()+5
                while True:
                    pid,status=os.waitpid(child,os.WNOHANG)
                    if pid:
                        self.assertEqual(status,0)
                        child=None
                        break
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(0.01)
            finally:
                if child is not None:
                    os.kill(child,signal.SIGKILL)
                    os.waitpid(child,0)


if __name__ == "__main__":
    unittest.main()

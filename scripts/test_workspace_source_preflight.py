"""Control-flow models only; never native NFS/SSH/permission qualification."""
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("early_workspace_preflight_model",Path(__file__).with_name("system-backup-workspace-source-preflight.py"))
early=importlib.util.module_from_spec(spec)
spec.loader.exec_module(early)


class EarlyReadonlyFlowModels(unittest.TestCase):
    def fixture(self,directory,fail=False):
        actions=[]
        class Refused(Exception):
            pass
        def need(value,code):
            if not value:raise Refused(code)
        class Session:
            definition={"session":"b"*32}
            def rpc(self,action):
                actions.append(action)
                return {"model_only":True}
        class Stages:
            operation="a"*32
            def __init__(self,operator):
                self.directory=Path(directory)
            def retain(self,name,value):
                return {"File":str(self.directory/name),"SHA256":"c"*64}
        class Owner:
            def inventory(self):
                actions.append("actual-kube-shape-model")
                return {"namespace_uid":"model-namespace"}
            def native_sessions(self,*args):
                self.sessions.append(Session())
                return {"model-node":self.sessions[-1]}
            def nfs_client_boundary(self,*args):
                actions.append("actual-nfs-client-model")
                if fail:raise Refused("unknown_nfs_client_model")
                return {"model_only":True}
            def once(self,session,action):
                return session.rpc(action)
            def close(self):
                actions.append("relay-close")
        module=types.SimpleNamespace(need=need,Refused=Refused,DeploymentStages=Stages)
        workspace=types.SimpleNamespace(NATIVE_SHA="d"*64,WorkspaceLocalization=Owner)
        def forbidden(*args):
            raise AssertionError("DDL/SQL/enrollment/new-image/upgraded_released must not run")
        operator=types.SimpleNamespace(open=lambda:actions.append("original-release-kube-scope-only"),pins={"files":{"scripts/system-backup-workspace-native.py":"d"*64}},upgraded_released=forbidden,cli=forbidden,db=forbidden)
        return operator,module,workspace,actions

    def test_early_read_does_not_call_sql_or_require_upgraded_image(self):
        with tempfile.TemporaryDirectory() as directory:
            operator,module,workspace,actions=self.fixture(directory)
            with patch.object(early,"load_sealed",side_effect=[module,workspace]),patch.object(early,"private_ssh_materials"):
                result=early.dispatch(operator)
            self.assertEqual(result["state"],"readonly_original_nfs_and_direct_ssh_shapes_observed_not_qualified")
            self.assertFalse(result["native_qualified"])
            self.assertFalse(result["backup_ready"])
            self.assertIn("abort-before-mutation",actions)
            self.assertIn("retire-owner",actions)

    def test_unknown_client_is_nonzero_refusal_with_actual_cleanup_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            operator,module,workspace,actions=self.fixture(directory,fail=True)
            with patch.object(early,"load_sealed",side_effect=[module,workspace]),patch.object(early,"private_ssh_materials"):
                with self.assertRaises(early.EarlyPreflightRefused) as failure:
                    early.dispatch(operator)
            self.assertEqual(failure.exception.result["state"],"STOP_BEFORE_DATABASE_DDL_OR_DEPLOYMENT")
            self.assertEqual(failure.exception.result["reason_code"],"unknown_nfs_client_model")
            self.assertFalse(failure.exception.result["backup_ready"])
            self.assertIn("abort-before-mutation",actions)
            self.assertIn("retire-owner",actions)


if __name__ == "__main__":
    unittest.main()

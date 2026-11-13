import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('renew', Path(__file__).with_name('renew-p2-observer-nov13.py'))
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class BundleLimits(unittest.TestCase):
    def test_total_limit_and_member_limit_are_distinct(self):
        assembly, rotation = Mock(), Mock()
        pin = {'File':'/original/node.tar','SHA256':'original-pin'}
        assembly.read.return_value = b'verified-tar'
        rotation.tar_files.return_value = {'unit':b'original'}
        self.assertEqual(M.read_node_bundle(assembly,rotation,pin), {'unit':b'original'})
        assembly.read.assert_called_once_with(pin,256<<20)
        rotation.tar_files.assert_called_once_with(b'verified-tar',64<<20)

    def test_pin_or_total_bound_refusal_stops_extraction(self):
        assembly, rotation = Mock(), Mock()
        assembly.read.side_effect = ValueError('pin or bound refused')
        with self.assertRaises(ValueError): M.read_node_bundle(assembly,rotation,{})
        rotation.tar_files.assert_not_called()


if __name__=='__main__': unittest.main()

import copy
import importlib.util
from pathlib import Path, PurePosixPath
import unittest

spec = importlib.util.spec_from_file_location('reauthor', Path(__file__).with_name('reauthor-p2-redis-source.py'))
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class SuccessorTests(unittest.TestCase):
    def fixture(self):
        old = {'File':'/old-ca', 'SHA256':'old-sha'}
        keeper = {'CA':old, 'ReaderCredential':{'File':'/reader','SHA256':'reader-sha'},
                  'Native':{'Policy':{'ServerID':'same'}, 'PodUID':'same'}, 'CustodyKey':{'File':'/custody'}}
        definition = {'Version':'original-initial-source-author-inputs.v1',
            'Deployment':{'redis_read_keepers':[keeper], 'profile_file':'/old/execution-profile.json',
                          'capture_modules':{'path':'/old/capture-materials.json'}},
            'Connections':[{'Purpose':'source_redis','CA':old,'Credential':keeper['ReaderCredential']}],
            'Materials':{'DeploymentConfigSHA256':'', 'CaptureGrantSHA256':'',
                         'Redis':{'Redis':{'CAFile':old['File'],'CASHA256':old['SHA256']}}},
            'Until':'unchanged', 'NotBefore':'unchanged'}
        return definition, keeper

    def run_successor(self, definition, keeper):
        return M.successor(definition, keeper, {'File':'/new-ca','SHA256':'new-sha'}, PurePosixPath('/old'), PurePosixPath('/new'))

    def test_only_ca_and_output_paths_change(self):
        definition, keeper = self.fixture(); original = copy.deepcopy(definition)
        new = self.run_successor(definition, keeper)
        self.assertEqual(definition, original)
        self.assertEqual(new['Until'], definition['Until'])
        self.assertEqual(new['Deployment']['redis_read_keepers'][0]['Native'], keeper['Native'])
        self.assertEqual(new['Connections'][0]['Credential'], keeper['ReaderCredential'])
        self.assertEqual(new['Materials']['Redis']['Redis']['CAFile'], '/new-ca')
        restored = M.replace_ca(new, {'File':'/new-ca','SHA256':'new-sha'}, keeper['CA'])
        restored['Deployment']['profile_file'] = '/old/execution-profile.json'
        restored['Deployment']['capture_modules']['path'] = '/old/capture-materials.json'
        self.assertEqual(restored, original)

    def test_unhandled_reference_refused(self):
        definition, keeper = self.fixture()
        definition['Materials']['Unexpected'] = keeper['CA']
        with self.assertRaisesRegex(ValueError, 'unhandled'):
            self.run_successor(definition, keeper)

    def test_changed_reader_refused(self):
        definition, keeper = self.fixture()
        definition['Connections'][0]['Credential'] = {'File':'other'}
        with self.assertRaisesRegex(ValueError, 'reader binding'):
            self.run_successor(definition, keeper)


if __name__ == '__main__': unittest.main()

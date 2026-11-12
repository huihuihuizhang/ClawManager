import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('repair', Path(__file__).with_name('repair-p2-source-pv-read.py'))
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class PVReadRepairTests(unittest.TestCase):
    def rules(self):
        return [{'apiGroups':[''], 'resources':['persistentvolumes'], 'verbs':['get'], 'resourceNames':['existing-pv']},
                {'apiGroups':[''], 'resources':['nodes'], 'verbs':['get'], 'resourceNames':['node']}]

    def test_only_one_pv_added(self):
        old = self.rules(); saved = copy.deepcopy(old); new = M.expanded_rules(old)
        self.assertEqual(old, saved)
        self.assertEqual(new[1], old[1])
        self.assertEqual(set(new[0]['resourceNames']), {'existing-pv', M.PV})
        self.assertEqual(new[0]['verbs'], ['get'])
        self.assertEqual(M.expanded_rules(new), new)

    def test_broad_or_unexpected_rule_refused(self):
        for key, value in [('verbs',['get','list']), ('resourceNames',['*']), ('resourceNames',[]), ('apiGroups',['other'])]:
            rules = self.rules(); rules[0][key] = value
            with self.assertRaises(ValueError): M.expanded_rules(rules)

    def test_duplicate_rule_refused(self):
        rules = self.rules(); rules.append(copy.deepcopy(rules[0]))
        with self.assertRaises(ValueError): M.expanded_rules(rules)


if __name__ == '__main__': unittest.main()

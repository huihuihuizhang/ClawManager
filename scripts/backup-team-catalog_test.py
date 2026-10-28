import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("catalog", Path(__file__).with_name("backup-team-catalog.py"))
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)

class RegistrySummaryTest(unittest.TestCase):
    def item(self, name, state, approved=()):
        return dict(object_type="table", name=name, decision_status=state,
                    required_cross_reviewers=["A", "C"], approved_cross_reviewers=list(approved))
    def test_actual_objects_drive_counts_without_approving_pending(self):
        items = [self.item("a", "owner_recorded"), self.item("b", "pending_owner_review"), self.item("c", "frozen", ["A", "C"])]
        self.assertEqual(catalog.registry_summary(items), dict(object_count=3, policy_recorded=2, policy_pending=1, cross_review_pending=1))
        self.assertEqual(items[1]["decision_status"], "pending_owner_review")
    def test_unknown_and_duplicates_require_review(self):
        for items in [[self.item("a", "guessed")], [self.item("a", "frozen"), self.item("a", "frozen")]]:
            with self.assertRaises(ValueError): catalog.registry_summary(items)

if __name__ == "__main__": unittest.main()

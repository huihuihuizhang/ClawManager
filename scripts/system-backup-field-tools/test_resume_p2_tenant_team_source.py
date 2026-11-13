import datetime as dt
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('tenant_team', Path(__file__).with_name('resume-p2-tenant-team-source.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)


class TenantTeamRenewalTests(unittest.TestCase):
    def test_window_never_exceeds_credential_or_certificate(self):
        now = dt.datetime(2026, 11, 13, 9, tzinfo=dt.timezone.utc)
        later = now + dt.timedelta(hours=8)
        self.assertEqual(R.window(now, later, later, later), (now-dt.timedelta(seconds=5), now+dt.timedelta(hours=2)))
        for i in range(3):
            limits = [later, later, later]; limits[i] = now + dt.timedelta(minutes=45)
            self.assertEqual(R.window(now, *limits)[1], limits[i])
            limits[i] = now + dt.timedelta(minutes=19)
            with self.assertRaises(ValueError): R.window(now, *limits)

    def test_attachment_window_is_thirty_minutes(self):
        now = dt.datetime(2026, 11, 13, 9, tzinfo=dt.timezone.utc)
        later = now + dt.timedelta(hours=8)
        self.assertEqual(R.window(now, later, later, later, 30)[1], now + dt.timedelta(minutes=30))

    def test_renewal_requires_exact_authenticated_account(self):
        class Assembly:
            NS = 'system'
            @staticmethod
            def need(ok, why):
                if not ok: raise ValueError(why)
        status = {'authenticated': True, 'user': {'username': 'system:serviceaccount:system:reader', 'uid': 'original'}}
        R.identity(Assembly, status, 'reader', 'original')
        for invalid in [dict(status, authenticated=False), dict(status, error='refused'),
                        {'user': dict(status['user'], uid='replacement')},
                        {'user': dict(status['user'], username='system:serviceaccount:other:reader')}]:
            with self.assertRaises(ValueError): R.identity(Assembly, invalid, 'reader', 'original')


if __name__ == '__main__': unittest.main()

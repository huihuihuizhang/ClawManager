"""Fail closed on an unknown or partially written original observation."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('vault_resume', Path(__file__).with_name('resume-p2-vault-dependency.py'))
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


class RefusedObservationChecks(unittest.TestCase):
    def args(self):
        return [R.OLD_AUTHOR, '--mode', 'provider-materials', '--output-directory', '/fixture/old']

    def test_known_failed_empty_observation_preserves_original_argv(self):
        selected = self.args()
        self.assertEqual(R.refused_observation(selected, {'ExitCode': 1}, b'', b'', [])['--mode'], 'provider-materials')
        self.assertEqual(selected, self.args())

    def test_unknown_successful_or_partially_written_observation_refuses(self):
        for exit_value, stdout, stderr, files in [({}, b'', b'', []), ({'ExitCode': 0}, b'', b'', []),
                                                ({'ExitCode': True}, b'', b'', []),
                                                ({'ExitCode': 1}, b'partial', b'', []),
                                                ({'ExitCode': 1}, b'', b'unknown error', []),
                                                ({'ExitCode': 1}, b'', b'', ['partial.json'])]:
            with self.subTest(exit_value=exit_value, files=files):
                with self.assertRaises(ValueError):
                    R.refused_observation(self.args(), exit_value, stdout, stderr, files)

    def test_other_modes_tools_duplicate_flags_or_incomplete_arguments_refuse(self):
        for argv in [[R.OLD_AUTHOR, '--mode', 'round-trip'],
                     ['/fixture/different-tool', *self.args()[1:]],
                     [*self.args(), '--mode', 'provider-materials'],
                     [*self.args(), '--unknown']]:
            with self.assertRaises(ValueError):
                R.refused_observation(argv, {'ExitCode': 1}, b'', b'', [])

    def test_jwt_continuation_requires_exact_prior_stage_and_empty_outputs(self):
        argv = ['/fixture/profile-author', '--mode', 'provider-materials']
        failure = {'Version': 'original-vault-dependency-material-failure.v1',
                   'State': 'unconfirmed_preserve_original_materials', 'Phase': 'kubernetes_jwt_trust'}
        R.jwt_trust_refusal(argv, list(argv), {'ExitCode': 1}, json.dumps(failure).encode(), b'', [])
        for value in [dict(failure, Phase='provider_native_metadata'), dict(failure, State='unknown'), {}]:
            with self.assertRaises(ValueError):
                R.jwt_trust_refusal(argv, list(argv), {'ExitCode': 1}, json.dumps(value).encode(), b'', [])
        for selected, exit_value, stderr, files in [(argv + ['--other'], {'ExitCode': 1}, b'', []),
                                                  (argv, {'ExitCode': 0}, b'', []),
                                                  (argv, {'ExitCode': True}, b'', []),
                                                  (argv, {'ExitCode': 1}, b'unknown', []),
                                                  (argv, {'ExitCode': 1}, b'', ['partial.json'])]:
            with self.assertRaises(ValueError):
                R.jwt_trust_refusal(selected, list(argv), exit_value, json.dumps(failure).encode(), stderr, files)


if __name__ == '__main__':
    unittest.main()

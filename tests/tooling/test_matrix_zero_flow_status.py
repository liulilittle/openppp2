"""An exact-zero stream must fail a matrix with CPU profiling disabled."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from datapath_matrix_metadata import evaluate_qualification_status


class ZeroFlowStatusTest(unittest.TestCase):
    def test_no_profile_zero_completion_fails(self):
        cell = dict(status='pass', cpu_measurement={'profile': 'none'},
                    fairness={'zero_rate_flows': 16},
                    qualification={'status': 'unavailable'})
        self.assertEqual(evaluate_qualification_status([cell]), 'fail')

    def test_no_profile_complete_flows_pass(self):
        cell = dict(status='pass', cpu_measurement={'profile': 'none'},
                    fairness={'zero_rate_flows': 0})
        self.assertEqual(evaluate_qualification_status([cell]), 'pass')


if __name__ == '__main__':
    unittest.main()

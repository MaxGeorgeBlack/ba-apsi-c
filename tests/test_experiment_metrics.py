import math, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments'))
from slm_metrics import metrics, policy_sets


class MetricsTest(unittest.TestCase):
    def test_global_denominator(self):
        v = metrics(['bad', 'a'], {'a', 'b', 'c'}, {'bad', 'other'})
        self.assertEqual(v['matching_rate'], 0.5)
        self.assertEqual(v['leakage_rate'], 0.5)
        self.assertEqual(v['recall_at_10'], 1 / 3)
        self.assertEqual(v['mrr'], 0.5)
        self.assertAlmostEqual(v['ndcg_at_10'], (1 / math.log2(3)) / (1 + 1 / math.log2(3) + 0.5))

    def test_empty_and_incomplete(self):
        v = metrics([], {'a'}, {'b'})
        self.assertIsNone(v['matching_rate'])
        self.assertEqual(v['mrr'], 0)
        self.assertEqual(v['recall_at_10'], 0)
        self.assertEqual(v['leakage_rate'], 0)
        v = metrics([], set(), set())
        self.assertIsNone(v['leakage_rate'])
        self.assertIsNone(v['recall_at_10'])
        self.assertLess(metrics(['a'], {'a', 'b'}, set())['ndcg_at_10'], 1)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            metrics(['a', 'a'], {'a'}, set())
        with self.assertRaises(ValueError):
            metrics([], {'a'}, {'a'})

    def test_policy(self):
        q = dict(
            requesting_agent='a',
            tenant_id='t',
            namespace='n',
            entity_type='risk',
            query_entities=['PROJECT 01'],
            required_policy_tags=['share'],
            policy_version='v2',
        )
        base = dict(
            owner_agent='o',
            tenant_id='t',
            namespace='n',
            entity_type='risk',
            entity_value=' project 01 ',
            policy_tags=['share'],
            authorized_agents=['a'],
        )
        rows = [
            base | dict(memory_id='yes'),
            base | dict(memory_id='denied', unauthorized_agents=['a']),
            base | dict(memory_id='revoked'),
            base | dict(memory_id='grant', authorized_agents=[]),
            base | dict(memory_id='foreign', tenant_id='x'),
            base | dict(memory_id='wrong_tag', policy_tags=[]),
        ]
        p = dict(
            policy_version='v2',
            grants={'grant': ['a'], 'denied': ['a']},
            revoked_memory_ids=['revoked'],
        )
        a, u = policy_sets(rows, q, p)
        self.assertEqual(a, {'yes', 'grant'})
        self.assertEqual(u, {'denied', 'revoked'})
        with self.assertRaises(ValueError):
            policy_sets(rows, q, p | {'policy_version': 'v1'})


if __name__ == '__main__':
    unittest.main()

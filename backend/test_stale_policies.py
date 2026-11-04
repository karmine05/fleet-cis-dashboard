"""Run: cd backend && python -m unittest test_stale_policies"""
import unittest

from sync_fleet_data import compute_stale_policy_ids

# Team 1 is live and fetched; team 2 is live but its policy fetch failed; team 9 was
# deleted in Fleet. Policy ids: 10 live in team 1, 11 gone from team 1, 20 in team 2,
# 90 in deleted team 9.
DB = [(10, 1), (11, 1), (20, 2), (90, 9)]


def stale(teams_ok=True, ok_team_ids=frozenset({1}), all_team_ids=frozenset({1, 2})):
    return sorted(compute_stale_policy_ids(
        DB, global_ok=True, teams_ok=teams_ok, ok_team_ids=set(ok_team_ids),
        all_team_ids=set(all_team_ids), global_api_ids=set(), team_api_ids={1: {10}}))


class StalePolicies(unittest.TestCase):
    def test_removed_policy_and_deleted_team_are_pruned(self):
        self.assertEqual(stale(), [11, 90])

    def test_unreachable_team_is_kept(self):
        self.assertNotIn(20, stale())

    def test_nothing_pruned_by_team_when_team_list_failed(self):
        self.assertEqual(stale(teams_ok=False, ok_team_ids=set(), all_team_ids=set()), [])


if __name__ == "__main__":
    unittest.main()

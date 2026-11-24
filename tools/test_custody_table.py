#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""NC0 share custody enumeration tests. Apache-2.0."""

import unittest

import custody_table as custody


class CustodyTableTest(unittest.TestCase):
    def test_adopted_layout_meets_single_place_rules(self):
        self.assertEqual(custody.violations(custody.PLACES), [])
        outcomes = {chosen: (stolen, kept) for chosen, stolen, kept in custody.rows(custody.PLACES)}
        self.assertEqual(len(outcomes), 15)
        self.assertEqual(outcomes[("Site 1",)], (["A"], ["B", "C"]))
        self.assertEqual(outcomes[("P",)], ([], ["A", "B"]))
        self.assertEqual(outcomes[("Site 1", "Site 2")][0], ["A", "B"])
        self.assertEqual(outcomes[("P", "Cloud")], (["C"], ["A", "B"]))

    def test_pure_cross_stored_papers_lose_the_root_with_one_site(self):
        crossed = dict(custody.PLACES)
        crossed["Site 1"] = frozenset({"stick A", "paper B"})
        crossed["Site 2"] = frozenset({"stick B", "paper A"})
        self.assertIn("loss of Site 1 leaves 1 shares", custody.violations(crossed))

    def test_both_sticks_in_one_place_breaks_both_rules(self):
        careless = dict(custody.PLACES)
        careless["Site 1"] = frozenset({"stick A", "paper A", "stick B", "paper B"})
        careless["Site 2"] = frozenset()
        problems = custody.violations(careless)
        self.assertIn("theft of Site 1 yields 2 shares", problems)
        self.assertIn("loss of Site 1 leaves 1 shares", problems)


if __name__ == "__main__":
    unittest.main()

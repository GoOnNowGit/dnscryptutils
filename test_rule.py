from unittest import TestCase

from rules import PfRule


class TestPfRule(TestCase):
    def test_can_make_rule(self):
        tests = [
            (
                PfRule(),
                dict(address="address", port="port"),
                "pass out quick proto tcp to address port port",
            ),
            (PfRule(), dict(address="address"), "pass out quick proto tcp to address"),
            (
                PfRule(label="testing"),
                dict(address="address"),
                "pass out quick proto tcp to address label testing",
            ),
            (
                PfRule(interface="en0", label="testing"),
                dict(address="address"),
                "pass out quick on en0 proto tcp to address label testing",
            ),
            (
                PfRule(log=True, interface="en0", label="testing"),
                dict(address="address"),
                "pass out log quick on en0 proto tcp to address label testing",
            ),
        ]

        for pf_rule, info, expected in tests:
            with self.subTest(f"should return {expected}"):
                result = pf_rule.make_rule(info)
                self.assertEqual(expected, result)

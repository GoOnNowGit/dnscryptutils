from unittest import TestCase

from dnscryptutils.rules import Console, PfRule


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
                PfRule(),
                dict(address="address", source="testing"),
                "pass out quick proto tcp to address label testing",
            ),
            (
                PfRule(interface="en0"),
                dict(address="address", source="testing"),
                "pass out quick on en0 proto tcp to address label testing",
            ),
            (
                PfRule(log=True, interface="en0"),
                dict(address="address", source="testing"),
                "pass out log quick on en0 proto tcp to address label testing",
            ),
        ]

        for pf_obj, info, expected in tests:
            with self.subTest(f"should return {expected}"):
                result = pf_obj(info)
                self.assertEqual(expected, result)


class TestRaw(TestCase):
    def test_raw_rule(self):
        tests = [
            (
                Console(),
                dict(address="address", source="testing"),
                "testing None None address None",
            ),
        ]

        for obj, info, expected in tests:
            with self.subTest(f"should return {expected}"):
                result = obj(info)
                self.assertEqual(expected, result)

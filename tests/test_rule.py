import argparse
from unittest import TestCase

from dnscryptutils.rules import PfRule, Raw


class TestPfRule(TestCase):
    def test_can_make_rule(self):
        tests = [
            (
                PfRule(
                    argparse.Namespace(
                        interface=None,
                        action="pass",
                        log=False,
                        quick=True,
                        add_label=False,
                        protocol=None,
                        source="any",
                    )
                ),
                dict(address="address", port="port"),
                "pass out quick from any to address port port",
            ),
            (
                PfRule(
                    argparse.Namespace(
                        interface=None,
                        action="pass",
                        log=False,
                        quick=True,
                        add_label=True,
                        protocol=None,
                        source=None,
                    )
                ),
                dict(address="address"),
                "pass out quick to address",
            ),
            (
                PfRule(
                    argparse.Namespace(
                        interface=None,
                        action="pass",
                        log=False,
                        quick=True,
                        add_label=True,
                        protocol=None,
                        source=None,
                    )
                ),
                dict(address="address", source="testing"),
                "pass out quick to address label testing",
            ),
            (
                PfRule(
                    argparse.Namespace(
                        interface="en0",
                        action="pass",
                        log=False,
                        quick=True,
                        add_label=True,
                        protocol="tcp",
                        source=None,
                    )
                ),
                dict(address="address", source="testing"),
                "pass out quick on en0 proto tcp to address label testing",
            ),
            (
                PfRule(
                    argparse.Namespace(
                        interface="en0",
                        action="pass",
                        log=True,
                        quick=True,
                        add_label=True,
                        protocol=None,
                        source=None,
                    )
                ),
                dict(address="address", source="testing"),
                "pass out log quick on en0 to address label testing",
            ),
        ]

        for pf_obj, info, expected in tests:
            with self.subTest(expected):
                result = pf_obj(info)
                self.assertEqual(expected, result)


class TestRaw(TestCase):
    def test_raw_rule(self):
        tests = [
            (
                Raw(argparse.Namespace()),
                dict(address="address", stamp="stamp", source="testing"),
                "testing None None stamp address None",
            ),
        ]

        for obj, info, expected in tests:
            with self.subTest(expected):
                result = obj(info)
                self.assertEqual(expected, result)

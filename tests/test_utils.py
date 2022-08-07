import ipaddress
import os.path
import unittest
from unittest.mock import MagicMock

import toml

from dnscryptutils import utils


class TestUtils(unittest.TestCase):
    def setUp(self):
        self.ip6_stamp = "sdns://gRZbMjAwMTpiYzg6MTgyNDo3Mzg6OjFd"
        self.ip4_stamp = "sdns://gQ01MS4xNTguMTY2Ljk3"
        self.ip4_stamp_parsed = dict(
            address="51.158.166.97", port=None, stamp=self.ip4_stamp
        )
        self.ip6_stamp_parsed = dict(
            address="2001:bc8:1824:738::1", port=None, stamp=self.ip6_stamp
        )

        HERE = os.path.abspath(os.path.dirname(__file__))
        self.relays_md = os.path.join(HERE, "test_data", "relays.md")
        self.dnscrypt_proxy_config = os.path.join(
            HERE, "test_data", "dnscrypt-proxy.toml"
        )

    def test_given_no_data_source_returns_empty_list(self):
        addrs = utils.get_sdns_info(None)
        self.assertEqual(list(addrs), [])

    def test_bad_sdns_returns_empty(self):
        stamp = "sdns://THISISABADSDNS"
        self.assertEqual(
            utils.parse_stamp(stamp),
            dict(address=None, port=None, stamp="sdns://THISISABADSDNS"),
        )

    def test_given_empty_toml_returns_empty_list(self):
        data = utils.get_sources_from_dnscrypt_config({})
        self.assertSequenceEqual(list(data), [])

    def test_given_valid_toml_returns_source_data(self):
        data = toml.load(self.dnscrypt_proxy_config)
        result = utils.get_sources_from_dnscrypt_config(data)

        expected = [
            (
                "public-resolvers",
                "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md",
                "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            ),
            (
                "public-resolvers",
                "https://download.dnscrypt.info/resolvers-list/v2/public-resolvers.md",
                "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            ),
            (
                "relays",
                "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/relays.md",
                "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            ),
            (
                "relays",
                "https://download.dnscrypt.info/resolvers-list/v2/relays.md",
                "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            ),
        ]

        self.assertEqual(list(result), expected)

    def test_given_good_data_source_returns_sdns_addrs(self):
        requester = MagicMock()
        requester.side_effect = [self.ip4_stamp, "minisig_data"]
        expected_minisign_key = "minisign_key"
        fake_minisign = MagicMock()
        fake_minisign.return_value = 0
        data_source = utils.minisigned_url(
            "url",
            expected_minisign_key,
            url_retriever=requester,
            minisign=fake_minisign,
        )

        result = utils.get_sdns_info(data_source)
        self.assertEqual(
            list(result),
            [self.ip4_stamp_parsed],
        )

    def test_minisign_fails_to_validate_and_returns_no_data(self):
        requester = MagicMock()
        requester.side_effect = [self.ip4_stamp, "minisig_data"]
        expected_minisign_key = "minisign_key"
        fake_minisign = MagicMock()
        fake_minisign.return_value = 1
        with self.assertRaises(utils.NoDataFromSource):
            _ = utils.minisigned_url(
                "url",
                expected_minisign_key,
                url_retriever=requester,
                minisign=fake_minisign,
            )

    def test_can_parse_addresses_from_valid_stamps(self):
        with open(self.relays_md, "r") as relays:
            data = relays.read()
        stamps = utils.get_stamps(data)

        self.assertEqual(len(list(stamps)), 39)

        for stamp in stamps:
            info = utils.parse_stamp(stamp)
            # should parse as a valid address
            ipaddress.ip_address(info["address"])

    def test_address_and_port_is_none(self):
        stamp = "sdns://AgcAAAAAAAAAAKDMEGDTnIMptitvvH0NbfkwmGm5gefmOS1c2PpAj02A5iBETr1nu4P4gHs5Iek4rJF4uIK9UKrbESMfBEz18I33zhZkb2guYXBwbGllZHByaXZhY3kubmV0Bi9xdWVyeQ"
        info = utils.parse_stamp(stamp)
        self.assertIsNone(info["address"])
        self.assertIsNone(info["port"])

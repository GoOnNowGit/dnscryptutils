import ipaddress
import os.path
import unittest
from unittest.mock import MagicMock

from dnscryptutils import utils


class FakeMinisign:
    def __init__(self, expected_minisign_key, return_value=0):
        self.expected_minisign_key = expected_minisign_key
        self.return_value = return_value

    def __call__(self, source_filepath: str, minisig_filepath: str, minisign_key: str):
        assert os.path.exists(source_filepath)
        assert os.path.exists(minisig_filepath)
        assert minisign_key == self.expected_minisign_key
        return self.return_value


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
        self.toml_data = {
            "sources": {
                "relays": {
                    "urls": ["http://127.0.0.1:8080/test_data/relays.md"],
                    "cache_file": "relays.md",
                    "minisign_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
                    "refresh_delay": 72,
                    "prefix": "",
                }
            }
        }
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

    def test_gets_multiple_sdns(self):
        datasource = """
        # sdns one
        sdns://gRZbMjAwMTpiYzg6MTgyNDo3Mzg6OjFd
        # sdns two
        sdns://gRZbMjAwMTpiYzg6MTgyNDo3Mzg6OjFd
        """
        addrs = utils.get_sdns_info(datasource)
        self.assertEqual(len(list(addrs)), 2)

    def test_given_empty_toml_returns_empty_list(self):
        data = utils.get_sources_from_dnscrypt_config({})
        self.assertSequenceEqual(list(data), [])

    def test_given_valid_toml_returns_source_data(self):
        result = utils.get_sources_from_dnscrypt_config(self.toml_data)
        expected = [
            (
                "relays",
                "http://127.0.0.1:8080/test_data/relays.md",
                "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
            ),
        ]
        self.assertEqual(list(result), expected)

    def test_given_good_data_source_returns_sdns_addrs(self):
        requester = MagicMock()
        requester.side_effect = [self.ip4_stamp, "minisig_data"]
        expected_minisign_key = "minisign_key"
        fake_minisign = FakeMinisign(expected_minisign_key)
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
        fake_minisign = FakeMinisign(
            expected_minisign_key=expected_minisign_key, return_value=1
        )

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

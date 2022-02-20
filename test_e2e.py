import ipaddress
import os.path
import unittest

import toml

import utils


class TestE2E(unittest.TestCase):
    HERE = os.path.abspath(os.path.dirname(__file__))

    def setUp(self):
        self.config = os.path.join(TestE2E.HERE, "test_data", "dnscrypt-proxy.toml")
        self.toml_data = toml.load(self.config)

    def test_e2e(self):
        source, url, mkey = next(utils.get_sources_from_toml(self.toml_data))

        self.assertEqual(source, "relays")
        self.assertEqual(
            url,
            "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md",
        )
        self.assertEqual(
            mkey, "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
        )

        data = utils.minisigned_url(url, mkey)
        assert data

        infos = utils.get_sdns_info(data)
        assert infos
        # should all parse as IP addresses
        for info in infos:
            ipaddress.ip_address(info["address"])

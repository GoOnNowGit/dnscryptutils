import argparse
import sys

import toml

from dnscryptutils import PfRule, utils

parser = argparse.ArgumentParser(
    description="build firweall rules from dnstamps in dnscrypt-proxy.toml sources"
)


parser.add_argument(
    "--config",
    dest="dnscrypt_config",
    action="store",
    help="dnscrypt-proxy.toml file path",
)

args = parser.parse_args()


def main():
    toml_data = toml.load(args.dnscrypt_config)
    sources = utils.get_sources_from_toml(toml_data)
    pf_rule = PfRule(interface="en0")

    for source, url, minisign_key in sources:
        try:
            data = utils.minisigned_url(url, minisign_key)
        except utils.NoDataFromSource:
            continue

        pf_rule.label = source
        for info in utils.get_sdns_info(data):
            rule = pf_rule.make_rule(info)
            print(rule)


if __name__ == "__main__":
    sys.exit(main())

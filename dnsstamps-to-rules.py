import argparse
import sys

import toml

import utils
from rules import PfRule

parser = argparse.ArgumentParser(
    description="build firweall rules from dnstamps in dnscrypt-proxy.toml sources"
)


parser.add_argument(
    "--config",
    dest="dnscrypt_config",
    action="store",
    help="dnscrypt-proxy.toml file path",
)

parser.add_argument(
    "--rule_type",
    required=True,
    choices=["pf"],
    dest="rule_type",
    action="store",
    help="type of rules to output",
)

args = parser.parse_args()

rule_makers = {
    "pf": PfRule(),
}


def main():
    rule_maker = rule_makers[args.rule_type]

    toml_data = toml.load(args.dnscrypt_config)
    sources = utils.get_sources_from_toml(toml_data)

    for source, url, minisign_key in sources:
        try:
            data = utils.minisigned_url(url, minisign_key)
        except utils.NoDataFromSource:
            continue

        rule_maker.label = source
        for info in utils.get_sdns_info(data):
            rule = rule_maker.make_rule(info)
            print(rule)


if __name__ == "__main__":
    sys.exit(main())

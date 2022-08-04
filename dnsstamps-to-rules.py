import argparse
import sys

import toml

from dnscryptutils import utils
from dnscryptutils.rules import PfRule, Raw


def parse_args(args):
    parser = argparse.ArgumentParser(
        description="build firweall rules from dnstamps in dnscrypt-proxy.toml sources"
    )

    parser.add_argument(
        "--dnscrypt_config",
        help="dnscrypt-proxy.toml file path",
    )

    parser.add_argument(
        "--rule_engine",
        choices=["pf", "raw"],
        help="type of rules to output",
    )

    pf_group = parser.add_argument_group("pf")
    pf_group.add_argument("--interface", default=None)
    pf_group.add_argument("--action", default="pass", help="block | pass")
    pf_group.add_argument("--log", action="store_false")
    pf_group.add_argument("--quick", action="store_false")
    pf_group.add_argument("--add_label", action="store_false")

    return parser.parse_args()


def main():
    rule_engines = {
        "pf": PfRule,
        "raw": Raw,
    }

    args = parse_args(sys.argv[1:])

    rule_engine = rule_engines[args.rule_engine]
    toml_data = toml.load(args.dnscrypt_config)
    the_rule_engine = rule_engine(args)

    for source, url, minisign_key in utils.get_sources_from_dnscrypt_config(toml_data):
        try:
            data = utils.minisigned_url(url, minisign_key)
        except utils.NoDataFromSource:
            print(f"No data from {source}...")
            continue

        for info in utils.get_sdns_info(data):
            info["source"] = source
            info["url"] = url
            info["minisign_key"] = minisign_key
            output = the_rule_engine(info)
            print(output)


if __name__ == "__main__":
    sys.exit(main())

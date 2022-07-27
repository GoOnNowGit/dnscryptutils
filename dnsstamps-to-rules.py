import argparse
import sys

import toml

from dnscryptutils import utils
from dnscryptutils.rules import Console, PfRule

parser = argparse.ArgumentParser(
    description="build firweall rules from dnstamps in dnscrypt-proxy.toml sources"
)


parser.add_argument(
    "--dnscrypt_config",
    action="store",
    help="dnscrypt-proxy.toml file path",
)

parser.add_argument(
    "--rule_type",
    required=True,
    choices=["pf", "console"],
    action="store",
    help="type of rules to output",
)

pfrule_arg_group = parser.add_argument_group("pf")
pfrule_arg_group.add_argument("--interface")
pfrule_arg_group.add_argument("--action")
pfrule_arg_group.add_argument("--log", action="store_false")
pfrule_arg_group.add_argument("--quick", action="store_false")
pfrule_arg_group.add_argument("--add_label", action="store_false")


args = parser.parse_args()

rule_engines = {
    "pf": PfRule,
    "console": Console,
}


def main():
    rule_type = rule_engines[args.rule_type]
    toml_data = toml.load(args.dnscrypt_config)

    rule_engine = None
    if args.rule_type == "pf":
        rule_engine(interface=args.pf.interface)

    sources = utils.get_sources_from_toml(toml_data)

    for source, url, minisign_key in sources:
        try:
            data = utils.minisigned_url(url, minisign_key)
        except utils.NoDataFromSource:
            print(f"No data from {source}...")
            continue

        for info in utils.get_sdns_info(data):
            info["source"] = source
            info["url"] = url
            info["minisign_key"] = minisign_key
            rule = rule_engine(info)
            print(rule)


if __name__ == "__main__":
    sys.exit(main())

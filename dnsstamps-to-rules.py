import argparse
import sys

import toml

from dnscryptutils import utils


def dump_info(info: dict) -> str:
    server = info.get("address")
    port = info.get("port")
    source = info.get("source")
    url = info.get("url")
    minisign_key = info.get("minisign_key")
    stamp = info.get("stamp")
    return f"{source} {url} {minisign_key} {stamp} {server} {port}"


def parse_args(args):
    parser = argparse.ArgumentParser(
        description="Dump SDNS info from source URLS in dnscrypt-proxy.toml config"
    )

    parser.add_argument(
        "--dnscrypt_config",
        help="dnscrypt-proxy.toml file path",
    )

    return parser.parse_args()


def main():
    args = parse_args(sys.argv[1:])
    toml_data = toml.load(args.dnscrypt_config)
    bad_sources = []

    for source, url, minisign_key in utils.get_sources_from_dnscrypt_config(toml_data):
        try:
            data = utils.minisigned_url(url, minisign_key)
        except utils.NoDataFromSource:
            bad_sources.append(source)
            continue
        # some stamps seem to return an empty host.
        # just returns dicts that have a host
        servers = (info for info in utils.get_sdns_info(data) if info["address"])
        for info in servers:
            info["source"] = source
            info["url"] = url
            info["minisign_key"] = minisign_key
            print(dump_info(info))

    if len(bad_sources):
        print(f"sources that returned no data:\n{bad_sources}")


if __name__ == "__main__":
    sys.exit(main())

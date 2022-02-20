"""
helper functions to retrieve sources from
a dnscrypt-config.toml, extract dns stamps and
parsing those stamps to return ip addresses
"""

import os
import os.path
import re
import subprocess
from contextlib import contextmanager
from tempfile import mkstemp

import dnsstamps
import requests


class GetStampInfoError(Exception):
    pass


class NoDataFromSource(GetStampInfoError):
    pass


class MalformedSDNS(GetStampInfoError):
    pass


@contextmanager
def data_disk(named_data: dict, file_provider=mkstemp, file_remover=os.unlink):
    """
    for each key in named_data write the value (named_data[key])
    to a temporary file on disk. then yield a new dictionary where the keys
    are the keys from named_data and the values are the corresponding temporary
    file paths were the values (named_data[key]) were written to disk
    """
    paths = {}

    try:
        for name, data in named_data.items():
            fd, path = file_provider()
            os.write(fd, data.encode())
            paths[name] = path
        yield paths
    finally:
        for path in paths.values():
            file_remover(path)


def get_stamps(data: str):
    """
    get all dns stamps from content
    """
    data = data or ""
    pattern = r"sdns://[a-zA-z0-9]+"
    return re.findall(pattern, data)


def parse_stamp(stamp: str):
    """
    make a dictionary from the parsed stamps contents
    """
    try:
        parsed = dnsstamps.parse(stamp)
    except Exception:
        return None
        # raise MalformedSDNS from exc

    if re.search(r"]:\d{1,5}", parsed.address):
        # remove port and if ip6 remove []
        # address = re.sub(r"[\[|\]]", "", addr.rsplit(":", 1)[0])
        address, port = re.sub(r"[\[|\]]", "", parsed.address).rsplit(":", 1)
    elif re.search(r"]$", parsed.address):
        # no port, if ip6 remove []
        address, port = re.sub(r"[\[|\]]", "", parsed.address), None
    elif re.search(r":\d{1,5}$", parsed.address):
        # ip4
        address, port = parsed.address.rsplit(":", 1)
    else:
        address, port = parsed.address, None

    return dict(address=address, port=port)


def subprocess_execute(args: list):
    """
    execute args via subprocess
    """
    return subprocess.call(args)


def minisign_verify(
    source_filepath: str,
    minisig_filepath: str,
    minisign_key: str,
    command_executor=subprocess_execute,
) -> int:
    """
    verify data via minisig
    """
    minisign = os.path.join("/", "usr", "local", "bin", "minisign")
    args = [
        minisign,
        "-V",
        "-m",
        source_filepath,
        "-x",
        minisig_filepath,
        "-P",
        minisign_key,
    ]
    return command_executor(args)


def get_sdns_info(data: str):
    for stamp in get_stamps(data):
        info = parse_stamp(stamp)
        if info:
            yield info


def requests_api(url: str) -> bytes:
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as exc:
        raise NoDataFromSource from exc

    if response.status_code != requests.codes["ok"]:
        raise NoDataFromSource

    return response.content.decode()


def minisigned_url(
    url: str,
    minisign_key: str,
    minisig_url=None,
    url_retriever=requests_api,
    disk=data_disk,
    minisign=minisign_verify,
) -> bytes:
    """
    retrieve a minisigned url and minisig file
    and verify that the data
    """
    minisign_url = minisig_url or f"{url}.minisig"

    source_response = url_retriever(url)
    minisig_response = url_retriever(minisign_url)

    responses = {
        "source": source_response,
        "minisig": minisig_response,
    }

    with disk(responses) as file_path_for:
        # verify  minisigned data
        result = minisign(
            file_path_for["source"], file_path_for["minisig"], minisign_key
        )
        if result != 0:
            raise NoDataFromSource

    return source_response


def get_sources_from_toml(toml_data: dict):
    """
    retrieve source blocks from dnscrypt-proxy.toml
    """
    sources = toml_data.get("sources", {})
    for source, properties in sources.items():
        if "urls" in properties and "minisign_key" in properties:
            for url in properties["urls"]:
                yield source, url, properties["minisign_key"]

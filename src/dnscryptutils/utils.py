"""
helper functions to retrieve sources from
a dnscrypt-config.toml, extract dns stamps and
parsing those stamps to return ip addresses
"""

import os
import os.path
import re
import subprocess
from ast import Call
from contextlib import contextmanager
from email.generator import Generator
from tempfile import mkstemp
from typing import Callable, Generator, List, Tuple

import dnsstamps
import requests


class GetStampInfoError(Exception):
    pass


class NoDataFromSource(GetStampInfoError):
    pass


@contextmanager
def dict_to_disk(
    named_data: dict,
    file_provider: Callable = mkstemp,
    file_remover: Callable = os.unlink,
    remove_files: bool = True,
) -> dict:
    """for each key in named_data write the value (named_data[key])
    to a temporary file on disk. then yield a new dictionary where the keys
    are the keys from named_data and the values are the corresponding temporary
    file paths were the values (named_data[key]) were written to disk

    Parameters
    ----------
    named_data : dict
        _description_
    file_provider : Callable, optional
        _description_, by default mkstemp
    file_remover : Callable, optional
        _description_, by default os.unlink
    remove_files : bool, optional
        _description_, by default True

    Returns
    -------
    dict
        _description_

    Yields
    ------
    Iterator[dict]
        _description_
    """
    paths = {}

    try:
        for name, data in named_data.items():
            fd, path = file_provider()
            os.write(fd, data.encode())
            paths[name] = path
        yield paths
    finally:
        if remove_files:
            for path in paths.values():
                file_remover(path)


def get_stamps(data: str) -> Generator[str, None, None]:
    """get all dns stamps from content

    Parameters
    ----------
    data : str
        _description_

    Returns
    -------
    _type_
        _description_

    Yields
    ------
    Generator[str, None, None]
        _description_
    """

    data = data or ""
    pattern = r"\bsdns://[^\s]+"
    return re.findall(pattern, data)


def parse_stamp(stamp: str) -> dict:
    """_summary_

    Parameters
    ----------
    stamp : str
        _description_

    Returns
    -------
    dict
        _description_
    """
    try:
        parsed = dnsstamps.parse(stamp)
    except Exception as e:
        return dict(address=None, port=None, stamp=stamp)

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

    return dict(address=address, port=port, stamp=stamp)


def subprocess_execute(args: list) -> int:
    """_summary_

    Parameters
    ----------
    args : list
        _description_

    Returns
    -------
    int
        _description_
    """
    return subprocess.call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def minisign_verify(
    source_filepath: str,
    minisig_filepath: str,
    minisign_key: str,
    command_executor: Callable[[List], int] = subprocess_execute,
) -> int:
    """_summary_

    Parameters
    ----------
    source_filepath : str
        _description_
    minisig_filepath : str
        _description_
    minisign_key : str
        _description_
    command_executor : Callable[[List], int], optional
        _description_, by default subprocess_execute

    Returns
    -------
    int
        _description_
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


def get_sdns_info(data: str) -> dict:
    for stamp in get_stamps(data):
        if info := parse_stamp(stamp):
            yield info


def requests_api(url: str) -> bytes:
    """_summary_

    Parameters
    ----------
    url : str
        _description_

    Returns
    -------
    bytes
        _description_

    Raises
    ------
    NoDataFromSource
        _description_
    NoDataFromSource
        _description_
    """
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
    disk=dict_to_disk,
    minisign=minisign_verify,
) -> bytes:
    """retrieve a minisigned url and minisig file and verify the data

    Parameters
    ----------
    url : str
        _description_
    minisign_key : str
        _description_
    minisig_url : _type_, optional
        _description_, by default None
    url_retriever : _type_, optional
        _description_, by default requests_api
    disk : _type_, optional
        _description_, by default dict_to_disk
    minisign : _type_, optional
        _description_, by default minisign_verify

    Returns
    -------
    bytes
        _description_

    Raises
    ------
    NoDataFromSource
        _description_
    """
    minisign_url = minisig_url or f"{url}.minisig"

    responses = {
        "source": url_retriever(url),
        "minisig": url_retriever(minisign_url),
    }

    with disk(responses) as file_path_for:
        # verify  minisigned data
        result = minisign(
            file_path_for["source"], file_path_for["minisig"], minisign_key
        )
        if result != 0:
            raise NoDataFromSource

    return responses["source"]


def get_sources_from_dnscrypt_config(toml_data: dict) -> Generator[Tuple, None, None]:
    """retrieves source blocks from dnscrypt-proxy.toml

    Parameters
    ----------
    toml_data : dict
        _description_

    Yields
    ------
    Generator[Tuple, None, None]
        _description_
    """
    sources = toml_data.get("sources", {})
    for source, properties in sources.items():
        if "urls" in properties and "minisign_key" in properties:
            for url in properties["urls"]:
                yield source, url, properties["minisign_key"]

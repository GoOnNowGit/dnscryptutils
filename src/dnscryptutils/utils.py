"""
helper functions to retrieve sources from
a dnscrypt-config.toml, extract dnsstamps and
parsing those stamps to return ip addresses
"""

import os
import re
import subprocess
from contextlib import contextmanager
from email.generator import Generator
from pathlib import Path
from tempfile import mkstemp
from typing import Callable, Generator, List, Tuple

import dnsstamps
import requests


class DnscryptUtilsError(Exception):
    pass


class NoDataFromSource(DnscryptUtilsError):
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
    parsed = None
    address = None
    port = None

    try:
        parsed = dnsstamps.parse(stamp)
    except Exception as e:
        return dict(address=address, port=port, stamp=stamp)
    # just return if there's no address
    if parsed.address == "":
        return dict(address=address, port=port, stamp=stamp)

    # ip6
    if re.search(r"]:\d{1,5}$", parsed.address):
        # remove port and remove []
        address, port = re.sub(r"[\[|\]]", "", parsed.address).rsplit(":", 1)
    elif re.search(r"]$", parsed.address):
        # no port, remove []
        address, port = re.sub(r"[\[|\]]", "", parsed.address), None
    # ip4
    elif re.search(r"[^\]]:\d{1,5}$", parsed.address):
        address, port = parsed.address.rsplit(":", 1)
    else:
        address = parsed.address

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


def minisign(
    source_data: str,
    minisig_data: str,
    minisign_key: str,
    command_executor: Callable[[List], int] = subprocess_execute,
    disk=dict_to_disk,
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
    data = {
        "source": source_data,
        "minisig": minisig_data,
    }

    with disk(data) as file_path_for:
        # verify minisigned data
        minisign = str(Path("/", "usr", "local", "bin", "minisign"))
        args = [
            minisign,
            "-V",
            "-m",
            file_path_for["source"],
            "-x",
            file_path_for["minisig"],
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
    url_retriever: Callable[[str], bytes] = requests_api,
    minisign: Callable[[str, str, str], int] = minisign,
) -> bytes:
    """_summary_

    Parameters
    ----------
    url : str
        _description_
    minisign_key : str
        _description_
    minisig_url : str, optional
        _description_, by default None
    url_retriever : Callable[[str], bytes], optional
        _description_, by default requests_api
    minisign : Callable[[str, str, str], int], optional
        _description_, by default minisign

    Returns
    -------
    bytes
        _description_

    Raises
    ------
    NoDataFromSource
        _description_
    """
    if not minisig_url:
        minisig_url = f"{url}.minisig"

    source = url_retriever(url)
    minisig = url_retriever(minisig_url)

    result = minisign(source, minisig, minisign_key)

    if result != 0:
        raise NoDataFromSource

    return source


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

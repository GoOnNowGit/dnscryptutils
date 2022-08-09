"""
Helper functions to retrieve minisigned sources from
a dnscrypt-config.toml, parse dnsstamps and return stamp info
"""

import os
import re
import subprocess
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkstemp
from typing import Callable, Dict, Generator, List, Tuple

import dnsstamps
import requests


class DnscryptUtilsError(Exception):
    """Base Exception for module"""

    # pylint: disable=unnecessary-pass
    pass


class NoDataFromSource(DnscryptUtilsError):
    # pylint: disable=unnecessary-pass
    pass


@contextmanager
def dict_to_disk(
    named_data: dict,
    file_provider: Callable = mkstemp,
    file_remover: Callable = os.unlink,
    remove_files: bool = True,
) -> Generator[Dict[str, str], None, None]:
    """For each key in named_data write the value (named_data[key])
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

    Yields
    ------
    Generator[Dict[str,str], None, None]
        _description_
    """
    paths = {}

    try:
        for name, data in named_data.items():
            file_descriptor, path = file_provider()
            os.write(file_descriptor, data.encode())
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
    """Calls dnsstamps.parse to parse a stamp and returns a dictionary containing
    a subset of the parsed fields

    Parameters
    ----------
    stamp : str
        The sdns

    Returns
    -------
    dict
        A subset of fields from the parsed dns stamp
    """
    parsed = None
    address = None
    port = None

    try:
        parsed = dnsstamps.parse(stamp)
    except Exception:
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
    """Uses subprocess to execute a command

    Parameters
    ----------
    args : list
        List of arguments

    Returns
    -------
    int
        Return code of subprocess.call
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
        minisign_path = str(Path("/", "usr", "local", "bin", "minisign"))
        args = [
            minisign_path,
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
    """Extracts sdns stamps from a string

    Parameters
    ----------
    data : String containing dnsstamps
        _description_

    Yields
    ------
    Iterator[dict]
        a subset of elements from a parsed dnsstamp
    """
    for stamp in get_stamps(data):
        if info := parse_stamp(stamp):
            yield info


def requests_api(url: str) -> bytes:
    """Wrapper around requests

    Parameters
    ----------
    url : str
        Url to retrieve

    Returns
    -------
    bytes
        The url content

    Raises
    ------
    NoDataFromSource
        when a HTTP 200 response code isn't returned

    """
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as exc:
        raise NoDataFromSource from exc

    if response.status_code != requests.codes["ok"]:
        raise NoDataFromSource

    return response.content.decode()


def get_minisigned_url(
    url: str,
    minisign_key: str,
    minisig_url=None,
    url_retriever: Callable[[str], bytes] = requests_api,
    minisign_func: Callable[[str, str, str], int] = minisign,
) -> bytes:
    """Gets content from a url and its minisign signature
    and verifies the integrity of the data via minisign

    Parameters
    ----------
    url : str
        Url to retrieve
    minisign_key : str
        _description_
    minisig_url : str, optional
        _description_, by default None
    url_retriever : Callable[[str], bytes], optional
        _description_, by default requests_api
    minisign_func : Callable[[str, str, str], int], optional
        _description_, by default minisign

    Returns
    -------
    bytes
        The contents of the url

    Raises
    ------
    NoDataFromSource
        when a HTTP 200 response code isn't returned
    """
    minisig_url = minisig_url or f"{url}.minisig"

    source = url_retriever(url)
    minisig = url_retriever(minisig_url)

    result = minisign_func(source, minisig, minisign_key)

    if result != 0:
        raise NoDataFromSource

    return source


def get_sources_from_dnscrypt_config(toml_data: dict) -> Generator[Tuple, None, None]:
    """Retrieves the source block from dnscrypt-proxy.toml

    Parameters
    ----------
    toml_data : dict
        Dnscrypt config

    Yields
    ------
    Generator[Tuple, None, None]
        source, url, minisign key
    """
    sources = toml_data.get("sources", {})
    for source, properties in sources.items():
        if "urls" in properties and "minisign_key" in properties:
            for url in properties["urls"]:
                yield source, url, properties["minisign_key"]

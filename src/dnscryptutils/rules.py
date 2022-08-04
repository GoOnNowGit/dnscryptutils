import argparse
from io import StringIO


class Raw:
    def __init__(self, args: argparse.Namespace):
        pass

    def __call__(self, info: dict) -> str:
        server = info.get("address")
        port = info.get("port")
        source = info.get("source")
        url = info.get("url")
        minisign_key = info.get("minisign_key")
        return f"{source} {url} {minisign_key} {server} {port}"


class PfRule:
    def __init__(self, args: argparse.Namespace):
        self.action = args.action
        self.quick = args.quick
        self.log = args.log
        self.interface = args.interface
        self.add_label = args.add_label
        self.source = args.source
        self.protocol = args.protocol

    def __call__(self, info: dict) -> str:
        server = info["address"]
        port = info.get("port", None)

        r = StringIO()
        r.write(f"{self.action} out")

        if self.log:
            r.write(" log")
        if self.quick:
            r.write(" quick")
        if self.interface:
            r.write(f" on {self.interface}")
        if self.protocol:
            r.write(f" proto {self.protocol}")
        if self.source:
            r.write(f" from {self.source}")
        if server:
            r.write(f" to {server}")
        if port:
            r.write(f" port {port}")
        if self.add_label and info.get("source"):
            r.write(f" label {info['source']}")

        return r.getvalue()

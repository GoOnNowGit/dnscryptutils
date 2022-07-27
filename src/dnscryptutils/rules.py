from io import StringIO


class Console:
    def __call__(self, info: dict) -> str:
        server = info.get("address")
        port = info.get("port")
        source = info.get("source")
        url = info.get("url")
        minisign_key = info.get("minisign_key")
        return f"{source} {url} {minisign_key} {server} {port}"


class PfRule:
    def __init__(
        self,
        action="pass",
        interface=None,
        quick=True,
        log=False,
        add_label=True,
    ):
        self.action = action
        self.quick = quick
        self.log = log
        self.interface = interface
        self.add_label = add_label

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

        r.write(" proto tcp to")

        if server:
            r.write(f" {server}")
        if port:
            r.write(f" port {port}")
        if self.add_label and info.get("source"):
            r.write(f" label {info['source']}")

        return r.getvalue()

from io import StringIO


class PfRule:
    def __init__(
        self,
        action="pass",
        interface=None,
        quick=True,
        log=False,
        label=None,
    ):
        self.action = action
        self.quick = quick
        self.log = log
        self.interface = interface
        self.label = label

    def make_rule(self, info: dict, *args, **kwargs):
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
        if self.label:
            r.write(f" label {self.label}")

        return r.getvalue()

import ipaddress
from typing import NamedTuple, NewType, Union


IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
L4Port = NewType("L4Port", int)
IfId = NewType("IfId", int)


class UnderlayAddress(NamedTuple):
    """Pair of an IP address and a port."""
    ip: IpAddress
    port: L4Port

    def __str__(self):
        return ":".join((str(self.ip), str(self.port)))

    def format_url(self):
        """Returns a string representation of the address suitable for use in URLs."""
        if isinstance(self.ip, ipaddress.IPv4Address):
            return "{}:{}".format(self.ip, self.port)
        elif isinstance(self.ip, ipaddress.IPv6Address):
            return "[{}]:{}".format(self.ip, self.port)
        else:
            assert(False)

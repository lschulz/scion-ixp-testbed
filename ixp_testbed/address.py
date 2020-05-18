import ipaddress
from typing import NamedTuple, NewType, Union

import lib.scion_addr


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


class ISD_AS(lib.scion_addr.ISD_AS):
    """Adds some removed methods back to ISD_AS."""
    AS_BITS = 48
    MAX_AS = (1 << AS_BITS) - 1

    def __init__(self, initializer=None):
        if initializer is None:
            self._isd = 0
            self._as = 0
        elif isinstance(initializer, ISD_AS):
            self._isd = initializer._isd
            self._as = initializer._as
        elif isinstance(initializer, int):
            self._isd = initializer >> self.AS_BITS
            self._as = initializer & self.MAX_AS
        else:
            super().__init__(initializer)

    def __getitem__(self, index):
        if index == 0:
            return self._isd
        elif index == 1:
            return self._as
        else:
            raise IndexError()

    def __int__(self):
        return self.int()

"""Base class for all network types and functions for connecting containers to all networks
underlying their links."""

from abc import ABC, abstractmethod
from collections import defaultdict
import logging
from typing import DefaultDict, Dict, Iterator, Optional, Tuple

from ixp_testbed import errors
from ixp_testbed.address import IfId, IpAddress, IpNetwork, ISD_AS, L4Port, UnderlayAddress
from ixp_testbed.constants import BR_DEFAULT_PORT
from ixp_testbed.scion import AS, Link

log = logging.getLogger(__name__)


class Bridge(ABC):
    """Abstract base class for bridges connecting Docker containers.

    Implements assignment of IP addresses and ports to border router interfaces.
    If the bridge is also used for connecting the coordinator to ASes IP addresses can be assigned
    with `assign_ip_address`.

    :ivar _name: Name of the network.
    :ivar _ip_network: The IP subnet addresses are allocated from.
    :ivar _as_map: Maps each AS connected to the bridge to exactly one IP address.
    :ivar _ip_map: Maps IP addresses assigned to at least one AS to a mapping from border router
                   interface to L4 port (`PortMap`). Multiple ASes can use the same IP address.
    """

    _COORD_ISD_AS = ISD_AS()
    """Pseudo AS ID identifying the coordinator."""

    _COORD_IFID = IfId(0)
    """Pseudo interface identifier for connections to the coordinator."""

    def __init__(self, name: str, ip_network: IpNetwork):
        self._name = name
        self._ip_network = ip_network

        PortMap = Dict[Tuple[ISD_AS, IfId], L4Port]
        self._as_map: Dict[ISD_AS, IpAddress] = {}
        self._ip_map: DefaultDict[IpAddress, PortMap] = defaultdict(dict)


    @property
    def name(self):
        return self._name

    @property
    def ip_network(self):
        return self._ip_network

    def str(self):
        return "{} [{}]".format(self._name, str(self._ip_network))

    def valid_ip_iter(self) -> Iterator[IpAddress]:
        """Returns an iterator over all valid host IP in the bridges IP subnet.

        This might exclude some address that ip_network.hosts() would produce.
        """
        return self._ip_network.hosts()

    @abstractmethod
    def is_docker_managed(self) -> bool:
        """Whether the network is managed by Docker, i.e., Docker automatically connects containers
        configured to use the bridge."""
        raise NotImplementedError()

    @abstractmethod
    def has_been_created(self) -> bool:
        """Check whether the bridge the objects represents has been created and should be available."""
        raise NotImplementedError()

    @abstractmethod
    def create(self) -> None:
        """Create the bridge."""
        raise NotImplementedError()

    @abstractmethod
    def remove(self) -> None:
        """Deletes the bridge. Containers should be disconnected first."""
        raise NotImplementedError()

    def get_published_ports(self, isd_as: ISD_AS, asys: AS) -> Dict[str, Tuple[str, str]]:
        """Get a dictionary of port mappings to be used when creating the AS container.

        The returned dictionary is of the correct type to be passed to the Docker Python SDK.

        Selectively exposing ports on the hosts network interfaces allows ASes on different hosts
        to communicate without an additional overlay network (like docker.OverlayNetwork using
        Dockers 'overlay' driver).
        Note that ports can only be published during container creation, not afterwards.

        :returns: Mapping from container ports to (host_ip, host_port). All values are returned as
                  strings. The container port is in the format "<port>/tcp" for TCP ports and
                  "<port>/udp" for UDP ports.
        """
        return {}

    def get_bind_ip(self, isd_as: ISD_AS, asys: AS) -> Optional[IpAddress]:
        """Returns the IP address services in the given AS should bind to or `None` if the bind
        address is identical to the public address.

        Call get_ip_address() to retrieve the public IP address of an AS.
        """
        return None

    def get_br_bind_address(self, isd_as: ISD_AS, asys: AS, ifid: IfId) -> Optional[UnderlayAddress]:
        """Returns the IP address and port the given border router interface should bind to or
        `None` if the bind address is identical to the public address.

        Call get_br_address() to retrieve the public address of the BR interface.
        """
        return None

    @abstractmethod
    def connect(self, isd_as: ISD_AS, asys: AS) -> None:
        """Connect the given AS to the network."""
        raise NotImplementedError()

    @abstractmethod
    def disconnect(self, isd_as: ISD_AS, asys: AS) -> None:
        """Disconnect the given AS from the network."""
        raise NotImplementedError()

    def connect_coordinator(self, coord):
        """Connect the coordinator to the network.

        At the moment only Docker bridges and overlay networks can be used as coordinator network.
        """
        raise NotImplementedError()

    def get_ip_address(self, isd_as) -> Optional[IpAddress]:
        """Get the IP address assigned to an AS.

        :param isd_as: AS identifier or Coordinator instance to get the IP address of the
                       coordinator if it is reachable on this network.
        :returns: The assigned IP address or `None`, if no address is assigned.
        """
        if isinstance(isd_as, ISD_AS):
            return self._as_map.get(isd_as, None)
        else:
            return self._as_map.get(self._COORD_ISD_AS, None)


    def get_br_address(self, isd_as: ISD_AS, ifid: IfId) -> Optional[UnderlayAddress]:
        """Get the underlay address assigned to a BR interface.

        :param isd_as: AS identifer.
        :param ifid: Interface within the AS.
        :returns: The assigned underlay address or `None`, if no address is assigned to the given
                  interface.
        """
        ip = self._as_map.get(isd_as, None)
        if ip is None:
            return None

        port_map = self._ip_map[ip]
        port = port_map[(isd_as, ifid)]
        if port is None:
            return None

        return UnderlayAddress(ip, port)


    def assign_ip_address(self, to, pref_ip: Optional[IpAddress]=None) -> IpAddress:
        """Assign an IP address to the given AS that will remain assigned until freed with
        `free_ip_address`.

        Use this function to reserve an address for an AS even if it has no links using this
        network. If an address has been assigned to the AS by this method the previously assigned
        address is returned. Note that a single call to `free_ip_address` is enough to undo all
        calls to `assign_ip_address` for that AS.

        By default, the lowest availabile IP is selected. If a specific IP is desired, it can be
        specified as `pref_ip`. If the preferred IP is not availabile, a `NotAvailabile` exception
        is raised.

        :param to: Pair of `ISD_AS` and `AS` or `Coordinator`.
        :param pref_ip: Optional IP to assign if possible.
        :returns: The assigned IP address.
        :raises NotAvailabile: `pref_ip` is not availabile.
        :raises OutOfResources: All IP addresses availabile in the bridge's subnet where assigned
                                already.
        """
        isd_as = to[0] if isinstance(to, tuple) else self._COORD_ISD_AS

        try:
            ip = self._as_map[isd_as]

        except KeyError:
            ip = self._select_ip(pref_ip)
            self._as_map[isd_as] = ip

            port_map = self._ip_map[ip]
            port_map[(self._COORD_ISD_AS, self._COORD_IFID)] = L4Port(0)

            return ip

        else:
            port_map = self._ip_map[ip]
            port_map[(self._COORD_ISD_AS, self._COORD_IFID)] = L4Port(0)

            return ip


    def free_ip_address(self, isd_as: ISD_AS) -> int:
        """Delete an assignment made with `assign_address`.

        The AS will keep its IP address until all BR interfaces registered with `assign_br_address`
        have been unregistered with `free_br_address`.

        :returns The number of BR interfaces using the same IP still assigned.
        """
        ip = self._as_map[isd_as]
        port_map = self._ip_map[ip]
        del port_map[(self._COORD_ISD_AS, self._COORD_IFID)]

        port_map_len = len(port_map)
        if port_map_len == 0:
            del self._as_map[isd_as]
            del self._ip_map[ip]

        return port_map_len


    def assign_br_address(self, isd_as: ISD_AS, asys: AS, ifid: IfId,
        pref_ip: Optional[IpAddress]=None, pref_port: Optional[L4Port]=None) -> UnderlayAddress:
        """Assign an underlay address the the given BR interface.

        If the given BR interface already has an address this address is returned and no new
        assignment is made.

        Different BR interfaces in the same AS get the same IP address and different ports.
        By default, the lowest availabile IP and port are assigned. The optional parameters
        `pref_ip` and `pref_port` allow to specify a preferred IP address and port. If one of
        `pref_ip` or `pref_port` is not availbile, a `NotAvailabile` exception is raised and no
        address is assigned.

        :param isd_as: AS to which an address should be assigned.
        :param asys: AS to which an address should be assigned.
        :param ifid: Identifier of the border router interface.
        :param pref_ip: Optional IP to assign if possible.
        :param pref_port: Optional port to assing if possible.
        :returns: The assigned address.
        :raises NotAvailabile: `pref_ip` or `pref_port` is not availabile.
        :raises OutOfResources: No more IP addresses or ports are availabile.
        """
        assert not isd_as.is_zero()
        try:
            ip = self._as_map[isd_as]

        except KeyError:
            # AS has no IP address, pick one.
            ip = self._select_ip(pref_ip)

            # Select a free port.
            port_map = self._ip_map.get(ip, {})
            port = self._select_port(pref_port, port_map)

            # Update the mapping after IP and port have been found to ensure consistency
            # if _select_ip or _select_port fail.
            port_map[(isd_as, ifid)] = port
            self._as_map[isd_as] = ip
            self._ip_map[ip] = port_map

            return UnderlayAddress(ip, port)

        else:
            # AS already has an IP address, just pick a free port.
            port_map = self._ip_map[ip]
            port = port_map.get((isd_as, ifid))

            if port is None:
                port = port_map[(isd_as, ifid)] = self._select_port(pref_port, port_map)

            return UnderlayAddress(ip, port)


    def free_br_address(self, isd_as: ISD_AS, ifid: IfId) -> int:
        """Returns an (IP, Port)-pair assigned by `assign_br_address` to the pool of available
        addresses.

        :param isd_as: AS the address was assigned to.
        :param ifid: ID of the interface the address was assigned to.
        :returns: The number of addresses using the same IP still assigned. This can be other BR
                  interfaces and additionally an assignment made by `assign_address`.
        """
        assert not isd_as.is_zero()

        ip = self._as_map[isd_as]
        port_map = self._ip_map[ip]
        del port_map[(isd_as, ifid)]

        port_map_len = len(port_map)
        if port_map_len== 0:
            del self._as_map[isd_as]
            del self._ip_map[ip]

        return port_map_len


    def _select_ip(self, pref_ip: Optional[IpAddress]) -> IpAddress:
        if pref_ip is not None:
            if pref_ip in self._ip_network:
                return pref_ip
            else:
                raise errors.NotAvailable()

        # Select the lowest available IP not assigned yet.
        assigned = self._ip_map.keys()
        hosts = self.valid_ip_iter()
        for ip in hosts:
            if ip not in assigned:
                return ip
        log.error("Not enough IP addresses in subnet '%s'.", self.ip_network)
        raise errors.OutOfResources()


    def _select_port(self, pref_port: Optional[L4Port], port_map) -> L4Port:
        if pref_port is not None:
            if pref_port not in port_map.values():
                return pref_port
            else:
                raise errors.NotAvailable()

        # Select the first port not assigned yet, starting at BR_DEFAULT_PORT.
        for port in range(BR_DEFAULT_PORT, BR_DEFAULT_PORT + 1000):
            if port not in port_map.values():
                return L4Port(port)
        raise errors.OutOfResources()


def get_published_ports(isd_as: ISD_AS, asys: AS) -> Dict[str, Tuple[str, str]]:
    """Gets all AS container ports that need to be published on host interfaces."""
    ports = {}
    for _, link in asys.links():
        ports.update(link.bridge.get_published_ports(isd_as, asys))
    return ports


def connect_bridges(isd_as: ISD_AS, asys: AS, non_docker_only: bool = False) -> None:
    """Connect the given AS to all bridges required by its links.

    :param non_docker_only: Only connect bridges not managed by Docker itself. This is useful if
    a container is restarted, because Docker managed bridges will have reconnected automatically.
    """
    connected = set()
    for _, link in asys.links():
        # multiple links can use the same network, only connect once
        if link.bridge not in connected:
            if not (non_docker_only and link.bridge.is_docker_managed()):
                link.bridge.connect(isd_as, asys)
                connected.add(link.bridge)


def disconnect_bridges(isd_as: ISD_AS, asys: AS, non_docker_only: bool = False) -> None:
    """Disconnect the given AS from all bridges required by its links.

    :param non_docker_only: Only disconnect bridges not managed by Docker itself.
    """
    disconnected = set()
    for _, link in asys.links():
        # multiple links can use the same network, only disconnect once
        if link.bridge not in disconnected:
            if not (non_docker_only and link.bridge.is_docker_managed()):
                link.bridge.disconnect(isd_as, asys)
                disconnected.add(link.bridge)


def connect_bridge(link: Link, isd_as: ISD_AS, asys: AS) -> None:
    """Connect the bridge `link` is established over to the container hosting the given AS.

    Both the bridge and the container should exist.
    """
    link.bridge.connect(isd_as, asys)


def disconnect_bridge(link: Link, isd_as: ISD_AS, asys: AS) -> None:
    """Disconnect the bridge `link` is established over from the container hosting the given AS.

    Both the bridge and the container should exist. No exception is raised even if the attempt to
    disconnect fails.
    """
    link.bridge.disconnect(isd_as, asys)

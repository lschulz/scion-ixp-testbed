import logging
from typing import Dict, Optional, Tuple, Union

from ixp_testbed import errors
from ixp_testbed import constants as const
from ixp_testbed.address import IfId, IpAddress, IpNetwork, ISD_AS, L4Port, UnderlayAddress
from ixp_testbed.coordinator import Coordinator
from ixp_testbed.host import Host
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.scion import AS
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)


class HostNetwork(Bridge):
    """Represents a network the Docker host itself is connected to.

    This network type allows containers on different hosts to communicate directly over the hosts's
    network. This is achieved by assigning the host's IP address to border router interfaces and
    publishing the BR's ports with Docker. For simplicity the port numbers within the
    containers and on the host interface are identical, e.g., port 50000 in the container is
    published to port 50000 on the host.

    The identity the ports are published on a host is set by set_host_ip(). There should be no more
    than a single HostNetwork per host IP address, since otherwise port allocations would collide.

    The ports that must be published during container creation can be retrieved with
    get_published_ports().

    The methods get_bind_ip() and get_br_bind_address() return the internal IP address of an AS's
    container from which ports are forwarded to the host.

    The Docker port publishing mechanism forwards ports from the network the container was
    connected to during its creation. This script creates containers without giving an explicit
    network and connects the necessary networks afterwards. Thus the containers are connected to
    the default docker bridge with an IP dertermined by Docker.
    get_bind_ip() and get_br_bind_address() retrieve the IP from the default bridge, so that SCION
    services can bind to the correct interface for them to be published on the host.

    :ivar _host_mapping: Contains the IP addresses of the hosts participating in the network.
    :ivar _initialized: Keep track of whether the bridge has been "created".
    :ivar _default_bridge_ip_cache: Cache of the container IPs in the default bridge network.
    """
    def __init__(self, name: str, ip_network: IpNetwork):
        super().__init__(name, ip_network)
        self._host_mapping: Dict[Host, IpAddress] = {}
        self._initialized = False
        self._default_bridge_ip_cache: Dict[ISD_AS, IpAddress] = {}

    def __getstate__(self):
        state = self.__dict__.copy()
        # Don't save the IP cache.
        state['_default_bridge_ip_cache'] = {}
        return state

    def is_docker_managed(self) -> bool:
        return False

    def has_been_created(self) -> bool:
        return True

    def set_host_ip(self, host: Host, ip: IpAddress) -> None:
        """Sets the IP address of a host running containers connected to this network.

        Host IP addresses must be set before containers running on the host can connect to the
        network.
        """
        self._host_mapping[host] = ip


    # Override assign_ip_address() to always assign the IP address of the AS's host.
    def assign_ip_address(self,
        to: Union[Coordinator, Tuple[ISD_AS, AS]], pref_ip: Optional[IpAddress]=None) -> IpAddress:

        host = to.host if isinstance(to, Coordinator) else to[1].host

        try:
            ip = self._host_mapping[host]

        except KeyError:
            log.error("No IP address for %s in network %s", host.name, self._name)
            raise

        else:
            if pref_ip is not None and pref_ip != ip:
                raise errors.NotAvailable()

            return super().assign_ip_address(to, ip)


    # Override assign_br_address() to always assign the IP address of the AS's host.
    def assign_br_address(self, isd_as: ISD_AS, asys: AS, ifid: IfId,
        pref_ip: Optional[IpAddress]=None, pref_port: Optional[L4Port]=None) -> UnderlayAddress:
        try:
            ip = self._host_mapping[asys.host]

        except KeyError:
            log.error("No IP address for %s in network %s", asys.host.name, self._name)
            raise

        else:
            if pref_ip is not None and pref_ip != ip:
                raise errors.NotAvailable()

            return super().assign_br_address(isd_as, asys, ifid, ip, pref_port)


    def create(self) -> None:
        if not self._initialized:
            # nothing to do, just create a log entry
            log.info("Initialized host network %s for '%s'.", self.name, self.ip_network)
            self._initialized = True


    def remove(self) -> None:
        # nothing to do
        self._initialized = False


    def get_published_ports(self, isd_as: ISD_AS, asys: AS) -> Dict[str, Tuple[str, str]]:
        exposed_ports = {}

        host_ip = self._as_map[isd_as]
        port_map = self._ip_map[host_ip]

        for ifid, _ in asys.links():
            port = port_map.get((isd_as, ifid))
            if port is not None:
                exposed_ports["%d/tcp" % port] = (str(host_ip), str(port))
                exposed_ports["%d/udp" % port] = (str(host_ip), str(port))

        return exposed_ports


    def get_bind_ip(self, isd_as: ISD_AS, asys: AS) -> Optional[IpAddress]:
        try:
            return self._default_bridge_ip_cache[isd_as]
        except KeyError:
            ip = asys.get_cntr_ip(const.DEFAULT_BRIDGE_NAME)
            self._default_bridge_ip_cache[isd_as] = ip
            return ip


    def get_br_bind_address(self, isd_as: ISD_AS, asys: AS, ifid: IfId) -> Optional[UnderlayAddress]:
        bind_ip = unwrap(self.get_bind_ip(isd_as, asys))

        # Use the same port number within the container as exposed on the host interface.
        host_ip = self._as_map[isd_as]
        port_map = self._ip_map[host_ip]
        bind_port = port_map[(isd_as, ifid)]

        return UnderlayAddress(bind_ip, bind_port)


    def connect(self, isd_as: ISD_AS, asys: AS) -> None:
        pass # nothing to do


    def disconnect(self, isd_as: ISD_AS, asys: AS) -> None:
        pass # nothing to do

"""Classes representing Docker networks using the bridge and overlay drivers."""

import ipaddress
import logging
from typing import Iterator, Mapping, Optional

import docker

from ixp_testbed import constants
from ixp_testbed import errors
from ixp_testbed.address import IpAddress, IpNetwork, ISD_AS
from ixp_testbed.coordinator import Coordinator
from ixp_testbed.host import Host
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.scion import AS
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)


class DockerNetwork(Bridge):
    """Abstract base class for Docker bridges and overlay networks.

    :ivar _host: Docker host the bridge is created on. In case of overlay networks that can span
                 multiple hosts, this must be a swarm manager node.
    :ivar _docker_id: Docker network ID.
    """
    def __init__(self, name: str, host: Host, ip_network: IpNetwork):
        super().__init__(name, ip_network)
        self._host = host
        self._docker_id: Optional[int] = None

    @property
    def docker_id(self):
        return self._docker_id

    def is_docker_managed(self) -> bool:
        return True

    def has_been_created(self) -> bool:
        return self._docker_id is not None

    def _create(self, driver: str, driver_options: Mapping[str, str]={}) -> None:
        """Create a Docker network.

        :param driver: Network driver. One of 'bridge' or 'overlay'.
        :param driver_options: Additional options passed to the network driver.
        """
        assert(self.ip_network)
        dc = self._host.docker_client

        # Check if bridge already exists
        if self._docker_id is not None:
            try:
                dc.networks.get(self._docker_id)
                return
            except docker.errors.NotFound:
                self._docker_id = None
                log.warning("Docker network %s [%s] (%s) not found.", self.name, self._host.name, self._docker_id)

        # Create bridge
        ipam_pool = docker.types.IPAMPool(
            subnet=str(self.ip_network)
        )
        ipam_config = docker.types.IPAMConfig(
            pool_configs=[ipam_pool]
        )

        additional_args = {}
        if driver == 'overlay':
            # Allows standalone containers to connect to overlay networks.
            additional_args['attachable'] = True

        try:
            network = dc.networks.create(self.name, driver=driver, ipam=ipam_config,
                options=driver_options,
                enable_ipv6=(self.ip_network.version == 6),
                **additional_args)

            self._docker_id = network.id
            log.info("Created Docker %s network %s [%s] (%s) for '%s'.",
                driver, self.name, self._host.name, self._docker_id, self.ip_network)

        except docker.errors.APIError as e:
            log.error("Error creating network %s: %s", self.name, str(e))
            raise


    def remove(self) -> None:
        if self._docker_id:
            dc = self._host.docker_client
            try:
                dc.networks.get(self._docker_id).remove()
                log.info("Removed Docker network %s [%s] (%s).", self.name, self._host.name, self._docker_id)
            except docker.errors.NotFound:
                log.warning("Docker network %s [%s] (%s) not found.", self.name, self._host.name, self._docker_id)
            self._docker_id = None


    def connect(self, isd_as: ISD_AS, asys: AS) -> None:
        ip = unwrap(self.get_ip_address(isd_as))
        self._connect(asys.get_container(), ip, asys.host)


    def disconnect(self, isd_as: ISD_AS, asys: AS) -> None:
        dc = asys.host.docker_client
        try:
            dc.networks.get(self._docker_id).disconnect(asys.container_id)
            log.info("Disconnected %s from %s.", isd_as, self.name)
        except docker.errors.NotFound:
            log.warning("Docker network %s [%s] (%s) not found.", self.name, self._host.name, self._docker_id)
        except docker.errors.APIError:
            log.warning("Disconnecting %s from Docker network %s failed.", isd_as, self.name)


    def connect_container(self, cntr, ip: IpAddress, host: Host) -> None:
        self._connect(cntr, ip, host)


    def _connect(self, cntr, ip: IpAddress, host: Host) -> None:
        """Connect a container to this network.

        :param cntr: The container to connect to this network.
        :param ip: IP address to assign to the container.
        :param host: The host `cntr` runs on.
        """
        dc = self._host.docker_client
        try:
            if isinstance(ip, ipaddress.IPv4Address):
                dc.networks.get(self._docker_id).connect(cntr, ipv4_address=str(ip))
            elif isinstance(ip, ipaddress.IPv6Address):
                dc.networks.get(self._docker_id).connect(cntr, ipv6_address=str(ip))
            log.info("Connected %s (%s) to %s.", cntr.name, ip, self.name)
        except docker.errors.NotFound:
            log.warning("Docker network %s [%s] (%s) not found.", self.name, self._host.name, self._docker_id)
            raise
        except docker.errors.APIError:
            log.error("Connecting %s (%s) to Docker network %s failed.", cntr.name, ip, self.name)
            raise


class DockerBridge(DockerNetwork):
    """Represents a Docker network using the "bridge" driver.
    """
    def __init__(self, name: str, host: Host, ip_network: IpNetwork):
        super().__init__(name, host, ip_network)

    def valid_ip_iter(self) -> Iterator[IpAddress]:
        hosts = self._ip_network.hosts()
        next(hosts) # first IP is reserved for the host
        return hosts

    def create(self) -> None:
        super()._create('bridge')


class OverlayNetwork(DockerNetwork):
    """Represents a Docker overlay network.

    Overlay networks can span multiple hosts.

    :param host: Must be a Docker swarm manager.
    :param ip_network: Should not contain at least 16 and no more more than 256 addresses.
                       Note: To have more than 256 addresses in an overlay network Docker allows
                       multiple subnets in the same overlay network (not implemented here).
    :param encrypted: Whether application data transmitted over the network is encrypted.
    """
    def __init__(self, name: str, host: Host, ip_network: IpNetwork, *, encrypted: bool=False):
        super().__init__(name, host, ip_network)
        self.encrypted = encrypted

    def valid_ip_iter(self) -> Iterator[IpAddress]:
        hosts = self._ip_network.hosts()
        # One IP address must be reserved for each Docker host sharing the network.
        for _ in range(constants.OVERLAY_NETWORK_MAX_HOSTS):
            next(hosts)
        return hosts

    def create(self) -> None:
        driver_options = {}
        if self.encrypted:
            driver_options['encrypted'] = 'true'
        super()._create('overlay', driver_options)

    # The Docker SDK for Python cannot connect standalone containers to overlay networks created
    # on a different host. Therefore, we use the command line interface here.
    def _connect(self, cntr, ip: IpAddress, host: Host) -> None:
        try:
            if isinstance(ip, ipaddress.IPv4Address):
                cmd = ["docker", "network", "connect", self._docker_id, cntr.id, "--ip", str(ip)]
                host.run_cmd(cmd, check=True, capture_output=True)
            elif isinstance(ip, ipaddress.IPv6Address):
                cmd = ["docker", "network", "connect", self._docker_id, cntr.id, "--ip6", str(ip)]
                host.run_cmd(cmd, check=True, capture_output=True)
            log.info("Connected %s (%s) to %s.", cntr.name, ip, self.name)
        except errors.ProcessError as e:
            log.error("Connecting %s (%s) to Docker network %s failed: %s",
                cntr.name, ip, self.name, e.output)
            raise

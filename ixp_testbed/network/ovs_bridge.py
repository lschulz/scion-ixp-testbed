import ipaddress
import logging
from typing import Iterator, Union

from lib.packet.scion_addr import ISD_AS

from ixp_testbed import errors
from ixp_testbed.address import IpAddress, IpNetwork
from ixp_testbed.host import Host
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.scion import AS
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)


class OvsBridge(Bridge):
    """Represents an Open vSwitch bridge.

    Can only connect containers running on the same host.

    :ivar _host: Docker host the bridge exists on.
    """
    def __init__(self, name: str, host: Host, ip_network: IpNetwork):
        """
        :param name: Must not be longer than 15 characters.
        :raises InvalidName: `name` is invalid.
        """
        if len(name) > 15:
            raise errors.InvalidName("Maximum OVS bridge name length is 15 characters.")

        super().__init__(name, ip_network)
        self._host = host
        self._created: bool = False

    def valid_ip_iter(self) -> Iterator[IpAddress]:
        hosts = self._ip_network.hosts()
        next(hosts) # keep the first IP for the host
        return hosts

    def is_docker_managed(self) -> bool:
        return False

    def has_been_created(self) -> bool:
        return self._created

    def create(self) -> None:
        try:
            # Check if bridge exists
            if self.has_been_created():
                result = self._host.run_cmd(["sudo", "ovs-vsctl", "list-br"],
                    check=True, capture_output=True)
                if self.name in result.output.split('\n'):
                    return # bridge exists already
                else:
                    self._created = False
                    log.warning("OVS bridge %s [%s] not found.", self.name, self._host.name)

            # Create new bridge
            self._host.run_cmd(["sudo", "ovs-vsctl", "add-br", self.name],
                check=True, capture_output=True)
            self._created = True
            self._host.run_cmd(
                ["sudo", "ovs-vsctl", "set", "bridge", self.name, "protocols=OpenFlow12"],
                check=True, capture_output=True)
            log.info("Created OVS bridge %s [%s] for '%s'.", self.name, self._host.name, self.ip_network)

        except errors.ProcessError as e:
            log.error("Error creating OVS bridge %s: %s", self.name, e.output)
            raise


    def remove(self) -> None:
        try:
            # Check if bridge exists
            if self._created:
                result = self._host.run_cmd(["sudo", "ovs-vsctl", "list-br"],
                    check=True, capture_output=True)
                if self.name not in result.output.split('\n'):
                    log.warning("OVS bridge %s [%s] not found.", self.name, self._host.name)
                    return # bridge does not exist

            # Remove bridge
            self._host.run_cmd(["sudo", "ovs-vsctl", "del-br", self.name],
                check=True, capture_output=True)
            self._created = False
            log.info("Removed OVS bridge %s [%s].", self.name, self._host.name)
        except errors.ProcessError as e:
            log.warning("Error deleting OVS bridge %s [%s]: %s", self.name, self._host.name, e.output)


    def connect(self, isd_as: ISD_AS, asys: AS) -> None:
        ip = unwrap(self.get_ip_address(isd_as))
        interface_address = _make_interface_address(ip, self.ip_network.prefixlen).with_prefixlen
        command = [
            # interface name in the container = bridge name
            "sudo", "ovs-docker", "add-port", self.name, self.name, asys.container_id,
            "--ipaddress={}".format(interface_address)
        ]
        try:
            result = asys.host.run_cmd(command, check=True, capture_output=True)
            log.info("Connected %s (%s) to %s.", isd_as, interface_address, self.name)
            if len(unwrap(result.output)) > 0:
                log.info("ovs-docker returned:\n%s", result.output)
        except errors.ProcessError as e:
            log.error("Connecting %s (%s) to OVS bridge %s failed: %s",
                isd_as, interface_address, self.name, e.output)
            raise


    def disconnect(self, isd_as: ISD_AS, asys: AS) -> None:
        try:
            command = [
                "sudo", "ovs-docker", "del-port", self.name, self.name, asys.container_id,
            ]
            result = asys.host.run_cmd(command, check=True, capture_output=True)
            log.info("Disconnected %s from %s.", isd_as, self.name)
            if len(unwrap(result.output)) > 0:
                log.info("ovs-docker returned:\n{}".format(result.output))
        except errors.ProcessError as e:
            log.error("Disconnecting %s from OVS bridge %s failed: %s", isd_as, self.name, e.output)


IpInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
def _make_interface_address(address: IpAddress, prefix_len: int) -> IpInterface:
    """Create an `IPv4Interface` or `IPv6Interface` with the given prefix length from an IP address.
    """
    if isinstance(address, ipaddress.IPv4Address):
        return ipaddress.IPv4Interface((address, prefix_len))
    elif isinstance(address, ipaddress.IPv6Address):
        return ipaddress.IPv6Interface((address, prefix_len))
    else:
        assert(False)

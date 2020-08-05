"""This module provides allocation of underlay addresses to ASes and SCION border router interfaces.
"""

import logging
from typing import Any, Dict, cast

from ixp_testbed import errors
from ixp_testbed.address import IpNetwork
from ixp_testbed.constants import LINK_SUBNET_HOST_LEN
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.network.docker import DockerBridge
from ixp_testbed.network.host import HostNetwork
from ixp_testbed.topology import Topology
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)


def check_subnet_overlap(topo: Topology) -> Topology:
    """Make sure the default link subnet does not overlap any of the explicitly specified link networks.

    :param topo: Topology to check.
    :returns: The `topo` argument.
    :raises SubnetOverlap: Subnets overlap.
    """
    if topo.default_link_subnet:
        for bridge in topo.bridges:
            if cast(Any, bridge.ip_network).overlaps(topo.default_link_subnet):
                log.error("Subnet %s overlaps the default link subnet.", bridge)
                raise errors.SubnetOverlap()
    return topo


def assign_coord_ip_addresses(topo: Topology) -> None:
    """Assigns IP addresses for communication between coordinator, other control services and ASes.

    :param topo: Topology with a coordinator. No IP addresses must be assigned yet in the
                 coordinator's network.
    """
    bridge = topo.coordinator.bridge
    host_gen = bridge.valid_ip_iter()
    topo.coordinator.reserve_ip_addresses(host_gen)
    for service in topo.additional_services:
        service.reserve_ip_addresses(host_gen)
    for isd_as in topo.ases.keys():
        bridge.assign_ip_address(isd_as, pref_ip=next(host_gen))


def assign_underlay_addresses(topo: Topology) -> None:
    """Assign underlay addresses to the border router interfaces in the given topology.

    :raises OutOfResources: Not enough underlay addresses availabile.
    """
    link_subnets = None

    if topo.default_link_subnet:
        def_subnet = topo.default_link_subnet
        prefixlen_diff = def_subnet.max_prefixlen - def_subnet.prefixlen - LINK_SUBNET_HOST_LEN
        if prefixlen_diff >= 0:
            link_subnets = topo.default_link_subnet.subnets(prefixlen_diff)

    # Wrapper around IP network host iterator.
    class HostAddrGenerator:
        def __init__(self, bridge: Bridge):
            self._iter = bridge.valid_ip_iter()
            self.current = next(self._iter)

        def next(self):
            self.current = next(self._iter)

    # Mapping from IP subnet to generator producing addresses from said subnet.
    addr_gens: Dict[IpNetwork, HostAddrGenerator] = {}

    for link in topo.links:
        if link.bridge is None: # assign a subnet of the default link network
            # DockerBridge cannot span multiple hosts.
            assert topo.ases[link.ep_a].host == topo.ases[link.ep_b].host

            if not link_subnets:
                log.error("No default link network specified.")
                raise errors.OutOfResources()
            try:
                ip_net = next(link_subnets)
                link.bridge = DockerBridge(
                    topo.gen_bridge_name(), topo.ases[link.ep_a].host, ip_net)
                topo.bridges.append(link.bridge)
            except StopIteration:
                log.error("Not enough IP addresses for all links.")
                raise errors.OutOfResources()

        # Assign IP addresses to link endpoints
        addr_gen = _lazy_setdefault(addr_gens, link.bridge.ip_network,
            lambda: HostAddrGenerator(unwrap(link.bridge)))

        try:
            if not link.ep_a.is_zero():
                link.ep_a_underlay = link.bridge.assign_br_address(
                    link.ep_a, topo.ases[link.ep_a], link.ep_a.ifid,
                    pref_ip=None if isinstance(link.bridge, HostNetwork) else addr_gen.current)
                if link.ep_a_underlay.ip == addr_gen.current:
                    addr_gen.next()

            if not link.ep_b.is_zero():
                link.ep_b_underlay = link.bridge.assign_br_address(
                    link.ep_b, topo.ases[link.ep_b], link.ep_b.ifid,
                    pref_ip=None if isinstance(link.bridge, HostNetwork) else addr_gen.current)
                if link.ep_b_underlay.ip == addr_gen.current:
                    addr_gen.next()

        except (errors.OutOfResources, StopIteration):
            log.error("Not enough IP addresses in subnet '%s'.", link.bridge.ip_network)
            raise errors.OutOfResources()


def _lazy_setdefault(dict, key, default):
    """Equivalent to `dict.setdefault(key, default())`, but `default` is only called
    if a default value is needed.
    """
    try:
        return dict[key]
    except KeyError:
        value = default()
        dict[key] = value
        return value

"""List, add, remove and modify SCION links."""

import logging
from pathlib import Path
import sys
from typing import Any, Callable, Mapping, NamedTuple, Tuple

import docker
from lib.packet.scion_addr import ISD_AS

from ixp_testbed import errors
from ixp_testbed.address import IfId
from ixp_testbed.gen.gen_dir import (
    add_br_interface, modify_as_topo_file, modify_br_interface_properties, remove_br_interface)
from ixp_testbed.network.bridge import connect_bridge, disconnect_bridge
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.scion import AS, BorderRouter, Link, LinkEp
from ixp_testbed.topology import Ixp, Topology
from ixp_testbed.util.defer import RollbackManager

log = logging.getLogger(__name__)


class _EndPoint(NamedTuple):
    isd_as: ISD_AS
    asys: AS
    br: BorderRouter
    ifid: IfId


def print_links(topo: Topology, out=sys.stdout) -> None:
    """Print a list of all links.

    :param topo: Topology
    :param out: Text stream the output is written to.
    """
    links = sorted(topo.links, key=lambda link: (int(link.ep_a), int(link.ep_b)))
    for link in links:
        print(link, file=out)


def add_link(topo: Topology, ixp: Ixp, a: Tuple[ISD_AS, AS], b: Tuple[ISD_AS, AS],
    link_properties: Mapping[str, Any], workdir: Path, dc: docker.DockerClient) -> bool:
    """Add a new link to the topology. New links can be added while the network is running.

    Links added by this function use an IXP network for physical connectivity. The current
    implementation allows only a single link between the same two ASes per IXP.

    :param topo: Topology
    :param ixp: The IXP to use for the new link. The ASes are connected to the IXP if they do not
                yet have a connection.
    :param a: First AS to connect. Has to be an AS running on localhost.
    :param b: Second AS to connect. Has to be an AS running on localhost.
    :param link_properties: Properties of the new link. Valid properties are:
                            'type', 'bandwidth', 'mtu'
    :param workdir: Topology working directory.
    :param dc: Docker client object connected to the Docker daemon.
    :returns: True, if the link was added. False, if a link between the specified ASes over `ixp`
              exists already.
    :raises InvalidTopo: Link has invalid (e.g., identical) endpoints.
    """
    isd_as_a, as_a = a
    isd_as_b, as_b = b

    # Check for identical endpoints.
    if isd_as_a == isd_as_b:
        raise errors.InvalidTopo("Link endpoints are identical.")

    # Check whether the link exists already on the IXP.
    for _, link in as_a.links():
        if link.is_endpoint(isd_as_b) and link.bridge == ixp.bridge:
            log.error("Link from {} to {} exists already.".format(isd_as_a, isd_as_b))
            return False

    br_a, connect_a = _select_br_new_link(as_a, ixp.bridge)
    br_b, connect_b = _select_br_new_link(as_b, ixp.bridge)

    ifid_a = as_a.get_unused_ifid()
    ifid_b = as_b.get_unused_ifid()

    log.info("Adding link from {}#{} to {}#{}.".format(
        br_a.get_name(isd_as_a), ifid_a, br_b.get_name(isd_as_b), ifid_b))

    with RollbackManager() as cleanup:
        # assign underlay addresses
        link = Link(
            LinkEp.Construct(isd_as_a, ifid=ifid_a),
            LinkEp.Construct(isd_as_b, ifid=ifid_b),
            link_properties['type'])
        link.bridge = ixp.bridge
        link.ep_a_underlay = ixp.bridge.assign_br_address(isd_as_a, as_a, ifid_a)
        cleanup.defer(lambda: ixp.bridge.free_br_address(isd_as_a, ifid_a))
        link.ep_b_underlay = ixp.bridge.assign_br_address(isd_as_b, as_b, ifid_b)
        cleanup.defer(lambda: ixp.bridge.free_br_address(isd_as_b, ifid_b))

        # connect to network bridge, if containers exist
        if connect_a and as_a.container_id:
            connect_bridge(link, isd_as_a, as_a)
            cleanup.defer(lambda: disconnect_bridge(link, isd_as_a, as_a))
            ixp.ases[isd_as_a] = as_a
            cleanup.defer(lambda: ixp.ases.pop(isd_as_a))
        if connect_b and as_b.container_id:
            connect_bridge(link, isd_as_b, as_b)
            cleanup.defer(lambda: disconnect_bridge(link, isd_as_b, as_b))
            ixp.ases[isd_as_b] = as_b
            cleanup.defer(lambda: ixp.ases.pop(isd_as_b))

        # add link
        topo.links.append(link)
        cleanup.defer(lambda: topo.links.remove(link))

        # add interfaces
        br_a.links[ifid_a] = link
        cleanup.defer(lambda: br_a.links.pop(ifid_a))
        br_b.links[ifid_b] = link
        cleanup.defer(lambda: br_b.links.pop(ifid_b))

        _connect_scion_link(topo=topo, workdir=workdir, dc=dc,
            a=_EndPoint(isd_as_a, as_a, br_a, ifid_a),
            b=_EndPoint(isd_as_b, as_b, br_b, ifid_b),
            link=link, properties=link_properties)
        cleanup.success()

    return True


def _select_br_new_link(asys: AS, bridge: Bridge) -> Tuple[BorderRouter, bool]:
    """Select the border router to use for a new link.

    :param asys: AS to select a BR from.
    :param bridge: Bridge the BR will be connected to.
    :returns: Pair of the selected BR and a boolean value. This value is True,
              if the selected BR is not yet connected to `bridge`.
    """
    empty_br = None
    # look for a BR already connected to the bridge
    for br in asys.border_routers:
        if len(br.links) == 0:
            empty_br = br
        else:
            for _, link in br.links.items():
                if link.bridge == bridge:
                    return br, False # pick the first BR already connected to the bridge
    else: # no BR is connected to the bridge
        if empty_br:
            return empty_br, True # pick the first BR without any links
        else:
            return asys.border_routers[0], True # pick the first BR


def modify_link(topo: Topology, ixp: Ixp, a: Tuple[ISD_AS, AS], b: Tuple[ISD_AS, AS],
    link_properties: Mapping[str, Any], workdir: Path, dc: docker.DockerClient) -> bool:
    """Modify an existing link by changing its properties including the link type.

    Updating a running network is possible.

    :param topo: Topology
    :param ixp: The IXP the link is established over.
    :param a: First AS of the link. Has to be an AS running on localhost.
    :param b: Second AS of the link. Has to be an AS running on localhost.
    :param link_properties: New link properties. Properties not found in the mapping are left unchanged.
    :param workdir: Topology working directory.
    :param dc: Docker client object connected to the Docker daemon.
    :returns: True, if the link was updated. False, if the link does not exist.
    """
    isd_as_a, as_a = a
    isd_as_b, as_b = b

    try:
        br_a, ifid_a, _ = _get_br_interface(as_a, isd_as_b, ixp.bridge)
        br_b, ifid_b, link = _get_br_interface(as_b, isd_as_a, ixp.bridge)
    except LookupError:
        log.error("No matching link found.")
        return False

    # Swap parent child relation to match link direction
    properties = dict(link_properties)
    if link.ep_a == isd_as_b:
        if properties.get('type') == 'PARENT':
            properties['type'] = 'CHILD'
        elif properties.get('type') == 'CHILD':
            properties['type'] = 'PARENT'

    log.info("Modifying link from {}#{} to {}#{}.".format(
        br_a.get_name(isd_as_a), ifid_a, br_b.get_name(isd_as_b), ifid_b))

    _modify_scion_link_properties(topo=topo, workdir=workdir, dc=dc,
        a=_EndPoint(isd_as_a, as_a, br_a, ifid_a),
        b=_EndPoint(isd_as_b, as_b, br_b, ifid_b),
        link=link, properties=properties)
    link.type = properties.get('type', link.type)

    return True


def remove_link(topo: Topology, ixp: Ixp, a: Tuple[ISD_AS, AS], b: Tuple[ISD_AS, AS],
    workdir: Path, dc: docker.DockerClient) -> bool:
    """Remove a link through an IXP between two ASes.

    Links can be removed from a running network.

    :param topo: Topology
    :param ixp: The IXP the link is established over.
    :param a: First AS of the link. Has to be an AS running on localhost.
    :param b: Second AS of the link. Has to be an AS running on localhost.
    :param workdir: Topology working directory.
    :param dc: Docker client object connected to the Docker daemon.
    :returns: True, if the link has been removed. False, if the link does not exist.
    """
    isd_as_a, as_a = a
    isd_as_b, as_b = b

    try:
        br_a, ifid_a, _ = _get_br_interface(as_a, isd_as_b, ixp.bridge)
        br_b, ifid_b, link = _get_br_interface(as_b, isd_as_a, ixp.bridge)
    except LookupError:
        log.error("No matching link found.")
        return False

    log.info("Removing link from {}#{} to {}#{}.".format(
        br_a.get_name(isd_as_a), ifid_a, br_b.get_name(isd_as_b), ifid_b))
    _disconnect_scion_link(topo=topo, workdir=workdir, dc=dc,
        a=_EndPoint(isd_as_a, as_a, br_a, ifid_a),
        b=_EndPoint(isd_as_b, as_b, br_b, ifid_b))

    # delete interfaces
    del br_a.links[ifid_a]
    del br_b.links[ifid_b]

    # delete link
    topo.links.remove(link)

    # disconnect from network bridge
    if ixp.bridge.free_br_address(isd_as_a, ifid_a) == 0:
        if link.bridge.has_been_created():
            disconnect_bridge(link, isd_as_a, as_a)
            del ixp.ases[isd_as_a]
    if ixp.bridge.free_br_address(isd_as_b, ifid_b) == 0:
        if link.bridge.has_been_created():
            disconnect_bridge(link, isd_as_b, as_b)
            del ixp.ases[isd_as_b]

    return True


def _get_br_interface(asys: AS, remote_asys: ISD_AS, bridge: Bridge):
    """Get the BR, interface and link connecting `asys` to `remote_asys` over `bridge`.

    :raises LookupError: No matching link found.
    """
    for br in asys.border_routers:
        for ifid, link in br.links.items():
            if link.bridge == bridge and link.is_endpoint(remote_asys):
                return br, ifid, link
    raise LookupError()


def _connect_scion_link(topo: Topology, a: _EndPoint, b: _EndPoint,
    link: Link, properties: Mapping[str, Any],
    workdir: Path, dc: docker.DockerClient) -> None:
    """Modify AS configuration files to create a new link."""
    _modify_topo(topo, a.isd_as, a.asys, workdir=workdir, dc=dc,
        mod_func=lambda topo_file:
            add_br_interface(topo_file, a.br, a.ifid, a.isd_as, link, properties))
    _modify_topo(topo, b.isd_as, b.asys, workdir=workdir, dc=dc,
        mod_func=lambda topo_file:
            add_br_interface(topo_file, b.br, b.ifid, b.isd_as, link, properties))


def _modify_scion_link_properties(topo: Topology, a: _EndPoint, b: _EndPoint,
    link: Link, properties: Mapping[str, Any],
    workdir: Path, dc: docker.DockerClient) -> None:
    """Modify AS configuration files to change link properties."""
    _modify_topo(topo, a.isd_as, a.asys, workdir=workdir, dc=dc,
        mod_func=lambda topo_file:
            modify_br_interface_properties(topo_file, a.br, a.ifid, a.isd_as, properties))
    _modify_topo(topo, b.isd_as, b.asys, workdir=workdir, dc=dc,
        mod_func=lambda topo_file:
            modify_br_interface_properties(topo_file, b.br, b.ifid, b.isd_as, properties))


def _disconnect_scion_link(topo: Topology, a: _EndPoint, b: _EndPoint,
    workdir: Path, dc: docker.DockerClient) -> None:
    """Modify AS configuration files to delete a link."""
    _modify_topo(topo, a.isd_as, a.asys, workdir=workdir, dc=dc,
        mod_func=lambda topo_file: remove_br_interface(topo_file, a.br, a.ifid, a.isd_as))
    _modify_topo(topo, b.isd_as, b.asys, workdir=workdir, dc=dc,
        mod_func=lambda topo_file: remove_br_interface(topo_file, b.br, b.ifid, b.isd_as))


def _modify_topo(topo: Topology, isd_as: ISD_AS, asys: AS,
    mod_func: Callable[[Mapping[str, Any]], None],
    workdir: Path, dc: docker.DockerClient):
    """Modify the configuration of the given AS.

    The actual modifications are made by `mod_func`. If the AS is running, it is stopped first and
    restarted after `mod_func` returns.

    :param topo: Topology
    :param isd_as: AS to modify.
    :param asys: AS to modify.
    :param mod_func: Function that performs the  desired modifications by altering the topology.json
                     file it is given in form of a mapping.
    :param workdir: Topology working directory.
    :param dc: Docker client object connected to the Docker daemon.
    """
    restart = topo.is_scion_running(isd_as, asys)
    if restart: # stop SCION in the affected AS
        log.info("Stopping SCION in AS{}.".format(isd_as))
        topo.stop_scion_asys(isd_as, asys)

    modify_as_topo_file(workdir.joinpath(isd_as.file_fmt(), "gen"), isd_as, mod_func)

    if restart: # restart SCION
        log.info("Starting SCION in AS{}.".format(isd_as))
        topo.run_scion_asys(isd_as, asys)
